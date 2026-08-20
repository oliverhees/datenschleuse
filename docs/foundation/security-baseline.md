# Security-Baseline

> Bindend per Gesetz 5. Maßstab für jedes Security-Audit.
> Anspruch: verkaufsfähige Software auf Audit-Niveau.

## Verbindliche Standards
- Backend/API: OWASP ASVS, Level 2 als Ziel
- Mobile App: OWASP MASVS (+ MASTG als Prüfleitfaden)
- Web-Anteile: OWASP Top 10 als Minimum-Checkliste

## Baseline-Regeln (Auszug — vom security-auditor gepflegt)
- Auth: bewährte Verfahren/Provider, keine Eigenbau-Crypto, Token-Lebenszeiten
  definiert, Refresh-Rotation.
- Storage (Mobile): Secrets nur in Keychain/Keystore, nie in AsyncStorage
  oder Klartext-Dateien.
- Transport: TLS überall, Certificate Pinning für kritische Endpunkte prüfen.
- Input: serverseitige Validierung ist Pflicht, Client-Validierung ist Komfort.
- Logging: keine PII, keine Tokens, keine Passwörter in Logs.
- Dependencies: Lockfile, CVE-Scan in CI (gitleaks + npm audit / semgrep).

## Allowlist-Prinzip für eingehende Nachrichten (bindend)

Jede Ebene einer eingehenden Chat-Message wird nach Allowlist behandelt:
geprüft wird, was ausdrücklich als prüfbar erfasst ist — alles Übrige
blockiert fail-closed. Denylists ("diese bekannten Felder sind gefährlich")
sind hier verboten: sie sind erst vollständig, wenn jemand die Lücke findet.

Historie derselben Lücke — der Grund für diese Regel:
- DATENSCHLE-57: Content-**Parts** (`file`, `input_audio`, unbekannte Typen)
- DATENSCHLE-64: der `content`-**Container** selbst (dict statt Liste)
- DATENSCHLE-66: alle **Felder neben `content`**, allen voran
  `tool_calls[].function.arguments` (für agentische Clients der Normalfall)

Verbindliches Feld-Register (Quelle: `MESSAGE_FIELDS_MASKED` /
`MESSAGE_FIELDS_VALIDATED` in `litellm/datenschleuse_guardrail.py` — Code und
Tabelle werden gemeinsam geändert, nie einzeln):

| Ebene | maskiert | validiert (nicht maskiert) | Rest |
|---|---|---|---|
| Message | `content`, `name`, `refusal`, `reasoning_content`, `tool_calls`, `function_call` | `role`, `tool_call_id`, `cache_control` | blockiert |
| tool_call | `function` | `id`, `type`, `index` | blockiert |
| function | `name`, `arguments` | — | blockiert |
| content-Part | `text` | `image_url` (nach Image-Policy) | Part-**Typ** blockiert; Part-**Felder** ⚠️ siehe unten |

> ⚠️ **Bekannte Abweichung auf der Part-Ebene (DATENSCHLE-65).** Die Allowlist
> greift für content-Parts derzeit auf den Part-**Typ**; die **Feldebene**
> innerhalb eines Parts ist noch nicht erfasst und in Arbeit. Die Zeile oben
> beschreibt insoweit den Soll-, nicht den Ist-Zustand: die Zusage „Rest
> blockiert" gilt auf der Part-Ebene bis zum Merge von **DATENSCHLE-65**
> **nicht**. Der Defekt stammt aus DATENSCHLE-57.
>
> Der genaue Umfang steht am Work Item, nicht hier — Begründung im Abschnitt
> „Offene Schwachstellen in eigener Doku".
>
> Diese Warnung bleibt stehen, bis DATENSCHLE-65 gemerged ist. Eine
> dokumentierte Sicherheitszusage, auf die sich ein Betreiber verlässt, ist
> selbst ein Sicherheitsmerkmal — eine zu weit gefasste Zusage ist ein Defekt,
> auch wenn der Code darunter älter ist als sie.

Regeln dazu:
- IDs werden **validiert statt maskiert**: ihr Wert muss byte-identisch
  bleiben, sonst findet das Modell das Tool-Ergebnis nicht zu seinem Aufruf.
  Genau deshalb müssen sie eng geprüft werden — sonst sind sie der bequemste
  Schmuggelkanal der Nachricht.
- `arguments` wird strukturerhaltend maskiert (JSON parsen, Werte und
  Schlüssel ersetzen, serialisieren). Nicht parsebares JSON wird als
  Freitext maskiert, nie ungeprüft durchgelassen.
- Blockmeldungen enthalten **nie** Client-Werte — auch kein Feldname, denn
  auch der ist Client-Inhalt (Gesetz 5).
- Ein neues Feld der OpenAI-API ist ein eigenes Work Item mit Eintrag im
  Register, nicht ein stillschweigendes Durchreichen.
- **Typprüfung gehört in den Validate-Pfad, nie in den Mask-Pfad.** Ein
  `if isinstance(x, str)` vor einer Maskierung ist immer ein stiller
  Durchlass: der Nicht-String fällt durch und geht ungeprüft raus. Ein
  bekanntes Feld mit falschem Typ muss blocken (Security-Audit F1).
- **Verifikationsdurchlauf auf dem Ergebnis.** Der fertig maskierte
  `arguments`-String geht erneut durch den Analyzer; findet der dort noch
  Entitäten, wird blockiert. Alle anderen Prüfungen sind pfadgebunden —
  diese ist die einzige, die einen Wert unabhängig von seinem Weg noch
  einmal ansieht. Sie ist deshalb ein zusätzliches Netz, keine Garantie:
  vor der Prüfung werden bekannte Platzhalter neutralisiert, und Treffer,
  die nachweislich erst durch diese Neutralisierung entstehen, werden
  verworfen (siehe „bekannte Grenzen").
- **JSON muss eindeutig sein.** Doppelte Schlüssel (`json.loads` behält still
  den letzten Wert, der erste wird nie geprüft) und nicht standardkonforme
  Konstanten (`NaN`, `Infinity`) werden abgelehnt, nicht interpretiert.
- **Fehlerpfade sind fail-closed, nicht Absturz.** Zu tief verschachteltes
  JSON blockt kontrolliert, statt einen `RecursionError` aus dem Hook zu
  werfen.
- **Diagnose ohne Preisgabe.** Blockmeldungen und Logs nennen Feldnamen nur
  aus unserem eigenen konstanten Vokabular; frei gewählte Feldnamen erscheinen
  ausschließlich als stabiler Fingerprint. Ein Feldname ist Client-Inhalt und
  kann selbst PII sein — Werte erscheinen nie, weder im Log noch am Client.

### Feld-Fingerprint — Formel

Damit ein Betreiber einen Fingerprint selbst nachrechnen kann, ohne in den
Quellcode zu sehen:

```
fingerprint(feldname) = sha256(repr(feldname).encode("utf-8")).hexdigest()[:8]
```

`repr()` (nicht `str()`), weil ein Feldname nicht zwingend ein String ist.
Nachrechnen in der Shell:

```bash
python3 -c 'import hashlib;print(hashlib.sha256(repr("mein_feld").encode()).hexdigest()[:8])'
```

Der Fingerprint ist stabil: derselbe Name ergibt immer denselben Wert. Damit
lässt sich ein blockendes Feld durch Vergleich eingrenzen, ohne dass der Name
selbst das System verlässt.

### Verifikationsdurchlauf — bekannte Grenzen

Der Durchlauf ist bewusst streng und erhöht die Blockrate für **legitime**
Aufrufe messbar. Das ist der akzeptierte Preis, keine Fehlfunktion:

- **Boundary-Artefakte der Erkennung.** Derselbe Analyzer kann an derselben
  Stelle im zweiten Durchlauf anschlagen, wo er im ersten nichts fand, weil
  sich der umgebende Kontext durch die Ersetzung verändert hat. Gegen echtes
  Presidio belegt: `{"projekt":"Digitalisierung Rathaus Muenchen",
  "ansprechpartner":"Frau Schmidt"}` wird geblockt — der Knoten-Durchlauf
  erkennt „Digitalisierung" als LOCATION und übersieht „Rathaus Muenchen",
  der Verifikationsdurchlauf findet es dann. **Kein Code-Fehler.** Die
  Blockmeldung nennt deshalb alle drei möglichen Ursachen und unterstellt
  keine — die dritte ist das eigene Whitespace-Muster aus dem nächsten Punkt,
  der einzige Fall, den der Betreiber selbst beheben kann.
- **Neutralisierung der Platzhalter — und ihre Kehrseite.** Damit die
  Erkennung nicht die Platzhalter selbst für Namen hält, werden sie vor der
  Prüfung durch ein neutrales Zeichen ersetzt. Diese Ersetzung kann eigene
  Treffer erzeugen, die es im echten Text nie gab: ein Muster, das über
  Whitespace hinweggreift, passt danach plötzlich.

  Verworfen wird ein Treffer deshalb **nur dann**, wenn er beweisbar unsere
  eigene Einfügung ist — sein Kern besteht ausschließlich aus eingefügten
  Zeichen und Whitespace. Steht auch nur ein Zeichen Klartext darin, wird
  blockiert. Keine Ausnahme, keine Feinabstimmung.

  **Diese Grobheit ist eine bewusste Entscheidung, keine Nachlässigkeit.**
  Es gab drei Anläufe, den Fehlalarmraum feiner zuzuschneiden — Filter nach
  Entitätstyp, Filter nach Span-Überlappung, Zerlegung in Segmente plus
  verklebter Kern. Jeder Anlauf hat ein eigenes Leck erzeugt, und jedes davon
  fand erst ein Audit (F10, S1, S1-R/HIGH-1/HIGH-2) — zuletzt gingen ganze
  Kreditkartennummern und mehrwortige Deny-Begriffe durch. Keine dieser
  Verfeinerungen wurde von einem Gegentest eingefordert; sie kauften
  ausschließlich Fehlalarm-Reduktion, die niemand verlangt hatte.

  **Regel für Änderungen an dieser Stelle:** Jede Verfeinerung braucht einen
  Gegentest, der ohne sie fehlschlägt. Gibt es den nicht, kauft sie nichts
  und kostet erfahrungsgemäß ein Leck. Regressionstests:
  `test/test_custom_rules.py`, Abschnitte 17, 20, 24 und 28.
- **Bewusst in Kauf genommener Fehlalarm.** Eine eigene Regex-Regel, deren
  Muster über einen Platzhalter hinweggreift, blockt. Das ist gewollt: von
  außen ist dieser Fall nicht von der Konstruktion zu unterscheiden, mit der
  man die Maskierung umgeht. Ein sichtbarer Fehlalarm ist billiger als ein
  stilles Leck.

  **Zu Deny-Listen — die Richtung ist wichtig:** Für *Fehlalarme* sind sie
  prinzipiell nicht betroffen, ein Begriff ohne Regex-Metazeichen greift
  nicht über einen Platzhalter hinweg. Als *Risikoschranke* war es unter den
  früheren Filtern jedoch genau umgekehrt: jeder **mehrwortige** Begriff war
  ein möglicher Falsch-Negativer, weil der verklebte Kern den Trenner löschte
  und der Begriff darin nicht mehr vorkommen konnte. Betroffen war damit
  ausgerechnet der Regelfall — die Beispieldatei und die CLI-Hilfe dieses
  Repos werben mit „Nordwind Logistik". Mit dem heutigen Filter ist diese
  Klasse geschlossen.

  Gemessen am deutschen PII-Testkorpus (45 Fälle, echter Analyzer, plus 45
  aus dem Korpus erzeugte Deny-Regeln, davon 33 mehrwortig): **0 Fehlalarme**,
  **0 Treffer mit Füller im Kern**.
- **Kosten.** Genau ein zusätzlicher Analyzer-Call pro `arguments`-String.
  Der Artefaktfilter entscheidet ohne weitere Aufrufe — am Testkorpus
  gemessen 1,00 Calls pro Fall. Damit kann sich auch das Zeitbudget der
  Regel-Schicht hier nicht vervielfachen.
- **Der Durchlauf ist ein Netz, kein Ersatz.** Er ersetzt keine der
  vorgelagerten Prüfungen; er fängt nur, was an ihnen vorbeigekommen ist.

## Offene Schwachstellen in eigener Doku (bindend)

Eigene Doku benennt eine offene Schwachstelle im **Umfang**, nie im **Bauplan**.
Kein Beispiel-Payload, kein Reproduktionspfad für etwas Unbehobenes. Ehrlichkeit
über den Ist-Zustand ja, Anleitung nein.

Der Maßstab in einem Satz: Der Leser muss erkennen, worauf er sich **nicht**
verlassen darf — er darf daraus nicht ableiten können, wie er es auslöst.

- **Nennen:** betroffene Ebene, Tragweite der Abweichung, Work Item, ab wann die
  Zusage wieder gilt.
- **Weglassen:** Payload, Feldnamen, Struktur, Typ, Aufrufreihenfolge — alles,
  woraus sich der Weg zur Lücke zusammensetzen lässt.
- Der vollständige Sachverhalt gehört ans Work Item. Plane ist intern, dieses
  Repository ist öffentlich: jede Zeile hier ist eine Veröffentlichung.
- Nach dem Merge des Fixes darf die Beschreibung vollständig werden — vorher nicht.

Das ist kein Widerspruch zum Klartext-Gebot: Vollständigkeit gilt nach innen,
Zurückhaltung nach außen. Eine zu weit gefasste Sicherheitszusage ist ein Defekt
(siehe Part-Ebene oben) — eine mitgelieferte Anleitung, sie zu umgehen, ist einer
mit Reichweite.

## Threat Model
- Beim Kickoff: STRIDE-Kurzdurchlauf pro Kernfeature, Ergebnis als
  `docs/adr/` bzw. Anhang hier. Bei neuen Angriffsflächen aktualisieren.

## Audit-Protokoll
- Jedes Audit: Findings mit Severity (Critical/High/Medium/Low) als
  Kommentare am Work Item. Merge-Sperre bei Critical/High (Gesetz 5).
