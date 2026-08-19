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

## Allowlist-Prinzip für Routen (bindend)

Die äußerste Ebene ist nicht das Feld und nicht die Nachricht, sondern die
**Route**. LiteLLM übergibt jedem Guardrail einen `call_type`, und jede Route
bringt ihr eigenes Payload-Schema mit. Eine Route, deren Schema die Maskierung
nicht abdeckt, wird **geblockt** — nie ungeprüft durchgereicht.

Warum das eine eigene Regel ist: eine Route stillschweigend durchzulassen ist
der schwerste Defektfall, den dieses Produkt haben kann. Nicht „Schutz
schwach", sondern *Schutz abwesend bei zugesichertem Schutz* — der Betreiber
hält seinen Verkehr für anonymisiert, während er es nie war. Genau das war
**DATENSCHLE-69** (behoben).

Verbindliches Routen-Register (Quelle: `CALL_TYPES_CHAT_MESSAGES` /
`CALL_TYPES_TEXT_PROMPT` / `KNOWN_UNSUPPORTED_CALL_TYPES` in
`litellm/datenschleuse_guardrail.py` — Code und Tabelle werden gemeinsam
geändert, nie einzeln):

| Route | `call_type` | Payload | Verhalten |
|---|---|---|---|
| `/v1/chat/completions` | `acompletion`, `completion` | `messages[]` | vollständig geprüft (Feld-Register unten) |
| `/v1/completions` | `atext_completion` | `prompt` | vollständig geprüft, Rückweg über `choices[].text` |
| `/v1/messages` (Anthropic) | `anthropic_messages` | eigenes Schema | **blockiert** |
| `/v1/responses` | `aresponses` | eigenes Schema | **blockiert** |
| Embeddings, Bild, Audio, Moderation, Rerank, Batch, Vector Store, MCP, Passthrough, Google GenAI | siehe Register | jeweils eigenes Schema | **blockiert** |
| jede künftige/unbekannte Route | — | — | **blockiert** |

Regeln dazu:
- Eine Route gilt erst als unterstützt, wenn **beide Richtungen** belegt sind:
  Maskierung des ausgehenden Payloads *und* Re-Identifikation der Antwort,
  jeweils mit eigenem Test. „Unterstützt" ohne Rückweg ist eine falsche
  Zusage, kein halber Fortschritt.
- Der `call_type` sagt nur, **welche** Route spricht — nicht, **wie** ihr
  Payload aussieht. Jeder unterstützte Pfad prüft deshalb zusätzlich die Form
  seines Payloads und blockt bei Abweichung. Ein Payload, der zu zwei Routen
  gleichzeitig passt, ist mehrdeutig und blockt.
- Die Typprüfung des `call_type` steht im **Validate-Pfad**, nicht als
  `isinstance`-Guard im Verarbeitungspfad. Ein Guard, der bei unerwartetem Typ
  still überspringt, ist immer ein Durchlass.
- **Blocken ist eine gültige Antwort.** Eine Route bewusst zu blocken und das
  zu dokumentieren ist erlaubt; sie stillschweigend durchzulassen nie.
- Eine neue LiteLLM-Route ist ein eigenes Work Item mit Eintrag im Register —
  nie eine stillschweigende Erweiterung im Code.

`/v1/messages` und `/v1/responses` sind bewusst geblockt, nicht vergessen:
beide brauchen ein eigenes Block-Register **und** einen eigenen Rückweg. Sie
als unterstützt zu führen, ohne ihre Struktur tatsächlich zu maskieren, wäre
derselbe Defekt noch einmal — nur dokumentiert falsch. Aufnahme jeweils als
eigenes Work Item.

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
- DATENSCHLE-65: die **Feldebene innerhalb eines Parts**
- DATENSCHLE-69: die **Route** selbst — siehe „Allowlist-Prinzip für Routen"

Fünfmal dieselbe Ursache: gelesen wurde, was man kannte, alles Übrige lief
still durch. Deshalb wird auf jeder Ebene **einmal vollständig erfasst** statt
Fall für Fall entdeckt.

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
  diese greift unabhängig davon, welchen Weg ein Wert genommen hat.
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
  Blockmeldung nennt deshalb beide möglichen Ursachen und unterstellt keine.
- **Kosten.** Ein zusätzlicher Analyzer-Call pro `arguments`-String.
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
