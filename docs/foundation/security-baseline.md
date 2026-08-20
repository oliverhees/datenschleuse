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
- DATENSCHLE-65: die **Felder innerhalb eines Content-Parts** — die Allowlist
  griff dort bis dahin nur auf den Part-**Typ**

Verbindliches Feld-Register (Quelle: `MESSAGE_FIELDS_MASKED` /
`MESSAGE_FIELDS_VALIDATED` und `PART_FIELDS_MASKED` / `PART_FIELDS_VALIDATED`
in `litellm/datenschleuse_guardrail.py` — Code und Tabelle werden gemeinsam
geändert, nie einzeln):

| Ebene | maskiert | validiert (nicht maskiert) | Rest |
|---|---|---|---|
| Message | `content`, `name`, `refusal`, `reasoning_content`, `tool_calls`, `function_call` | `role`, `tool_call_id`, `cache_control` | blockiert |
| tool_call | `function` | `id`, `type`, `index` | blockiert |
| function | `name`, `arguments` | — | blockiert |
| content-Part `text` | `text`, `citations` (nur die Freitext-Felder, s.u.) | `type`, `cache_control` | blockiert |
| content-Part `image_url` | — | `type`, `image_url` (nach Image-Policy), `cache_control` | blockiert |
| `image_url`-Container | — | `url`, `detail` | blockiert |
| `citations[]` (nur `char_location`, `page_location`, `content_block_location`) | `cited_text`, `document_title` | `type`, `document_index`, die beiden Positions-Indizes | blockiert |

Die Part-Ebene ist damit auf **beiden** Achsen geschlossen: Allowlist für den
Part-**Typ** (DATENSCHLE-57) und Allowlist für die **Felder** innerhalb eines
Parts (DATENSCHLE-65). Bis DATENSCHLE-65 galt die Zusage „Rest blockiert" nur
für den Typ — ein Part mit erlaubtem Typ durfte zusätzliche, ungeprüfte Felder
tragen. Dasselbe gilt seither eine Ebene tiefer für den `image_url`-Container,
dessen Zusatzfelder die Bild-Policy unverändert überlebten.

`cache_control` ist auf Part-Ebene **zugelassen und validiert, nicht
maskiert** — Anthropic-Clients hängen den Marker an Content-Blöcke, ein Block
wäre Client-Breakage. Er trägt keinen Freitext (geschlossene Wertemengen für
`type` und `ttl`), deshalb gilt er für Text- **und** Bild-Parts.

`citations` ist der eine Fall, der **beides** ist: Struktur validiert, Inhalt
maskiert. Anthropic hängt das Array an Assistant-Text-Blöcke; schickt ein
Client die Historie zurück — der Normalfall im Multi-Turn — trägt die
Assistant-Nachricht es. Seine Freitext-Felder `cited_text` (wörtlicher
Dokumentinhalt) und `document_title` (der vom Nutzer vergebene Titel, etwa
`Arztbrief_Mustermann.pdf`) laufen deshalb durch den Masker wie jeder andere
Text; die Indizes bleiben unverändert, sonst zeigt das Zitat nach der
Schleuse auf eine andere Stelle.

Warum nicht einfach blockieren, sobald `cited_text` da ist: das Feld ist im
Request-Schema der Messages-API **Pflicht** und wird beim Echo ausdrücklich
zurückerwartet. Eine Allowlist, die es blockt, lässt jede reale
Multi-Turn-Anfrage mit Zitaten weiter scheitern — fail-closed wäre das dem
Namen nach, praktisch wäre es eine Dauerstörung.

Bewusst **nicht** zugelassen sind die beiden übrigen Zitat-Typen
`search_result_location` und `web_search_result_location`: sie tragen
`source`, `url` und `title` als Freitext sowie `encrypted_index`, ein opakes
Provider-Token, das den Provider byte-identisch erreichen muss. Ebenso blockt
`file_id` — es existiert nur antwortseitig, ein schema-konformer Client
sendet es nie.

> **Korrektur (QA-Audit zu `1e197f9`).** Eine frühere Fassung dieses
> Abschnitts begründete beide Blocks damit, die Typen entstünden
> „ausschließlich aus Part-Typen, die die Datenschleuse ohnehin am Part-Typ
> blockt". Für `search_result_location` stimmt das — der Typ setzt einen
> `search_result`-Content-Part voraus, und der blockt. **Für
> `web_search_result_location` stimmt es nicht.** Anthropics natives
> Web-Search-Server-Tool wird über das Top-Level-Feld `tools` aktiviert
> (`{"type": "web_search_20250305", "name": "web_search"}`); es braucht
> keinen Content-Part. Das Zitat hängt anschließend an einem ganz normalen
> `text`-Block. Die Aussage war also falsch, und mit ihr die Einordnung
> „toter Code".

### Bekannte Einschränkung: Anthropics natives Web-Search-Tool

**Multi-Turn-Konversationen mit Anthropics Web-Search-Server-Tool
funktionieren durch die Datenschleuse nicht.** Das ist eine bewusst
akzeptierte Einschränkung, kein Versehen — und ein beworbenes Kernfeature,
also für Betreiber relevant.

Was passiert: Der erste Turn läuft durch. Antwortet das Modell mit
Web-Search-Zitaten und schickt der Client die Historie zurück — der Normalfall
im Multi-Turn — blockt die Folgeanfrage fail-closed.

Der Block greift dabei an **zwei** Stellen, nicht an einer:

1. **Am Part-Typ.** Anthropic verlangt für die Fortsetzung ausdrücklich,
   dass der Client die Assistant-Blöcke unverändert zurückschickt,
   `server_tool_use` und `web_search_tool_result` eingeschlossen — mit
   `encrypted_content`, das sonst mit einem 400 quittiert wird. Beide
   Part-Typen stehen nicht im Register und blocken.
2. **Am Zitat-Typ.** `web_search_result_location` ist nicht zugelassen.

**Warum wir den Zitat-Typ trotzdem nicht öffnen.** Ihn allein zuzulassen
würde den Kundenfall *nicht* reparieren: die Anfrage blockte dann eben eine
Ebene höher am Part-Typ. Bezahlt wäre das mit einem `encrypted_index`, für
das Anthropic weder Zeichenmenge noch Länge dokumentiert — ein opaker
Provider-Token-Kanal ohne belegbare Obergrenze, der byte-identisch
durchlaufen muss und deshalb nicht maskiert werden kann. Realer
Sicherheitspreis, kein funktionaler Gegenwert. Wer die Web-Search-Kette
unterstützen will, braucht ein eigenes Work Item, das **beide** Ebenen
zusammen behandelt.

Was heute schon gilt: Kommt ein Web-Search-Zitat auf dem **Rückweg** an,
werden seine Platzhalter aufgelöst (siehe oben). Der Kunde sieht dort also
keine `<PERSON_0>`.

Ergänzend, außerhalb dieses Work Items: Das Top-Level-Feld `tools` wird von
diesem Guardrail nicht geprüft. Das eigene Register dafür entsteht in
DATENSCHLE-69.

Zwei Grenzen, die für Betreiber zählen:
- Die Zitat-Indizes beziehen sich auf das Dokument **wie gesendet**, also auf
  die maskierte Fassung. Ändert ein Platzhalter die Länge, zeigen
  `start_char_index`/`end_char_index` im re-identifizierten Klartext nicht
  mehr exakt auf dieselbe Stelle. `page_location` und die Block-Index-Typen
  sind davon nicht betroffen.
- Die Re-Identifikation deckt Zitate im **Antwort**-Pfad ab: nicht-gestreamt
  über `provider_specific_fields.citations`, im Stream über
  `provider_specific_fields.citation` (das `citations_delta`-Event). Sie gilt
  für **alle fünf** Zitat-Typen, auch die, die der Hinweg blockt — der
  Rückweg ist ein Einlöse-Pfad zum Kunden, kein Prüf-Pfad, und ersetzt
  ausschließlich Platzhalter, die dieser Request selbst vergeben hat.
  Mit-abgedeckt ist `supported_text`, ein von LiteLLM erfundenes Feld, das
  den vollen stützenden Antworttext trägt. Nicht angefasst werden
  `encrypted_index` und `file_id` (opake Provider-Token).

  > **Korrektur (QA-Audit zu `1e197f9`).** Eine frühere Fassung behauptete,
  > der Antwort-Pfad „kann durch diesen Proxy nicht auftreten", weil Zitate
  > dort nur aus `document`-Parts entstünden. Das war aus demselben Grund
  > falsch wie oben (Web-Search braucht keinen Content-Part) — und der Pfad
  > war tatsächlich defekt: der Haupttext kam im Klartext an, dasselbe Zitat
  > trug den rohen Platzhalter. Behoben; kein Vertraulichkeitsleck, ein
  > stehengebliebener Platzhalter ist die sichere Fehlerrichtung.

**„Validiert" heißt Struktur, nicht Inhalt.** In der Tabelle bedeutet
„validiert" ausschließlich: das Feld hat den erwarteten Typ und — wo eine
geschlossene Wertemenge existiert (`cache_control.type`, `cache_control.ttl`,
`image_url.detail`) — einen Wert daraus. Es bedeutet **nicht**, dass der Inhalt
auf PII geprüft wird. Konkret bei `image_url.url`: geprüft wird, dass es ein
String ist, nicht was darin steht. Bei `image_policy="pass"` verlässt dieser
String den Proxy unverändert — eine URL kann also personenbezogene Daten in
Pfad oder Query tragen und wird dabei nicht maskiert. Wer Bild-URLs aus
Nutzereingaben zusammensetzt, betreibt `pass` auf eigenes Risiko;
`redact` oder `block` sind die Voreinstellungen der Wahl.

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
- **Bekannte Provider-Felder werden benannt, nicht einzeln entdeckt.** Zu
  jeder Ebene gehört eine Liste real existierender Felder, die wir bewusst
  NICHT behandeln (`KNOWN_UNSUPPORTED_MESSAGE_FIELDS`,
  `KNOWN_UNSUPPORTED_PART_FIELDS`). Sie blocken wie jedes unbekannte Feld,
  werden dem Betreiber aber beim Namen genannt, damit er nicht per
  Trial-and-Error gegen die Allowlist raten muss. Was dort fehlt und was
  bewusst nicht behandelt wird, steht im Code am Register.
- **Offene Schwachstellen werden im Umfang beschrieben, nie im Bauplan** —
  ausgeführt im eigenen Abschnitt „Offene Schwachstellen in eigener Doku".

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
  Ein veröffentlichter Payload bleibt genau so lange nutzbar, wie der Fix
  braucht; das ist das Zeitfenster, das diese Regel schließt. Auch nach dem
  Fix gehört ein neuer Payload nicht in die Doku.

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
