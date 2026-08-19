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
| content-Part `text` | `text` | `type`, `cache_control` | blockiert |
| content-Part `image_url` | — | `type`, `image_url` (nach Image-Policy), `cache_control` | blockiert |
| `image_url`-Container | — | `url`, `detail` | blockiert |

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
- **Offene Schwachstellen werden im Umfang beschrieben, nie im Bauplan.**
  Eine noch offene Lücke wird nach Ebene und Wirkung dokumentiert („die
  Feldebene innerhalb eines Parts wird nicht geprüft"), niemals mit einem
  lauffähigen Beispiel-Payload. Unsere Doku ist öffentlich; ein Payload darin
  ist eine Schritt-für-Schritt-Anleitung zur Umgehung der Maskierung, die
  genau so lange nutzbar bleibt, wie der Fix braucht. Nach dem Fix darf die
  Beschreibung konkret werden — ein neuer Payload gehört trotzdem nicht
  hinein.

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

## Threat Model
- Beim Kickoff: STRIDE-Kurzdurchlauf pro Kernfeature, Ergebnis als
  `docs/adr/` bzw. Anhang hier. Bei neuen Angriffsflächen aktualisieren.

## Audit-Protokoll
- Jedes Audit: Findings mit Severity (Critical/High/Medium/Low) als
  Kommentare am Work Item. Merge-Sperre bei Critical/High (Gesetz 5).
