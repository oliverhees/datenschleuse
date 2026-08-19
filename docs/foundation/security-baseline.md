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
| Message | `content`, `name`, `refusal`, `tool_calls`, `function_call` | `role`, `tool_call_id` | blockiert |
| tool_call | `function` | `id`, `type`, `index` | blockiert |
| function | `name`, `arguments` | — | blockiert |
| content-Part | `text` | `image_url` (nach Image-Policy) | blockiert |

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

## Threat Model
- Beim Kickoff: STRIDE-Kurzdurchlauf pro Kernfeature, Ergebnis als
  `docs/adr/` bzw. Anhang hier. Bei neuen Angriffsflächen aktualisieren.

## Audit-Protokoll
- Jedes Audit: Findings mit Severity (Critical/High/Medium/Low) als
  Kommentare am Work Item. Merge-Sperre bei Critical/High (Gesetz 5).
