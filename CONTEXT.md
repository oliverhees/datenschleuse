# CONTEXT.md — Geteilte Sprache des Projekts

Dieses Dokument dekodiert den Jargon des Projekts. Es wird von
/grill-with-docs und /domain-modeling automatisch gepflegt.

## Glossar

| Begriff | Bedeutung |
|---|---|
| **Message-Feld-Register** | Abschließende Liste aller Felder einer Chat-Message mit ihrer Behandlung (maskiert / validiert / blockiert). Liegt als Konstanten in `litellm/datenschleuse_guardrail.py` und als bindende Tabelle in `docs/foundation/security-baseline.md`. Was nicht im Register steht, blockiert fail-closed. |
| **Allowlist-Prinzip** | Geprüft wird nur, was ausdrücklich als prüfbar erfasst ist; alles Übrige wird blockiert. Gegenstück zur Denylist, die erst vollständig ist, wenn jemand die Lücke findet. |
| **Strukturerhaltende Maskierung** | Maskierung eines JSON-Strings (`tool_calls[].function.arguments`), bei der nur Werte und Schlüssel durch Platzhalter ersetzt werden, die JSON-Syntax aber intakt bleibt — sonst wäre der Tool-Aufruf beim Zielmodell unbrauchbar. |
| **Opake Korrelations-ID** | `tool_call_id` bzw. `tool_calls[].id`: Zuordnungs-Token zwischen Tool-Aufruf und Tool-Ergebnis. Wird bewusst **nicht** maskiert (der Wert muss byte-identisch bleiben), dafür eng validiert, damit das Feld kein Freitext-Kanal ist. |
| **Verifikationsdurchlauf** | Zweite Analyse auf dem FERTIG maskierten Ergebnis. Findet die Erkennung dort noch Entitäten, wird der Request blockiert. Die einzige Prüfung, die unabhängig davon greift, welchen Pfad ein Wert genommen hat — Gegenmittel gegen Type-Confusion und künftige Lücken im Maskierungspfad. |
| **Type Confusion (im Guardrail-Kontext)** | Ein bekanntes Feld mit unerwartetem Typ (z. B. `arguments` als Objekt statt JSON-String). Ein `isinstance`-Guard im Maskierungspfad lässt es still passieren — die Prüfung gehört deshalb in den Validate-Pfad und muss blocken. |
| **Feld-Fingerprint** | Kurzer SHA-256-Prefix eines unbekannten Feldnamens in Blockmeldungen und Logs. Gibt Betreibern eine Diagnosemöglichkeit (gleicher Name → gleicher Wert), ohne den Namen preiszugeben — auch ein Feldname ist Client-Inhalt. |
| **Bypass-Kanal** | Ein Feld, das das Zielmodell erreicht, ohne die Maskierung zu durchlaufen. Historisch: Content-Parts (DATENSCHLE-57), `content`-Container (DATENSCHLE-64), Felder neben `content` (DATENSCHLE-66). |
| **Eigene Regel** (Custom Rule) | Ein vom Anwender selbst hinterlegter Begriff oder Regex, den die automatische Erkennung nicht findet — Kundenname, Projektname, internes Kürzel, Produktbezeichnung, Mandantenname. Deterministisch, kein ML. Liegt in `rules/custom-rules.yml`, gepflegt über `tools/datenschleuse-rules`. Siehe `docs/EIGENE-MUSTER.md`. |
| **Regel-Layer** | Die Schicht der eigenen Regeln (`litellm/custom_rules.py`), bewusst getrennt von der Presidio-Recognizer-Registry. Ihre Treffer werden in `_analyze()` eingemischt und laufen dann durch denselben Masker wie alle anderen Entitäten. Begründung: ADR-0001. |
| **Selbstverifikation** | Jede eigene Regel trägt ihren Testfall (`examples`) selbst und wird beim Laden dagegen geprüft. Eine Regel ohne grünen Testfall wird nicht aktiv. So ist "kein ungetestetes Muster in der Pipeline" technisch erzwungen, nicht nur prozessual gefordert. |
| **Quarantäne** | Zustand einer eigenen Regel, die geladen, aber wegen eines Fehlers oder rotem Testfall NICHT aktiv ist. Sie verschwindet nicht still, sondern wird mit Grund ausgewiesen (`datenschleuse-rules list`) — sonst hielte man sich fälschlich für geschützt. |
| **Gegenbeispiel** (counter example) | Text, in dem eine Regel ausdrücklich NICHT greifen darf. Fängt zu gierige Muster ab, bevor sie live gehen. |
| **Fehler-Isolation** | Grundsatz, dass ein fehlerhaftes Muster nur die eigene Entität kostet, nie die Pipeline: eigene Kompilierung, eigene Selbstverifikation und eigenes Zeitbudget pro Regel. |
| **Hot-Reload** | Die Regeldatei wird bei Änderung automatisch neu eingelesen (mtime-Prüfung). Ein neues Muster wirkt sofort — ohne Rebuild und ohne Container-Neustart. |
| **ReDoS** | Regular expression Denial of Service: ein Muster mit exponentiellem Backtracking, das beliebig lange rechnet. Abgefangen über den `timeout` des `regex`-Moduls; betroffen ist nur die eine Regel. |
| **Platzhalter** | Der eindeutige Ersatztext, den das Modell statt echter Daten sieht (`<PERSON_0>`, `<CUSTOM_KUNDENNAME_0>`). Eigene Regeln bekommen das Präfix `CUSTOM_`, um Kollisionen mit Presidio-Typen auszuschließen. |
| **reid_map** | Mapping Platzhalter → Klartext für einen Request. Einzige Quelle der Rück-Übersetzung; eigene Regeln nutzen dasselbe Mapping, es gibt kein zweites. |
| **fail-closed** | Bei Fehlern wird geblockt statt unmaskiert durchgelassen. Gilt für die Presidio-Erreichbarkeit. Der Regel-Layer ist die bewusste Ausnahme: dort verlangt ISC-26 ausdrücklich, dass ein Regelfehler die Pipeline nicht lahmlegt. |

## Architektur-Entscheidungen (ADRs)

ADRs liegen unter `docs/adr/`. Kurzverweise hier eintragen.

| ADR | Titel | Kurzfassung |
|---|---|---|
| [ADR-0001](docs/adr/0001-eigene-muster-deny-list.md) | Eigene Begriffe und Muster als separater Regel-Layer | Eigene Regeln kommen NICHT in `presidio/recognizers-config.yml`: ein kaputtes Regex dort reißt beim Boot den ganzen Analyzer mit (verletzt ISC-26), jede Änderung bräuchte einen Neustart (verletzt ISC-23/27), und für Testfälle gibt es dort kein Feld (verletzt ISC-24). |
