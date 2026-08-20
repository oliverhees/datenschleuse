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
| **Störquote** | Anteil der PII-freien Testtexte, in denen die Erkennung mindestens einen Fehlalarm produziert. Ergänzt die Precision, weil `TP/(TP+FP)` zwei Töpfe mischt (TP aus Positiv-, FP aus Negativ-Fällen) und sich allein durch Hinzufügen von Positiv-Fällen verbessern lässt. Die Störquote ist gegen diesen Effekt immun und bildet ab, was ein Anwender erlebt. Gemessen von `test/corpus-benchmark.py`. |
| **Nicht-PII-Wortliste** | `presidio/de-stopwords.yml`: gemessene deutsche Alltagswörter, die das spaCy-NER fälschlich als PERSON/LOCATION/ORGANIZATION meldet. Wird als Presidio-`allow_list` (regex, `^...$`-verankert) an `/analyze` übergeben. Die Verankerung ist die Sicherheitseigenschaft: unterdrückt wird nur ein Span, der **vollständig** aus dem Stoppwort besteht — `Frau Menge` bleibt deshalb erkannt. |
| **Positiv-Kontrolle (Korpus)** | Testfall, der belegt, dass eine Precision-Maßnahme keinen Recall kostet — z. B. echte Nachnamen in ASCII-Umschrift (`Mueller`, `Schroeder`) neben den Negativ-Fällen, die dieselbe Schreibweise als Fehlalarm erzeugen. Ohne Positiv-Kontrolle ist eine Precision-Verbesserung unbelegt. |

## Architektur-Entscheidungen (ADRs)

ADRs liegen unter `docs/adr/`. Kurzverweise hier eintragen.

- **ADR-0002** — Nicht-PII-Wortliste zur Unterdrückung von NER-Fehlalarmen. Genehmigte Ausnahme vom Denylist-Verbot der Security-Baseline: Das Verbot zielt auf Listen, die bestimmen, was als PII *gilt* (Lücke = ungeschützte Daten). Diese Liste bestimmt, was *kein* Name ist (Lücke = Fehlalarm bleibt stehen). Vier testgeprüfte Gegenkontrollen, allen voran die `^...$`-Verankerung.
