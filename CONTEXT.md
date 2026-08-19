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
| **Bypass-Kanal** | Ein Feld, das das Zielmodell erreicht, ohne die Maskierung zu durchlaufen. Historisch: Content-Parts (DATENSCHLE-57), `content`-Container (DATENSCHLE-64), Felder neben `content` (DATENSCHLE-66). |

## Architektur-Entscheidungen (ADRs)

ADRs liegen unter `docs/adr/`. Kurzverweise hier eintragen.
