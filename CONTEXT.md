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
| **Zitat-Register** | Gegenstück zum Message- und Part-Feld-Register, eine Ebene tiefer: abschließende Liste der zugelassenen Zitat-Typen (`citations[]`) und ihrer Felder mit der jeweiligen Behandlung. Freitext (`cited_text`, `document_title`) wird maskiert, Positions-Indizes werden nur validiert und bleiben unverändert — sonst zeigt das Zitat nach der Re-Identifizierung ins Leere. |
| **Hinweg / Rückweg** | Hinweg = die Anfrage zum Modell, ein **Prüf-Pfad**: Allowlist, alles Ungeprüfte blockiert fail-closed. Rückweg = die Antwort zum Kunden, ein **Einlöse-Pfad**: er löst nur Platzhalter auf, die dieser Request selbst vergeben hat, und ist deshalb bewusst großzügiger. Ein Feld zu viel kann dort nichts leaken, ein Feld zu wenig lässt einen Platzhalter beim Kunden stehen. |
| **Index-Drift** | Zitat-Indizes zeigen auf das Dokument *wie gesendet*, also auf die maskierte Fassung. Hat ein Platzhalter eine andere Länge als der echte Wert, treffen `start_char_index`/`end_char_index` im re-identifizierten Klartext nicht mehr exakt dieselbe Stelle. Betrifft nur die Zeichen-Indizes, nicht Seiten- oder Block-Zitate. |
| **Bekannte, nicht unterstützte Typen** | Typen, die es in der Praxis gibt und die die Datenschleuse bewusst nicht behandelt (`KNOWN_UNSUPPORTED_*`). Sie blockieren wie alles Unbekannte, werden in der Blockmeldung aber **beim Namen genannt** — der Name stammt aus der Konstante, nie aus dem Request. So kann ein Betreiber eine akzeptierte Einschränkung von einem echten Bug unterscheiden. Beispiel: `server_tool_use` / `web_search_tool_result` aus Anthropics Web-Search-Kette. |
| **Bypass-Kanal** | Ein Feld, das das Zielmodell erreicht, ohne die Maskierung zu durchlaufen. Historisch: Content-Parts (DATENSCHLE-57), `content`-Container (DATENSCHLE-64), Felder neben `content` (DATENSCHLE-66). |

## Architektur-Entscheidungen (ADRs)

ADRs liegen unter `docs/adr/`. Kurzverweise hier eintragen.
