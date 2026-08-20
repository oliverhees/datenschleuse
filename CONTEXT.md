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
| **Feld-Fingerprint** | Kurzer, **gesalzener** Hash (blake2s, prozesslokaler Salt) eines unbekannten Feldnamens in Blockmeldungen und Logs. Gibt Betreibern eine Diagnosemöglichkeit (gleicher Name → gleicher Wert innerhalb eines Prozesses), ohne den Namen preiszugeben — auch ein Feldname ist Client-Inhalt. Ungesalzen war er zurückrechenbar: Feldnamen sind entropiearm. |
| **Logging-Kanal** | Der Weg eines Feldes zu den Logging-Callbacks — getrennt vom Weg zum Provider. Ein Feld, das das Modell nie erreicht (`metadata`), kann trotzdem im Log stehen. „Erreicht den Provider nicht" ist deshalb **kein** Beleg für „harmlos". |
| **Logging-Schnappschuss** | `proxy_server_request.body`: die flache Kopie des Request-Bodys, die LiteLLM **vor** dem Guardrail baut und an `standard_logging_payload`, `spend_tracking_utils` und alle Callbacks weiterreicht. Flach heißt: pro Key dieselbe Objekt-Referenz — was die Guardrail durch Rebinding maskiert, bleibt dort unmaskiert. Wird deshalb nach der Maskierung neu gebaut, und bei einem Block ersetzt. |
| **Siegel (Re-Id-Mapping)** | Das Platzhalter-zu-Klartext-Mapping als Fernet-Token statt als Klartext-dict. Verschlüsselt + lokal (prozesslokaler Schlüssel) + TTL, wie in `CLAUDE.md` zugesagt. Nötig, weil das Mapping in `metadata` reist und damit im Log landet. |
| **Replay eines Siegels** | Wiederverwendung eines **fremden**, gültigen Siegels: Verschlüsselung schützt gegen Fälschen, nicht gegen Wiederverwenden. Ein Angreifer schickt ein aus dem Log gefischtes Siegel mit einem Text voller Platzhalter mit und bekommt fremden Klartext zurück — ein Orakel. Gegenmittel: client-gesetzte Siegel werden verworfen, und das Lesen ist deterministisch. |
| **Obermengen-Vertrag** | Unsere Ausschlussmenge für den Logging-Schnappschuss muss die LiteLLM-eigene **enthalten**, nicht ihr gleichen. Ein Key zu wenig ist ein Leck, ein Key zu viel zeigt Konsumenten nur weniger. Wird gegen das installierte LiteLLM gemessen (ast-Parse), nicht abgeschrieben. |
| **Bypass-Kanal** | Ein Feld, das das Zielmodell erreicht, ohne die Maskierung zu durchlaufen. Historisch: Content-Parts (DATENSCHLE-57), `content`-Container (DATENSCHLE-64), Felder neben `content` (DATENSCHLE-66). |

## Architektur-Entscheidungen (ADRs)

ADRs liegen unter `docs/adr/`. Kurzverweise hier eintragen.
