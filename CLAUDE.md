# Projekt: Datenschleuse

Offener, selbst-hostbarer PII-Anonymisierungs-Proxy für LLM-Anfragen. Community-Asset für die DACH-KI-Szene.

## Kontext
- **Vollständiges Konzept:** `KONZEPT.md`
- **Aktueller Stand:** `PROJEKT-STATUS.md`
- **Strategie:** Open-Source-first, Reichweite/Autorität zuerst, Monetarisierung folgt

## Konventionen
- **Basis-Stack:** Python (LiteLLM + Microsoft Presidio). Bewusste Ausnahme von der bun/TypeScript-Regel, weil LiteLLM/Presidio die Standards sind. Begründung in KONZEPT.md §7.
- **Eigenanteil:** deutsche Custom-Recognizer, streaming-sicheres Re-Identification, Packaging/DX.
- **Sicherheit:** fail-closed by default, kein PII in Logs, Mapping verschlüsselt + lokal + TTL.
- **Kommunikation:** DSGVO ehrlich (Pseudonymisierung nimmt Daten NICHT aus dem DSGVO-Scope).
- **Deploy-Ziel:** `docker compose up` + One-Liner-Install im Stil des Coolify-Hardening-Repos.

## Wichtig
- Erkennungsrate ist nie 100%. Bei jeder Recognizer-Änderung gegen Testfälle prüfen.
- Bei neuen deutschen Entitäten: Recognizer + Testfall + Benchmark-Eintrag zusammen liefern.
