# Projekt-Status: Datenschleuse

**Phase:** PoC-Gerüst v0.1 (gebaut, ungetestet) + Architektur-/Strategie-Update | **Letzte Aktualisierung:** 2026-07-22

## Update 2026-07-22: Architektur-Pivot zu Hermes-Plugin, Lizenz entschieden
- Vollständige ISA angelegt: `ISA.md` (38 ISCs, siehe dort für Details)
- **Multi-Modell-Auswahl technisch bestätigt & umgesetzt:** `litellm/config.yaml` hat jetzt 3 Modell-Einträge; Hermes' "custom"-Provider entdeckt sie automatisch über `GET /v1/models` (kein Hermes-Code nötig). Modell-IDs sind Platzhalter bis echter eurouter-Key da ist.
- **Lizenz entschieden: Open-Core.** Kern (LiteLLM+Presidio+DE-Recognizer) bleibt Open Source, Premium/Portal separat. MIT vs. AGPL für den Kern noch offen (Advisor empfiehlt AGPL gegen Fork-durch-Wettbewerber).
- **Positionierung geändert:** primärer Vertriebsweg = Hermes Model-Provider-Plugin (`hermes plugins install`) + Desktop-Pane-Cockpit statt separates Web-Portal. Bestätigt durch externe Marktrecherche (Community-Nachfrage grün, kein starker Wettbewerber, OSS war Top-Ask).
- **Neue v1-Gates identifiziert (wichtiger als Deploy-Frage):** streaming-sichere Re-Identification, gemessenes Recall/Precision-Ziel für deutsche PII-Erkennung, Quasi-Identifier-Erkennung aus Kontext, Self-Learning-Filter ohne Roh-PII-Speicherung.
- **Rechtliches Framing geschärft:** nie "DSGVO-Compliance-Lösung", immer "technische Maßnahme nach Art. 25 DSGVO".

**Task-Tracking:** Projekt "Datenschleuse" in Plane angelegt (privat, Workspace codelabs), Projekt-ID `d8c45b0f-18bc-4b20-9c86-e062cfc26205`. 9 Themenblöcke, 37 Einzelaufgaben, alle aus der ISA abgeleitet. 2 Aufgaben bereits als erledigt markiert (ISC-1 Multi-Model-Config, ISC-33 Lizenz-Entscheidung dokumentiert).

## PoC v0.1 Stand
- Docker-Setup gebaut: LiteLLM-Proxy + Presidio-Analyzer (DE-Modell) + Anonymizer
- Backend: eurouter.ai (Oliver besorgt Test-Key)
- Eigene DE-Recognizer: Steuer-ID, Sozialversicherung, Handelsregister, KFZ
- Verifiziert (ohne Key): Docker da (v29.5.1), compose + alle YAMLs syntaktisch OK
- OFFEN bis Live-Test: eurouter-Modell-ID, Presidio-Recognizer-Schema gegen reale Version, Maskierung/Re-Id/fail-closed wirklich greifen

## Wo wir stehen
- Idee geboren (Auslöser: github.com/flbcoat/austrai-privacyproxy), Oliver will was Eigenes/Besseres
- Marktcheck gemacht: DACH-Markt nicht leer, echte Lücke = Open-Source/Community
- Strategie entschieden: Open-Source-Community-Asset (Reichweite/Autorität zuerst, Umsatz folgt)
- Bau-Ansatz entschieden: auf LiteLLM + Presidio aufsetzen, Eigenanteil = deutsche Recognizer + Re-Id + Packaging
- Konzeptpapier geschrieben (siehe KONZEPT.md)

## Offene Entscheidungen
- [x] Name festgelegt: **Datenschleuse** (2026-06-29)
- [ ] Soll ein separater Haupt-Projektordner unter /mnt/projekte/eigene_projekte_neu/ entstehen (Geschwister zu ALICE), sobald Code startet?
- [ ] Domain/GitHub-Verfügbarkeit für "Datenschleuse" prüfen vor Launch

## Nächste Schritte
1. PoC (v0.1) bauen: LiteLLM + Presidio + erste deutsche Recognizer + Re-Id, Docker, gegen EU-Router testen
2. Benchmark deutsche PII-Erkennung als Beweis/Marketing

## Notizen
- DSGVO ehrlich kommunizieren (Pseudonymisierung != außerhalb DSGVO-Scope)
- Streaming-sicheres Re-Identification ist der technische Qualitäts-Hebel
