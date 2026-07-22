---
task: "Datenschleuse: Multi-Model-Auswahl, Coolify-Template, Lizenz-Pivot, Portal/Dashboard, Self-Learning-Filter"
project: datenschleuse
effort: E3
effort_source: classifier
phase: plan
progress: 1/38
mode: interactive
started: 2026-07-22T08:48:01+02:00
updated: 2026-07-22T08:48:01+02:00
---

## Problem

Der Datenschleuse-PoC (v0.1) forwardet an genau EIN hartverdrahtetes eurouter.ai-Modell (`litellm/config.yaml`, `model_name: datenschleuse-gpt`). Wenn Oliver die Datenschleuse vor Hermes Desktop schaltet, kann er dort kein Modell mehr wählen — genau das Problem, das er heute schon mit der direkten EU-Router-Anbindung hat (immer nur ein Modell einstellbar), würde durch die Datenschleuse nicht gelöst, sondern durchgereicht. Zusätzlich soll aus dem PoC ein deploybarer, potenziell kommerzieller Dienst werden (Coolify-Template, restriktive Lizenz, Portal mit Audit-Log, selbstjustierbares Filtersystem) — das ist ein Sprung vom Ein-Personen-PoC zum Produkt mit offenen Grundsatzfragen.

## Vision

Oliver öffnet Hermes Desktop, wählt "Datenschleuse" als Custom-Provider, und sieht dort dieselbe Modellauswahl wie direkt bei eurouter.ai — nur dass jede Anfrage vorher lokal von PII befreit wird. Ein `docker compose up` (oder Coolify-Klick) bringt den ganzen Stack hoch. Ein Dashboard zeigt ihm auf einen Blick, wie viele Entitäten heute maskiert wurden, ohne je Klartext-PII zu speichern. Wenn Presidio ein Muster übersieht (z.B. eine interne Rechnungsnummer), trägt er es in unter zwei Minuten über die UI nach — ohne Neustart, ohne Code-Änderung.

## Out of Scope

- Kein vollständiges ML-basiertes Selbstlern-System, das eigenständig neue PII-Muster aus Traffic ableitet — das wäre ein Forschungsprojekt für sich und würde bedeuten, unredigierte Beispieldaten zu speichern, um daraus zu lernen (Widerspruch zu "kein PII in Logs"). Diese Runde deckt nur den *menschengeführten* Nachpflege-Loop ab (Oliver/Admin definiert Muster, System wendet es an).
- Keine Mandanten-/Multi-Tenant-Architektur in dieser Runde — das Portal ist zunächst Single-Operator (Oliver), nicht Multi-Kunde-SaaS. Das ist eine spätere, eigene Entscheidung.
- Keine finale Lizenztext-Formulierung (Juristendeutsch) — nur die strategische Richtungsentscheidung (Open-Core vs. vollständig restriktiv) plus Wahl einer bestehenden Lizenz-Vorlage.
- Kein Live-Test gegen eurouter.ai in dieser Runde, solange kein API-Key vorliegt (bereits als offener Punkt in PROJEKT-STATUS.md dokumentiert).

## Principles

- Ehrliche Kommunikation vor Feature-Tempo: eine Strategie-Kehrtwende (OSS → restriktiv) wird sichtbar gemacht und zur Entscheidung vorgelegt, nicht still übernommen.
- DSGVO-Ehrlichkeit bleibt Kernprinzip des Projekts (bereits in CLAUDE.md/KONZEPT.md verankert) — ein Audit-Feature darf das Kernversprechen "kein PII in Logs" nicht unterlaufen.
- Bestehende Infrastruktur wiederverwenden statt neu erfinden (LiteLLM/Presidio-Bordmittel prüfen, bevor Custom-Dashboard gebaut wird) — deckt sich mit der bereits getroffenen Entscheidung "auf LiteLLM+Presidio aufsetzen, nicht bei Null".

## Constraints

- Backend bleibt eurouter.ai (EU-gehostet, GDPR, Zero Data Retention) — kein Wechsel auf US-Router.
- Fail-closed bei Guardrail-Fehlern bleibt Pflicht (bestehende Projekt-Konvention).
- Mapping/Vault bleibt verschlüsselt + lokal + TTL-begrenzt (bestehende Projekt-Konvention).
- Jede neue deutsche Entität braucht Recognizer + Testfall + Benchmark-Eintrag zusammen (bestehende CLAUDE.md-Regel des Projekts).
- Hermes' Provider-Mechanismus (`fetch_models()` → `GET {base_url}/models`) ist eine externe, nicht veränderbare Schnittstelle — die Datenschleuse muss sich daran anpassen, nicht umgekehrt.

## Goal

Die Datenschleuse bietet über ihren bestehenden OpenAI-kompatiblen Endpoint mehrere eurouter.ai-Modelle zur Auswahl an (verifiziert über Hermes' Custom-Provider-Modell-Picker), ist per Coolify-Template deploybar, und Oliver hat eine bewusste, dokumentierte Entscheidung zu Lizenz-Richtung und Portal/Dashboard/Self-Learning-Scope getroffen, bevor an diesen drei Punkten Code entsteht.

## Criteria

- [x] ISC-1: `litellm/config.yaml` enthält mindestens zwei `model_list`-Einträge mit unterschiedlichen eurouter.ai-Modell-IDs
- [ ] ISC-2: jeder `model_list`-Eintrag referenziert einen aus eurouter.ai-Doku bestätigten Modell-Identifier
- [ ] ISC-3: `GET /v1/models` am Datenschleuse-Proxy liefert alle konfigurierten `model_name`-Werte zurück
- [ ] ISC-4: `POST /v1/chat/completions` mit explizitem `model`-Feld routet zum passenden eurouter-Modell (Live-Test mit echtem Key)
- [ ] ISC-5: Presidio-Guardrail (`pre_call` PII-Maskierung) greift identisch unabhängig vom gewählten Modell
- [ ] ISC-6: Hermes' "custom"-Provider zeigt gegen die Datenschleuse-Base-URL alle konfigurierten Modellnamen im Picker (Live-Test in Hermes Desktop)
- [ ] ISC-7: Anti: kein Modellwechsel im Request umgeht die PII-Maskierungs-Pipeline
- [ ] ISC-8: `docker-compose.yml` nutzt ausschließlich Environment-Variablen für Secrets (kein hartkodierter Key/Master-Key)
- [ ] ISC-9: Ein `coolify-template.json` (oder äquivalent) existiert nach Vorbild von `paione/coolify-template.json`
- [ ] ISC-10: `.env.example` listet alle für den Deploy nötigen Variablen inkl. `EUROUTER_API_KEY`, `DATENSCHLEUSE_MASTER_KEY`
- [ ] ISC-11: Eine One-Liner-Deploy-Doku existiert im Stil des Coolify-Hardening-Repos
- [ ] ISC-12: Anti: kein Secret ist im Template oder Compose-File im Klartext eingetragen
- [ ] ISC-13: Lizenz-Richtungsentscheidung (Open-Core vs. vollständig restriktiv) ist mit Oliver getroffen und in `## Decisions` protokolliert
- [ ] ISC-14: Die getroffene Lizenz-Richtung ist in einer `LICENSE`-Datei im Projekt hinterlegt
- [ ] ISC-15: README kommuniziert die Lizenz ehrlich — kein "Open Source"-Framing, falls die Lizenz OSI-Kriterien nicht erfüllt
- [ ] ISC-16: Anti: die getroffene Lizenz-Richtung widerspricht nicht der dokumentierten "Reichweite zuerst"-Strategie (`projekt-datenschleuse.md`), ohne dass der Widerspruch Oliver explizit vorgelegt wurde
- [ ] ISC-17: Geprüft und dokumentiert, ob LiteLLM Proxy Admin-UI/Spend-Logs den Dashboard-Bedarf bereits ganz oder teilweise abdeckt
- [ ] ISC-18: Dashboard-Konzept zeigt Zeitpunkt, Ziel-Modell, Anzahl maskierter Entitäten pro Request — ohne Klartext-PII-Feld
- [ ] ISC-19: Audit-Log-Konzept persistiert ausschließlich maskierte/pseudonymisierte Werte, nie Klartext-PII
- [ ] ISC-20: Dashboard-Zugriff ist im Konzept authentifiziert (kein offener Endpoint)
- [ ] ISC-21: Anti: Klartext-PII landet im Audit-Log oder in einer Dashboard-Datenbank
- [ ] ISC-22: UI-Konzept erlaubt Eingabe eines neuen Regex-Musters + Entity-Label für einen deutschen Custom-Recognizer
- [ ] ISC-23: Neu hinzugefügter Recognizer wird ohne Proxy-Neustart aktiv (Presidio-Hot-Reload-Mechanismus identifiziert oder Alternative dokumentiert)
- [ ] ISC-24: Neuer Recognizer erhält vor Live-Schaltung einen Testfall, der ihn gegen ein Beispiel verifiziert
- [ ] ISC-25: Bestehende Recognizer-Liste ist im Konzept über die UI einsehbar
- [ ] ISC-26: Anti: ein fehlerhaftes neues Muster blockiert nicht die gesamte Pipeline, sondern nur die eine Entität (fail-closed bleibt scoped)
- [ ] ISC-27: Antecedent: der Nachpflege-Workflow ist so konzipiert, dass Oliver ein neues Muster in unter 2 Minuten eingeben und testen kann
- [ ] ISC-28: Priorisierungs-Reihenfolge der 5 Ausbaustufen ist mit Oliver abgestimmt und in `## Decisions` protokolliert
- [ ] ISC-29: Die Lizenz-Pivot-Spannung (OSS-first vs. restriktiv) wurde Oliver explizit vorgelegt, nicht still übernommen
- [ ] ISC-30: Die DSGVO-Log-Spannung (Audit-Dashboard vs. "kein PII in Logs") wurde Oliver explizit vorgelegt
- [ ] ISC-31: Der bestehende ungetestete PoC-Stand (kein Live-Key) blockiert die Konzeptentscheidungen dieser Runde nicht
- [ ] ISC-32: Anti: diese Runde committed keinen Code, der Lizenz- oder Dashboard-Scope-Entscheidungen vorwegnimmt, bevor Oliver entschieden hat
- [ ] ISC-33: Lizenz-Feindetail entschieden: MIT vs. AGPL-3.0 für den Proxy-Kern (Advisor-Einwand: MIT erlaubt DACH-Wettbewerbern wie KI-Shield, den Kern in geschlossene SaaS zu forken; AGPL erzwingt Quelloffenheit bei Netzwerk-Nutzung)
- [ ] ISC-34: Streaming-sichere Re-Identification hat einen dokumentierten Lösungsansatz (Platzhalter-Buffering über SSE-Chunk-Grenzen) und ist als v1-Gate markiert, nicht als Detail
- [ ] ISC-35: Ein gemessenes Recall/Precision-Ziel für deutsche PII-Erkennung existiert, gegen einen deutschen Testkorpus verifiziert, bevor v1 als "fertig" gilt
- [ ] ISC-36: Self-Learning-Filter-Design verifiziert: keine Rohdaten-Speicherung/kein Training auf PII-Inhalten — nur Muster (Regex/Label), die Oliver manuell einträgt
- [ ] ISC-37: Fail-Policy bei Proxy-Ausfall ist explizit entschieden und dokumentiert (fail-closed = kein LLM-Zugriff bei Störung, bewusster Trade-off gegen fail-open = Leck-Risiko)
- [ ] ISC-38: Anti: Datenschleuse wird nicht als "DSGVO-Compliance-Lösung" beworben, sondern als technische Maßnahme nach Art. 25 DSGVO

## Test Strategy

| ISC | Type | Check | Threshold | Tool |
|-----|------|-------|-----------|------|
| ISC-1 | config | grep `model_name:` Vorkommen in config.yaml | ≥2 | Read/Grep |
| ISC-2 | doc-check | eurouter.ai Modell-Doku gegen Config abgleichen | exakte Übereinstimmung | WebFetch/Read |
| ISC-3 | live | `curl {base_url}/models` | enthält alle model_name | Bash/curl |
| ISC-4 | live | `curl -d '{"model":"X",...}' /chat/completions` mit echtem Key | 200 + korrektes Modell in Antwort | Bash/curl |
| ISC-5 | live | Request mit PII gegen beide Modelle | PII in beiden maskiert | Bash/curl |
| ISC-6 | manual-live | Hermes Desktop custom-Provider konfigurieren, Modell-Dropdown öffnen | alle konfigurierten Modelle sichtbar | Interceptor/manuell |
| ISC-7 | live | Request ohne "model"-Override | Guardrail greift trotzdem | Bash/curl |
| ISC-8 | inspection | grep `os.environ/` statt Klartext in compose+config | keine hartkodierten Secrets | Grep |
| ISC-9 | file-exists | Datei `coolify-template.json` vorhanden + valides JSON | Read/jq |
| ISC-10 | file-exists | `.env.example` enthält alle referenzierten env-Namen | Diff gegen compose/config | Grep |
| ISC-11 | file-exists | Deploy-Doku-Abschnitt vorhanden | Read |
| ISC-12 | inspection | Grep nach Klartext-Key-Mustern in Compose/Template | 0 Treffer | Grep |
| ISC-13 | decision-log | Eintrag in `## Decisions` mit Datum + Begründung | Read |
| ISC-14 | file-exists | `LICENSE` vorhanden, Inhalt passt zu Decision | Read |
| ISC-15 | inspection | README-Lizenzabschnitt gegen OSI-Kriterien geprüft | Read |
| ISC-16 | consistency | Decision-Eintrag referenziert den Strategie-Widerspruch explizit | Read |
| ISC-17 | research | LiteLLM-Doku/Repo auf Admin-UI/Spend-Log-Feature geprüft | dokumentiertes Ergebnis in Decisions | WebFetch/Agent |
| ISC-18 | concept-review | Dashboard-Feldliste enthält kein PII-Feld | Read |
| ISC-19 | concept-review | Audit-Log-Schema enthält nur maskierte Felder | Read |
| ISC-20 | concept-review | Auth-Mechanismus im Konzept benannt | Read |
| ISC-21 | inspection | Schema-Review gegen "kein PII"-Prinzip | 0 Klartext-Felder | Read |
| ISC-22 | concept-review | UI-Mockup/Flow-Beschreibung für Muster-Eingabe vorhanden | Read |
| ISC-23 | research | Presidio RecognizerRegistry Hot-Reload-Fähigkeit recherchiert | dokumentiertes Ergebnis | WebFetch/Agent |
| ISC-24 | concept-review | Workflow verlangt Testfall vor Live-Schaltung | Read |
| ISC-25 | concept-review | Recognizer-Liste-Ansicht im Konzept vorhanden | Read |
| ISC-26 | concept-review | Fehlerbehandlung pro-Entität statt global beschrieben | Read |
| ISC-27 | manual | Zeitmessung eines Test-Durchlaufs (sobald gebaut) | <2min | manuell, DEFERRED bis Build |
| ISC-28 | decision-log | Prioritäts-Reihenfolge in `## Decisions` | Read |
| ISC-29 | conversation | Lizenz-Spannung im Chat explizit benannt | diese Antwort | inline |
| ISC-30 | conversation | DSGVO-Log-Spannung im Chat explizit benannt | diese Antwort | inline |
| ISC-31 | consistency | PROJEKT-STATUS.md offene Punkte bleiben unverändert offen, nicht blockierend | Read |
| ISC-32 | inspection | `git diff`/Dateiliste zeigt keine Lizenz-Datei-Änderung, keine Dashboard-Code-Datei vor Oliver-Entscheidung | Bash |
| ISC-33 | decision-log | Decision-Eintrag MIT vs. AGPL mit Begründung | Read |
| ISC-34 | live | Streaming-Response mit über Chunk-Grenzen gesplittetem Platzhalter, Re-Id-Ergebnis prüfen | Bash/curl SSE |
| ISC-35 | benchmark | Testkorpus deutscher PII-Beispiele gegen Presidio+Custom-Recognizer laufen lassen, Recall/Precision berechnen | Score ≥ dokumentiertes Ziel | Bash/Script |
| ISC-36 | concept-review | Self-Learning-Design-Doku enthält explizit "kein Raw-Storage/kein Training auf PII" | Read |
| ISC-37 | decision-log | Fail-Policy-Entscheidung dokumentiert + in `general_settings` config umgesetzt | Read/Grep |
| ISC-38 | inspection | README/Marketing-Texte enthalten "Art. 25", nicht "DSGVO-konform" | Grep |

## Features

| Name | Beschreibung | satisfies | depends_on | parallelizable |
|------|--------------|-----------|------------|----------------|
| multi-model-routing | Mehrere eurouter-Modelle in LiteLLM-Config, Hermes-Provider-Verifikation | ISC-1..7 | — | ja |
| coolify-deploy | Coolify-Template + Compose-Härtung + Doku | ISC-8..12 | multi-model-routing (Config muss final sein) | ja (nach Config-Freeze) |
| license-pivot | Strategieentscheidung Lizenz + LICENSE-Datei + README | ISC-13..16 | Oliver-Entscheidung (blockierend) | nein |
| audit-dashboard | PII-freies Portal/Dashboard-Konzept + spätere Umsetzung | ISC-17..21 | Oliver-Entscheidung zu Scope (blockierend) | ja (parallel zu license-pivot) |
| self-learning-filter | Human-in-the-loop Recognizer-Nachpflege-UI | ISC-22..27 | audit-dashboard (teilt UI-Schicht) | nein |
| decision-transparency | Spannungen offenlegen, Priorisierung abstimmen, Scope-Commit verhindern | ISC-28..32 | — | nein, läuft zuerst |

## Decisions

- 2026-07-22 (Oliver, nach externer Bedarfsrecherche zu "PII-Shield für Hermes"): Lizenz-Richtung final entschieden — **Open-Core**. Proxy-Kern MIT-lizenziert (passt zur Hermes-Plugin-Ökosystem-Kultur), Premium/Portal separat. Bestätigt die FirstPrinciples-Empfehlung unten unabhängig. Zusätzlich validiert: Community-Nachfrage nach Open-Source war meistgevotete Frage (14↑) im Referenz-Thread, Wettbewerber (Tobit Sidekick, "NER+Proxy, das war's") verlor Vertrauen durch "nein". Positionierung ändert sich: primärer Vertriebsweg ist ein **Hermes Model-Provider-Plugin** (`hermes plugins install`) mit **Desktop-Pane als Redaction-Cockpit** statt (nur) separatem Web-Portal — das deckt den Dashboard/Self-Learning-Filter-Bedarf direkt in Hermes ab, kein eigenständiges Web-Frontend nötig für v1.
- 2026-07-22 (Marktrecherche, Feature-Specs aus 3 Einwänden): (1) Quasi-Identifier-Erkennung aus Kontext nötig (z.B. "42, männlich, Ingenieur in Weimar") — reine Einzelwort-Regex/NER reicht der Zielgruppe nicht, neue technische Anforderung über bestehende DE-Recognizer hinaus. (2) Rechtliche Framing-Pflicht: NIE als "DSGVO-Compliance-Lösung" bewerben, sondern als technische Maßnahme nach Art. 25 DSGVO ("zusätzliche Schutzschicht") — deckt sich mit bereits bestehendem Projekt-Prinzip, jetzt mit konkretem Rechtsartikel geschärft.
- 2026-07-22 (Advisor, Commitment-Boundary vor Empfehlung an Oliver): v1/v2-Split war falsch gerahmt — der MIT/AGPL-Proxy-Kern IST der v1, weil Open-Core das erzwingt (kann nicht "später" gebaut werden, ist per Definition schon Teil des Kerns). Was wirklich verschiebbar ist: die polierte, supportete Standalone-Erfahrung (Coolify-Template-Politur, generische Client-Doku), nicht der Code selbst. Empfehlung: v1-Fokus auf Hermes-Plugin+Cockpit als vermarktetes Produkt, Proxy-Kern läuft "mit", aber ohne eigene SLA/Support-Zusage für Nicht-Hermes-Clients. Zusätzlich 5 Lücken benannt, die wichtiger sind als die Deploy-Frage: (1) streaming-sichere Re-Identification ungelöst, (2) kein gemessenes Recall/Precision-Ziel für deutsche PII-Erkennung, (3) Self-Learning-Filter riskiert PII-Speicherung/Training wenn falsch designt, (4) Audit-Dashboard riskiert selbst zur PII-Quelle zu werden wenn falsch designt (durch SystemsThinking bereits sauber gelöst, siehe oben), (5) MIT vs. AGPL für den Kern nicht bewusst entschieden — MIT erlaubt Wettbewerbern, den Kern in geschlossene SaaS zu forken. Alle fünf als ISC-33..38 aufgenommen.
- 2026-07-22: Diese Runde liefert Konzept + eine konkrete, risikoarme Code-Änderung (Multi-Model-Config-Erweiterung), aber KEINE Lizenzänderung und KEINEN Dashboard-Code — beide hängen von Olivers Entscheidung ab (Constraint aus Out of Scope). Show-your-math für Delegation-Floor: Forge/Anvil nicht eingesetzt, da die einzige Code-Änderung dieser Runde eine triviale YAML-Erweiterung ist (kein Coding-Task im Sinne des Forge-Auto-Include-Gates); stattdessen zwei Research-Agents für LiteLLM-Admin-UI und Presidio-Hot-Reload eingesetzt (Delegation-Floor E3 ≥2 erfüllt).
- 2026-07-22 (litellm-admin-research, Agent-Ergebnis): LiteLLM Proxy hat bereits ein eingebautes Admin-UI (`/ui`, braucht Postgres-DB + master_key), das pro Request Zeitpunkt, Modell, Token-Verbrauch, Kosten UND (über `StandardLoggingPayload.applied_guardrails`/`guardrail_information`) die von Presidio maskierten Entity-Typen samt Confidence-Score zeigt — deckt den Kern von ISC-18 nativ ab, kein Custom-Dashboard-Backend nötig. **Entscheidender Fund für die DSGVO-Log-Spannung:** `litellm_settings.turn_off_message_logging: True` verhindert nativ, dass Message-Content geloggt wird, während Spend/Tokens/Modell/Zeitpunkt weiter getrackt werden — genau das Muster, das SystemsThinking als Lösung vorgeschlagen hat, existiert bereits als Config-Flag (ISC-19/21 dadurch strukturell einfacher: konfigurieren statt bauen). Offen laut Agent: unklar ob Content bei aktivem Flag durch Platzhalter ersetzt oder komplett weggelassen wird — vor Produktivnutzung selbst verifizieren (neuer Punkt für ISC-19-Testverfahren). Auth des Admin-UI nur Basic-Auth (`UI_USERNAME`/`UI_PASSWORD`), SSO nur Enterprise-Tier. Scope-Implikation für Feature `audit-dashboard`: primär LiteLLM-UI konfigurieren + ggf. per API in die Hermes-Cockpit-Pane einbetten, statt eigenes Dashboard-Backend zu bauen.
- 2026-07-22 (presidio-license-research, Agent-Ergebnis): Presidio hat **keinen offiziellen persistenten REST-Endpoint** zum dauerhaften Hot-Add eines Recognizers im laufenden Container — nur (a) In-Process `registry.add_recognizer()` im Python-SDK (nicht für den Docker-Container von außen nutzbar), (b) **Ad-hoc-Recognizer pro Request** über `ad_hoc_recognizers` im `/analyze`-Body (echtes Hot-Add, aber nicht persistent — gilt nur für die eine Anfrage), (c) YAML-Config + Container-Neustart, (d) eigener Wrapper-Endpoint um `registry.add_recognizer()` (In-Memory, muss zusätzlich in YAML persistiert werden für Neustart-Festigkeit). **Wichtige Design-Konsequenz für ISC-23:** das ursprünglich angenommene "Hot-Reload ohne Neustart" braucht zwingend einen selbstgebauten Wrapper-Endpoint (Option d) — es gibt kein Presidio-Bordmittel dafür. Lizenz-Zusatzfund: PolyForm Shield 1.0.0 (kommerzielle Nutzung erlaubt, aber Bau eines Konkurrenzprodukts verboten) wäre eine Option speziell für eine später *verteilte* Portal-Codebasis (falls Portal nicht nur gehostet, sondern auch als Code weitergegeben werden soll) — aktuell nicht akut, da Portal als gehosteter Dienst geplant ist. Bekannte Präzedenzfälle bestätigen das FirstPrinciples-Risiko: Terraform (MPL→BSL) und Elasticsearch (Apache→SSPL) lösten beide harte Community-Forks aus (OpenTofu, OpenSearch) — Grund mehr, den Kern klar AGPL/permissiv zu halten wie entschieden.
- 2026-07-22 (litellm-streaming-reid-research, Agent-Ergebnis): LiteLLM hat bereits eingebautes Streaming-Re-Identification-Handling für den OpenAI-kompatiblen `/chat/completions`-Pfad (`async_post_call_streaming_iterator_hook` in `litellm/proxy/guardrails/guardrail_hooks/presidio.py`) — sammelt ALLE Stream-Chunks, baut den Volltext zusammen, un-maskiert erst danach. Löst ISC-34 strukturell, kein Custom-Buffer-Code nötig — Scope-Reduktion nach demselben Muster wie beim LiteLLM-Admin-UI-Fund. **Wichtiger Trade-off, den Oliver kennen muss:** dadurch verliert Streaming effektiv Time-to-First-Token — die Antwort kommt bei Datenschleuse-Nutzung erst komplett, wie bei non-streaming. Das ist ein UX-Unterschied gegenüber direktem eurouter.ai-Zugriff, den Hermes-Nutzer spüren könnten. Nicht offiziell dokumentiert (nur im Code nachvollziehbar), versionsabhängig — Live-Test bleibt Pflicht. **Wichtige Einschränkung:** der Anthropic-Native-API-Passthrough-Pfad ist nachweislich kaputt für dieses Un-Masking (GitHub-Issue #22821) — Datenschleuse darf niemals Anthropic-native durchreichen, nur den OpenAI-kompatiblen Pfad nutzen (ist ohnehin die aktuelle Architektur).
- 2026-07-22 (litellm-custom-guardrail-research, Agent-Ergebnis): Mittelweg zwischen Full-Buffer-Streaming (LiteLLM-Bordmittel, killt Time-to-first-Token) und gar keiner Streaming-Sicherheit bestätigt machbar. LiteLLM unterstützt offiziell eigene Custom-Guardrail-Klassen (`litellm.integrations.custom_guardrail.CustomGuardrail`), registriert in config.yaml als `guardrail: <datei>.<Klasse>`. Die Streaming-Hook-Signatur (`async_post_call_streaming_iterator_hook`, gibt AsyncGenerator zurück, chunk-weise `yield`) erlaubt echtes inkrementelles Verarbeiten statt Full-Buffer. Kein offizielles Vorbild für den Sliding-Window-Lookback-Ansatz gefunden (Presidio/Lakera buffern beide voll) — Datenschleuse baut hier eigenständig, das ist ein echter Differenzierer, kein Nacharbeiten fremder Lösung. Entscheidung: eigene, selbstständige Guardrail-Klasse bauen (nicht auf LiteLLMs internes Presidio-Metadata-Schema verlassen, da Key-Name unsicher/nicht offiziell dokumentiert) — ruft Presidio Analyzer/Anonymizer selbst per REST auf (gleiche Container wie bisher), hält eigenes Platzhalter-Mapping im eigenen Metadata-Key, Sliding-Window-Tail-Puffer (~40 Zeichen) im Streaming-Hook. Ersetzt den bisherigen eingebauten `guardrail: presidio`-Eintrag komplett.
- 2026-07-22: ISC-1 umgesetzt und verifiziert — `litellm/config.yaml` von 1 auf 3 `model_list`-Einträge erweitert (gpt/claude/gemini als Platzhalter-Namen). ISC-2 (echte eurouter-Modell-IDs) bleibt offen bis Test-Key vorliegt — nicht fabriziert, um keine falschen Modell-Pfade als Fakt hinzustellen. Zwei Recherche-Agents (litellm-admin-research, presidio-license-research) laufen im Hintergrund weiter, Ergebnisse fließen bei Rückmeldung in die ISA ein.

## Verification

ISC-1: config-inspection — `grep -c "model_name:" litellm/config.yaml` → `3` (war 1 vor dieser Runde)
- 2026-07-22 (FirstPrinciples/Challenge): "Kompletter Non-Commercial-Lizenzwechsel" als unvalidated assumption entlarvt — widerspricht der eigenen Reichweite-Strategie. Empfehlung: Open-Core — Proxy-Kern (LiteLLM+Presidio+DE-Recognizer) bleibt permissiv für Reichweite, Portal/Dashboard wird separat lizenziert oder direkt als gehosteter Dienst angeboten (dann keine Lizenzfrage nötig). Freigabe steht noch aus (ISC-13).
- 2026-07-22 (SystemsThinking/CausalLoop): Reinforcing Loop (mehr Traffic → mehr Nachpflege → bessere Erkennung → mehr Vertrauen → mehr Traffic) kollidiert strukturell mit dem Balancing-Prinzip "kein PII in Logs" um dieselbe Ressource (Log-Detailgrad). Auflösung: Signal von Content trennen — Dashboard zeigt nur Konfidenz-Scores/Entity-Typ-Zählungen/Fail-closed-Häufungen, nie Klartext; Nachpflege-Review passiert client-seitig aus Olivers eigener Chat-Historie, nie serverseitig geloggt. Bestätigt: menschengeführter statt automatischer Lernloop war die strukturell richtige Wahl (ISC-19, ISC-21). Vorbehalt für späteren Multi-Tenant-Ausbau: Konfidenz-Score-Aggregation über wenig Traffic kann re-identifizierbar werden — als künftiges Anti-Kriterium vormerken, außerhalb des aktuellen Scopes (Out of Scope: kein Multi-Tenant).
