# 🔒 Datenschleuse

> Hänge sie zwischen dein Tool und die KI. Personenbezogene Daten verlassen dein System nie im Klartext.

Die Datenschleuse ist ein OpenAI-kompatibler Proxy, der personenbezogene Daten lokal erkennt, durch Platzhalter ersetzt, nur den anonymisierten Text an das KI-Modell schickt und die echten Werte in der Antwort lokal wieder einsetzt. Du biegst nur die `base_url` deines Tools auf die Datenschleuse um, sonst ändert sich nichts.

**Stack:** [LiteLLM](https://litellm.ai) (Proxy) + [Microsoft Presidio](https://microsoft.github.io/presidio/) (Erkennung) + eigene deutsche Recognizer.
**Backend:** forwardet an [eurouter.ai](https://www.eurouter.ai) (EU-gehostet, GDPR, Zero Data Retention).

---

## ⚠️ Ehrliche DSGVO-Einordnung (bitte lesen)

Die Datenschleuse **reduziert das Risiko erheblich**, indem Personendaten gar nicht erst im Klartext an den Modellanbieter gehen. Aber:

- Pseudonymisierung nimmt die Daten rechtlich **nicht** aus dem DSGVO-Scope.
- Die Datenschleuse ist **kein** Compliance-Zertifikat und **kein** Ersatz für eine Datenschutz-Folgenabschätzung.
- Keine PII-Erkennung ist zu 100 % perfekt. Es gibt immer ein Restrisiko (False Negatives).

Diese Ehrlichkeit ist Absicht. Wer dir etwas anderes verspricht, verkauft dir Marketing.

---

## 🚀 Quickstart

```bash
# 1. Konfiguration vorbereiten
cp .env.example .env
# .env öffnen und EUROUTER_API_KEY eintragen

# 2. Modell prüfen
# In litellm/config.yaml die Modell-ID an die eurouter.ai-Modellliste anpassen

# 3. Starten
docker compose up --build

# 4. Testen (in zweitem Terminal)
bash test/test-anonymisierung.sh
```

Deine Tools sprechen die Datenschleuse dann so an:
- **Base-URL:** `http://localhost:4000/v1`
- **API-Key:** der `DATENSCHLEUSE_MASTER_KEY` aus deiner `.env`
- **Modell:** `datenschleuse-gpt`

---

## 🧩 Architektur

```
Dein Tool  ──►  Datenschleuse (LiteLLM)  ──►  Presidio (erkennt + maskiert DE-PII)
                       │                              │
                       │  nur anonymisierter Text     │
                       ▼                              ▼
                 eurouter.ai (EU)  ──►  Antwort  ──►  Re-Identification lokal  ──►  Dein Tool
```

## 🇩🇪 Was erkannt wird

Standard (über Presidio, deutsch): Namen, Orte, E-Mail, Telefon, Kreditkarte, IBAN, IP.
Eigene deutsche Recognizer: **Steuer-ID, Sozialversicherungsnummer, Handelsregisternummer, KFZ-Kennzeichen.**
Genau diese deutschen Entitäten erkennt Standard-Presidio nicht, das ist der Kern-Mehrwert.

---

## 🔧 Status: v0.1 (Proof of Concept, ungetestet)

Dieses Gerüst ist durchdacht, aber noch **nicht live getestet**. Beim ersten echten Run gemeinsam zu verifizieren:

- [ ] Korrekte eurouter.ai-Modell-ID in `litellm/config.yaml`
- [ ] Presidio-Analyzer lädt das deutsche Modell + die Custom-Recognizer (Config-Schema gegen reale Presidio-Version prüfen, evtl. Feldnamen/Env-Vars anpassen)
- [ ] Maskierung kommt tatsächlich anonymisiert beim Modell an (Logs prüfen)
- [ ] Re-Identification (`output_parse_pii`) setzt Werte korrekt zurück
- [ ] Fail-closed-Verhalten bei Guardrail-Fehler

### Bekannte Grenzen v0.1
- Re-Identification funktioniert zuverlässig nur bei **non-streaming**. Streaming-sicheres Re-Id kommt in v0.2.
- Custom-Recognizer-Schema ist versionsabhängig (siehe oben).

Siehe `KONZEPT.md` für Vision, Markt und Roadmap, `PROJEKT-STATUS.md` für den aktuellen Stand.
