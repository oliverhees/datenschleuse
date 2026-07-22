# 🔒 Datenschleuse

> Hänge sie zwischen dein Tool und die KI. Personenbezogene Daten verlassen dein System nie im Klartext.

Die Datenschleuse ist ein OpenAI-kompatibler Proxy, der personenbezogene Daten lokal erkennt, durch Platzhalter ersetzt, nur den anonymisierten Text an das KI-Modell schickt und die echten Werte in der Antwort lokal wieder einsetzt. Du biegst nur die `base_url` deines Tools auf die Datenschleuse um, sonst ändert sich nichts.

**Stack:** [LiteLLM](https://litellm.ai) (Proxy) + [Microsoft Presidio](https://microsoft.github.io/presidio/) (Erkennung) + eigene deutsche Recognizer.
**Backend:** forwardet an [eurouter.ai](https://www.eurouter.ai) (EU-gehostet, GDPR, Zero Data Retention).

---

## ⚠️ Ehrliche DSGVO-Einordnung (bitte lesen)

Die Datenschleuse **reduziert das Risiko erheblich**, indem Personendaten gar nicht erst im Klartext an den Modellanbieter gehen. Sie ist eine technische Maßnahme im Sinne von **Art. 25 DSGVO** (Datenschutz durch Technikgestaltung), eine zusätzliche Schutzschicht. Aber:

- Pseudonymisierung nimmt die Daten rechtlich **nicht** aus dem DSGVO-Scope.
- Die Datenschleuse ist **kein** Compliance-Zertifikat und **kein** Ersatz für eine Datenschutz-Folgenabschätzung. Wir bewerben sie nie als "DSGVO-konform".
- Keine PII-Erkennung ist zu 100 % perfekt. Es gibt immer ein Restrisiko (False Negatives).

Diese Ehrlichkeit ist Absicht. Wer dir etwas anderes verspricht, verkauft dir Marketing.

## 📜 Lizenz

Der Kern (dieser Proxy, die Presidio-Integration, die deutschen Recognizer) steht unter der **[GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE)** — eine von der Open Source Initiative anerkannte, echte Open-Source-Lizenz. Frei nutzbar, frei veränderbar, frei weitergebbar. Der Copyleft-Effekt: wer die Datenschleuse verändert und als Netzwerkdienst anbietet (auch ohne den Code selbst weiterzugeben), muss den veränderten Quellcode ebenfalls offenlegen. Das verhindert, dass jemand den Kern in ein geschlossenes, proprietäres Produkt forkt, ohne etwas zurückzugeben.

Ein späteres Portal/Cockpit (Dashboard, Self-Learning-Filter-UI) kann separat lizenziert oder als gehosteter Dienst angeboten werden — das ist bewusst getrennt vom offenen Kern.

---

## 🚀 Quickstart

```bash
# 1. Konfiguration vorbereiten
cp .env.example .env
# .env öffnen und EUROUTER_API_KEY eintragen

# 2. Modelle prüfen
# In litellm/config.yaml die Modell-IDs (aktuell Platzhalter) an die
# eurouter.ai-Modellliste anpassen -- mehrere model_list-Einträge möglich,
# jeder taucht als wählbares Modell in OpenAI-kompatiblen Clients auf

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

Standard (über Presidio, deutsch): Namen, Orte, E-Mail, Telefon, Kreditkarte, IBAN, IP-Adresse.
Eigene deutsche Recognizer: **Steuer-ID, Sozialversicherungsnummer, Handelsregisternummer, KFZ-Kennzeichen.**
Genau diese deutschen Entitäten erkennt Standard-Presidio nicht, das ist der Kern-Mehrwert.

Gemessen gegen einen eigenen deutschen Testkorpus (`test/corpus/`): **Recall 100 %, Precision 100 %** über alle Pflicht-Entitäten (Ziel war ≥95 %/≥90 %). Lauf jederzeit selbst wiederholbar: `python3 test/corpus-benchmark.py`.

Noch eine bekannte Lücke: **Quasi-Identifier-Kombinationen** (z. B. "42, männlich, Ingenieur in Weimar") werden noch nicht erkannt, das ist reine Einzelwort-Erkennung. Steht auf der Roadmap.

---

## 🔧 Status: v0.2 (live getestet, eigener Custom-Guardrail)

Der PII-Erkennungsteil ist gegen einen echten laufenden Presidio-Stack verifiziert, nicht nur konzeptionell:

- [x] Presidio-Analyzer lädt das deutsche Modell + alle Custom-Recognizer
- [x] Maskierung kommt beim Modell nachweislich anonymisiert an (End-to-End-Test gegen den echten Proxy)
- [x] Streaming-sichere Re-Identification über einen eigenen Sliding-Window-Guardrail (`litellm/datenschleuse_guardrail.py`, 21 Unit-Tests) — ersetzt LiteLLMs eingebauten Presidio-Guardrail, der beim Streaming den kompletten Antworttext buffert und damit Time-to-first-Token killt
- [x] Fail-closed bestätigt: Presidio nicht erreichbar → Request wird geblockt, kein unmaskiertes PII geht raus
- [ ] Echte eurouter.ai-Modell-ID in `litellm/config.yaml` (Platzhalter aktuell) — braucht einen gültigen Test-Key
- [ ] Kompletter Streaming-Live-Test mit über Chunk-Grenzen gesplittetem Platzhalter (Logik ist getestet, echte SSE-Antwort noch nicht)

### Bekannte Grenzen v0.2
- Multi-Modell-Auswahl ist technisch fertig (mehrere `model_list`-Einträge, automatische Erkennung durch OpenAI-kompatible Clients wie Hermes), aber die konkreten eurouter-Modell-Pfade sind noch Platzhalter.
- Quasi-Identifier-Erkennung fehlt noch (siehe oben).
- Self-Learning-Filter (eigene Muster im laufenden Betrieb nachtragen) ist konzipiert, noch nicht gebaut — Presidio hat dafür kein Bordmittel, das kommt als eigener kleiner Wrapper-Service.

Siehe `KONZEPT.md` für Vision, Markt und Roadmap, `PROJEKT-STATUS.md` für den aktuellen Stand, `ISA.md` für die vollständige Kriterienliste.
