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

## ⚖️ Fail-Policy: Verfügbarkeit vs. Datenschutz (bewusste Entscheidung)

Die Datenschleuse sitzt inline im Anfrageweg. Fällt Presidio aus, hat das zwei mögliche Verhalten:

- **Fail-closed (so implementiert):** Die Anfrage wird geblockt. Du bekommst gar keine Antwort, statt einer unmaskierten. **Konsequenz:** Ist Presidio down, kannst du über die Datenschleuse gar keine KI-Anfragen mehr stellen — sie wird zum Single Point of Failure für deinen gesamten KI-Zugriff.
- **Fail-open (bewusst NICHT implementiert):** Bei Presidio-Ausfall würde die Anfrage unmaskiert durchgereicht. Mehr Verfügbarkeit, aber genau in dem Moment, wo der Schutz am nötigsten wäre (Störung), fällt er weg — für ein Privacy-Tool ein inakzeptabler Trade-off.

Wir wählen **fail-closed**, weil ein verlorener Request ärgerlich, aber ein PII-Leck nicht rückgängig zu machen ist. Wenn dir das für deinen Anwendungsfall zu strikt ist (z. B. unkritische interne Tests), kannst du das im Custom-Guardrail-Code (`litellm/datenschleuse_guardrail.py`, `_analyze()`) anpassen — aber das ist eine bewusste Abweichung vom Standard, keine Konfigurationsoption.

## 🛡️ Schutzklassen-Modell: drei Sensitivitätsstufen (Stufe 3 ist eine harte Code-Garantie)

Nicht jede Anfrage ist gleich heikel. Bevor überhaupt maskiert wird, ordnet die Datenschleuse jede Nachricht einer von drei Schutzklassen zu:

- **Stufe 1 — niedrig sensibel:** normaler Inhalt. Geht nach der normalen PII-Maskierung an die Cloud.
- **Stufe 2 — vertraulich:** interne Geschäfts-/Vertragsdaten mit Personenbezug (z. B. Gehalt, Vertragsnummer, „NDA"/„vertraulich"). Braucht Anonymisierung **und** eine explizite Freigabe (`metadata.sensitivity_approval: true`). **Ohne Freigabe wird blockiert** — „Freigabe fehlt" ist der sichere Default, nicht „automatisch durchlassen".
- **Stufe 3 — höchst sensibel:** besondere Kategorien personenbezogener Daten nach **Art. 9 DSGVO** (Gesundheit, Religion/Weltanschauung, Gewerkschaft, sexuelle Orientierung, biometrische/genetische Daten) und strafrechtliche Verurteilungen nach **Art. 10 DSGVO** — jeweils in Kombination mit einem Personenbezug. Diese Anfragen werden **NIE an die Cloud geschickt, auch nicht anonymisiert.**

Der entscheidende Punkt bei Stufe 3: **Das ist eine harte Zusage im Code, keine Konfigurationsoption.** Der Block lässt sich nicht per Config, Header oder Freigabe-Flag umgehen. Wer die Anfrage explizit als „harmlos" markiert, kann eine als Stufe 3 erkannte Nachricht trotzdem nicht durchdrücken — die strengere Einstufung gewinnt immer (der Nutzer kann eine Anfrage nur strenger, nie laxer machen). Die Durchsetzungsfunktion nimmt bewusst keinen Bypass-Parameter (`force`, `override`) entgegen, damit auch später niemand versehentlich eine Hintertür einbaut. Genau darum ist es eine Garantie und kein Feature-Flag.

Ehrlich bleibt ehrlich: Die Klassifizierung ist regelbasiert (Signalwörter aus `presidio/sensitivity-keywords.yml` + Personenerkennung) und damit transparent und nachprüfbar — aber wie jede Mustererkennung nicht zu 100 % vollständig. Sie ist bewusst **fail-closed**: bei Unsicherheit stuft sie strenger ein, nicht laxer. Jede Einstufung liefert eine nachvollziehbare Begründung (welche Regel gegriffen hat), damit ein Sicherheits-Gate kein Blackbox bleibt. Details zur Integration: `docs/SENSITIVITY-INTEGRATION.md`.

## 🇩🇪 Was erkannt wird

Standard (über Presidio, deutsch): Namen, Orte, E-Mail, Telefon, Kreditkarte, IBAN, IP-Adresse.
Eigene deutsche Recognizer: **Steuer-ID, Sozialversicherungsnummer, Handelsregisternummer, KFZ-Kennzeichen.**
Genau diese deutschen Entitäten erkennt Standard-Presidio nicht, das ist der Kern-Mehrwert.

Gemessen gegen einen eigenen deutschen Testkorpus (`test/corpus/`): **Recall 100 %, Precision 100 %** über alle Pflicht-Entitäten (Ziel war ≥95 %/≥90 %). Lauf jederzeit selbst wiederholbar: `python3 test/corpus-benchmark.py`.

### 🧩 Quasi-Identifier: Session-übergreifende Akkumulation

**Quasi-Identifier (QI)** sind einzeln harmlos, in Kombination re-identifizierend. Klassiker (Sweeney): **PLZ + Geburtsdatum + Geschlecht identifiziert ~87 % der Menschen eindeutig.** Presidio ist zustandslos und sieht jede Nachricht isoliert — die Gefahr entsteht erst, wenn sich solche Merkmale über eine Konversation hinweg ansammeln ("männlich" in Nachricht 1, "Jahrgang 1979" in Nachricht 3, "PLZ 84028" in Nachricht 6).

Die Datenschleuse erkennt jetzt fünf deutsche QI-Typen über eigene Recognizer — **Postleitzahl, Geburtsjahr, TVöD-/Besoldungsgruppe, Geschlecht, Beruf** — und akkumuliert sie **verschlüsselt, lokal und TTL-begrenzt** pro Session (Default 24 h). Ab einem Schwellwert an *unterschiedlichen* QI-Typen werden neu auftretende QI nicht mehr im Klartext ans LLM gelassen, sondern **generalisiert statt gelöscht** (Rest-Nutzwert bleibt erhalten):

| QI-Typ | Beispiel | Generalisierung |
|--------|----------|-----------------|
| Postleitzahl | `84028` | `Region Bayern (Süd)/…` (grob über erste PLZ-Ziffer) |
| Geburtsjahr | `1979` | `Ende der 1970er` (Dekade + Phase) |
| TVöD/Besoldung | `TVöD E13` | `gehobenes Einkommensband (öffentlicher Dienst)` |
| Geschlecht | `männlich` | `[Geschlecht anonymisiert]` |
| Beruf | `Bürgermeister` | bleibt stehen, zählt aber zum Session-Risiko (Beruf+Ort) |

Die direkte-Identifier-Maskierung (Namen, IBAN, …) läuft davon **unberührt** weiter — QI-Verarbeitung ist eine zusätzliche Schicht.

### ⚖️ Trade-off: Utility vs. Privacy (konfigurierbar)

Der Schwellwert ist ein bewusster Regler zwischen erhaltenem Kontext (Utility) und Schutz (Privacy), einstellbar über `qi_risk_preset` in `litellm/config.yaml`:

- **`utility`** — Schwellwert 5. Permissiv: mehr Kontext bleibt im Klartext, Generalisierung greift spät. Für Fälle, in denen Nutzwert wichtiger ist als maximale Anonymität.
- **`balanced`** — Schwellwert 3 (**Default**). Ab drei unterschiedlichen QI-Typen in einer Session wird generalisiert — nah am Sweeney-Trio.
- **`paranoid`** — Schwellwert 1. Jede einzelne erkannte QI wird sofort generalisiert. Maximaler Schutz, wenig Kontext.

Wie bei der Fail-Policy gilt: der strengere Weg kostet Nutzwert, der permissivere kostet Schutz — die Wahl ist bewusst und dokumentiert, keine versteckte Voreinstellung. Ist `qi_risk_preset` gar nicht gesetzt, bleibt der QI-Layer komplett aus (dann wird auch kein `DATENSCHLEUSE_STATE_KEY` gebraucht).

> **Ehrliche Grenze:** Die Session-Akkumulation greift nur, wenn eine Konversation zuverlässig einer Session zugeordnet werden kann. LiteLLM erzeugt **keine** stabile Session-ID von sich aus — der Client muss eine mitschicken (`litellm_session_id` bzw. Header `x-litellm-session-id`). Fehlt sie, fällt die Datenschleuse auf den **API-Key-Hash** als groben Session-Proxy zurück (ein Key ≈ ein Nutzer). Das bündelt parallele Chats desselben Keys ineinander — akzeptable Näherung, aber keine exakte Konversations-Grenze. Details im Abschnitt „Bekannte Grenzen".

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
