# Der Round-Trip-Beweis

> Die zentrale Behauptung der Datenschleuse lautet:
>
> **Klartext → Platzhalter → LLM → Platzhalter → Klartext.**
> Das Modell sieht nie den Klartext, der Anwender sieht nie den Platzhalter.
>
> Dieses Dokument beschreibt, wie diese Behauptung **bewiesen** wird — nicht
> behauptet, nicht in Unit-Tests simuliert, sondern gegen den echten Stack
> mitgeschnitten.

Reproduzieren:

```bash
./test/run-e2e-roundtrip.sh
```

Ein Aufruf, ein Exit-Code, ein Ordner voller Artefakte
(`test/e2e/artifacts/`). Exit-Code 0 heißt: alle Kriterien erfüllt.

---

## Warum ein eigener Beweis nötig war

Die Round-Trip-Logik (`Masker`, `reidentify_full`, `ReidStreamProcessor`) war
durch Unit-Tests abgedeckt. Unit-Tests beweisen aber nur, dass die Logik das
tut, was der Test ihr vorlegt. Sie beweisen **nicht**:

- dass LiteLLM das Re-Id-Mapping über den echten Hook-Pfad durchreicht,
- dass der Upstream-Payload auf der Leitung tatsächlich maskiert ist,
- dass echte SSE-Chunk-Grenzen eines echten Modells die Sliding-Window-Logik
  nicht doch zerlegen.

Genau das schließt dieser Beweis.

## Aufbau

```
Client ──► LiteLLM (Datenschleuse + Guardrail) ──► [ TAP ] ──► Ollama (llama3.1:8b)
   ▲                     │                            │
   │                     ▼                            ▼
Klartext            Presidio-Analyzer         Mitschnitt des Payloads,
zurück               (der echte!)             den das Modell wirklich sieht
```

Drei bewusste Entscheidungen:

**1. Der Tap sitzt an der Vertrauensgrenze.** Ein Nachweis aus dem
Guardrail-Code selbst wäre zirkulär — er würde das Verhalten aus derselben
Quelle belegen, die geprüft werden soll. `test/e2e/tap.py` protokolliert
deshalb dort, wo die Daten das System verlassen: auf der Leitung zum Modell.

**2. Das Backend ist lokal.** Ollama läuft auf derselben Maschine. Deshalb —
und nur deshalb — darf der Beweis mit **echten deutschen Testdaten** arbeiten
(Name, Straße, IBAN, Telefonnummer). Sie verlassen den Rechner nicht.

**3. Die Konfiguration ist nicht entschärft.** Der Guardrail-Block in
`test/e2e/config.e2e.yaml` ist absichtlich identisch zur Produktivkonfiguration
(gleiche Klasse, gleiche Parameter, gleiches QI-Preset `balanced`), und der
Analyzer ist der echte, laufende Container. Ein Beweis gegen eine abgeschwächte
Konfiguration wäre keiner.

Der E2E-Stack läuft isoliert neben dem Produktiv-Stack: eigener
Compose-Projektname, eigene Ports (4001 Proxy, 4600 Tap), **eigene, pro Lauf
frisch erzeugte Schlüssel**. Es wird nie ein Wert aus `.env` gelesen.

## Was geprüft wird

| Kriterium | Inhalt | Artefakt |
|---|---|---|
| **AK1** | Non-Streaming: Klartext kommt beim Client korrekt zurück | `ak1-*.json` |
| **AK2** | Streaming: auch über Chunk-Grenzen hinweg | `ak2-*-client-stream.sse`, `ak2-*-upstream-record.json` |
| **AK3** | Das LLM hat den Klartext nie gesehen | `ak3-upstream-payloads.json` |
| **AK4** | Stabile Zuordnung Wert ↔ Platzhalter | `ak4-*.json` |

Die Kernprüfung ist bewusst nicht auf einen erwarteten Antworttext verdrahtet
(das Modell formuliert frei). Stattdessen gilt: **für jeden Platzhalter, den
das Modell zurückgibt, muss beim Client der zugehörige Klartext stehen — und
der Platzhalter muss verschwunden sein.** Welche Platzhalter das Modell
zurückgab, wird aus dem Mitschnitt gelesen, nicht geraten.

### AK2: Chunk-Grenzen deterministisch statt zufällig

Ob ein Platzhalter über eine SSE-Chunk-Grenze zerrissen wird, entscheidet sonst
der Tokenizer des Modells — also Zufall. Der Beweis läuft deshalb **zweimal**:

- **`passthrough`** — realistischer Fall. In der Praxis zerreißt llama3.1 jeden
  Platzhalter ohnehin, z. B. `<DE_STRASSE_0>` in sieben Chunks:
  `[" <DE", "_STR", "AS", "SE", "_", "0", ">\n"]`
- **`shred`** — der Tap zerlegt jedes Delta in Ein-Zeichen-Events. Damit steht
  **garantiert jeder** Platzhalter zerrissen im Stream:
  `["<", "D", "E", "_", "S", "T", "R", "A", "S", "S", "E", "_", "0", ">"]`

In beiden Fällen liest der Client sauberen Klartext. Determinismus schlägt
Handarbeit (Methode #12).

## Befunde aus dem Beweislauf

### 1. Behoben: kollidierende Beispiel-Platzhalter im Hinweistext

Der Anonymisierungs-Hinweis nannte `<PERSON_1>`, `<ADDRESS_0>` usw. als
Beispiele — also exakt die Form `<TYP_ZAHL>`, die der `Masker` auch für **echte**
Werte vergibt. Im Beweislauf war `<PERSON_1>` gleichzeitig Beispiel im Hinweis
**und** echter Platzhalter für „Thomas Schneider". Greift das Modell das
Beispiel auf, macht die Re-Identifikation stillschweigend den echten Namen
daraus und setzt ihn an eine Stelle, an die er nie gehörte.

Kein PII-Leck — der Klartext geht weiterhin nicht raus. Aber eine **stille
falsche Antwort**, dieselbe Fehlerklasse wie der dokumentierte Live-Befund vom
2026-07-29 („Hallo Hans Müller!"), nur eine Ebene subtiler.

Behoben: die Beispiele nutzen jetzt `<PERSON_N>`. Der Masker nummeriert
ausschließlich mit Ziffern, ein `<..._N>` kann deshalb nie kollidieren.
Abgesichert durch `TestNoticePlaceholderCollision`.

### 2. Offen: PERSON-False-Positives bei ASCII-Umschrift

Presidios deutsches NER-Modell hält bestimmte großgeschriebene Wörter am
Satzanfang für Personennamen. Gemessen gegen den laufenden Analyzer:

| Eingabe | Ergebnis |
|---|---|
| `Aendere keinen einzigen Wert.` | `PERSON 0.85` auf `'Aendere'` |
| `Ändere keinen einzigen Wert.` | **keine Entität** |
| `Spaeter hat Maria Meier nochmal angerufen.` | `PERSON 0.85` auf `'Spaeter'` |
| `Fasse den Text zusammen.` | `PERSON 0.85` auf `'Fasse'` |
| `Erstelle eine Liste der Kunden.` | keine Entität |

Das Muster ist schärfer als „großgeschriebenes Verb am Satzanfang": es trifft
vor allem **ASCII-umschriebene Umlautwörter** (`Aendere`, `Spaeter`) — mit
korrektem Umlaut (`Ändere`) verschwindet der Treffer. Plausible Erklärung:
solche Tokens sind für das Modell out-of-vocabulary, und es rät PERSON.

**Einordnung:** Overmasking, kein Leck. Der Anwender bekommt seinen Text durch
die Rückübersetzung korrekt zurück. Ärgerlich wird es, wenn dadurch die Anfrage
für das Modell unverständlich wird — im Beweislauf wurde aus „Ändere keinen
einzigen Wert." ein „`<PERSON_0>` keinen einzigen Wert.", was die
Antwortqualität sichtbar gedrückt hat.

Gehört zur Präzisionsarbeit an der deutschen Erkennung (Recall/Precision-Ziel),
**nicht** in den Round-Trip. Dort mit Testkorpus und Benchmark behandeln.

## Voraussetzungen

- Docker + Compose v2
- laufender Produktiv-Stack (mindestens `datenschleuse-analyzer`) und das Image
  `datenschleuse-datenschleuse:latest` — also einmal `docker compose up --build`
- laufender Ollama-Container mit `llama3.1:8b`

Netze und Ollama-Adresse ermittelt das Skript selbst; nichts ist hartkodiert.
Abweichende Umgebungen über `DS_E2E_OLLAMA_CONTAINER`, `DS_E2E_OLLAMA_URL`,
`DS_E2E_OLLAMA_NETWORK`, `DS_E2E_PRESIDIO_NETWORK` überschreibbar.
`DS_E2E_KEEP_UP=1` lässt den Stack zum Nachschauen stehen.

## Verhältnis zur CI

Der Beweislauf ist **nicht** Teil der CI-Suite — sein Dateiname trägt bewusst
kein `test_`-Präfix, `python3 -m unittest discover -s ./test -p "test_*.py"`
greift ihn also nicht auf. Grund: er braucht Docker, einen laufenden Analyzer
und ein geladenes LLM.

Die Eigenschaften, die sich ohne Infrastruktur prüfen lassen, sind zusätzlich
als schnelle Unit-Tests hinterlegt (u. a. stabile Zuordnung und
Platzhalter-Kollisionsfreiheit in `test/test_datenschleuse_guardrail.py`). Der
E2E-Lauf gehört vor jeden Release und nach jeder Änderung am Guardrail-Pfad.
