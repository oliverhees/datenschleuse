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

## Stabilität ist Teil des Beweises

Ein Gate, das grundlos rot wird, ist als Gate wertlos — und ein Beweis, der bei
Wiederholung ein anderes Ergebnis liefert, ist keiner. Der Lauf wird deshalb
nicht einmal, sondern **in Serie** verifiziert:

| Lauf | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| Exit-Code | 0 | 0 | 0 | 0 | 0 |
| Prüfungen | 51 | 51 | 51 | 51 | 51 |
| Fehlschläge | 0 | 0 | 0 | 0 | 0 |

Dass diese Serie nötig war, ist selbst ein Befund: eine frühere Fassung war
einmal grün und beim nächsten Lauf rot. Wer den Beweis ändert, wiederholt die
Serie.

### Die Vorbedingung, die Flakes in Diagnosen verwandelt

`PII_MASKED_RE` prüft vor jeder inhaltlichen Bewertung: sind **genau** die vier
PII-Felder maskiert, und ist der Anweisungssatz **unberührt** geblieben?

Der Grund ist eine Lektion aus dem Fehlschlag. Maskiert Presidio versehentlich
ein Wort der Anweisung mit, bekommt das Modell einen zerstörten Satz und
verweigert womöglich die Antwort. Der Lauf fällt dann drei Schritte später mit
„LLM hat keine Platzhalter zurückgegeben" um — einer Meldung, die auf die
falsche Fährte führt und wie ein sporadischer Fehler des Round-Trips aussieht,
obwohl der Round-Trip nie an die Reihe kam. Die Vorbedingung nennt stattdessen
sofort die wahre Ursache.

## Befunde aus dem Beweislauf

### 1. Behoben: der Hinweistext hielt dem Modell etwas zum Nachbauen hin

Zwei Runden, und die zweite war lehrreicher als die erste.

**Runde 1 — Kollision.** Der Anonymisierungs-Hinweis nannte `<PERSON_1>`,
`<ADDRESS_0>` usw. als Beispiele — also exakt die Form `<TYP_ZAHL>`, die der
`Masker` auch für **echte** Werte vergibt. Im Beweislauf war `<PERSON_1>`
gleichzeitig Beispiel im Hinweis **und** echter Platzhalter für „Thomas
Schneider". Greift das Modell das Beispiel auf, macht die Re-Identifikation
stillschweigend den echten Namen daraus.

**Runde 2 — die Schablone war schlimmer.** Der erste Fix stellte die Beispiele
auf `<PERSON_N>` um, mit dem Zusatz „wobei N für eine Ziffer steht".
Kollisionsfrei — und gemessen gegen llama3.1:8b brandgefährlich: das Modell
setzte die Ziffer **pflichtbewusst ein** und gab `<PERSON_1>` zurück, wo
`<PERSON_0>` stand. In 3 von 3 Läufen, bei `temperature 0`. Damit war jeder
Platzhalter der Antwort unbrauchbar. Aus einem seltenen Kollisionsrisiko war
ein systematischer Totalausfall geworden.

**Die allgemeine Lehre:** Was der Hinweis dem Modell hinhält, baut das Modell
nach — ob Beispielname („Hans Müller", Live-Befund 2026-07-29), echter
Beispiel-Platzhalter (`<PERSON_1>`) oder Schablone (`<PERSON_N>`). Der Hinweis
enthält deshalb **gar keinen Token in spitzen Klammern** mehr. Er beschreibt
das Prinzip in Worten und schützt die Nummer ausdrücklich („mit unveränderter
Nummer … nicht umnummerieren"). Gemessen: 3 von 3 Läufen indextreu.
Abgesichert durch zwei Tests in `TestNoticePlaceholderCollision`.

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
korrektem Umlaut verschwindet der Treffer. Plausibel: solche Tokens sind
out-of-vocabulary, und das Modell rät PERSON. Relevant, weil ASCII-Umschrift in
Formularen, CLIs und Altsystemen verbreitet ist.

**Einordnung:** Overmasking, kein Leck. Gehört zur Präzisionsarbeit an der
deutschen Erkennung, nicht in den Round-Trip.

**Aber:** dieser Befund hat den Beweis selbst instabil gemacht — `Aendere` im
eigenen Testprompt wurde maskiert und zerstörte die Anfrage. Ein Befund, der
die eigene Messmethode betrifft, ist nie „außerhalb des Scopes". Deshalb ist
der Prompt korrigiert **und** durch `PII_MASKED_RE` dauerhaft abgesichert.

### 3. Offen: das Modell hält sich nicht zuverlässig an Platzhalter

Der Round-Trip setzt voraus, dass das Modell Platzhalter **byte-genau**
zurückgibt. Gemessen gegen llama3.1:8b ist das keine Selbstverständlichkeit:

- **Umnummerierung.** Bei einer Schablone im Hinweis schrieb das Modell
  systematisch `<PERSON_1>` statt `<PERSON_0>` (siehe Befund 1). Behoben, aber
  das Muster bleibt modellabhängig.
- **Verweigerung.** Als Bitte um „Name / IBAN / Telefon" formuliert, antwortete
  das Modell „Ich kann keine Informationen zu bestimmten Personen oder ihren
  Konten bereitstellen" — obwohl es ausschließlich Platzhalter sah. Es liest
  die **Labels**. Bei `temperature 0` mal so, mal so.

Beides ist keine Eigenschaft der Datenschleuse, sondern des Zielmodells. Für
den Beweis ist der Prompt deshalb als technischer Formatierungstest gerahmt und
gegen das Modell vermessen. Für das **Produkt** ist es die konkrete Messung zu
einem längst notierten Risiko (`docs/HEADROOM.md`): verändert ein Modell einen
Platzhalter, schlägt die Re-Identifikation **still** fehl — der Nutzer sieht
einen stehengebliebenen Platzhalter oder, im schlimmsten Fall, den falschen
Namen. Kleine Modelle brauchen hier mehr Aufmerksamkeit als große.

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
