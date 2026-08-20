# Deutscher PII-Testkorpus & Benchmark

Ground-Truth-Korpus plus Benchmark-Runner, mit dem die PII-Erkennung der
Datenschleuse (Presidio-Standard-Recognizer + eigene deutsche Recognizer)
gegen einen festen Satz realistischer deutscher Texte gemessen wird.

## Dateien

| Datei | Zweck |
|-------|-------|
| `de-pii-testkorpus.yaml` | Ground-Truth-Korpus: pro Case ein Text + die exakt erwarteten PII-Teilstrings. |
| `../../presidio/de-stopwords.yml` | Nicht-PII-Wortliste: gemessene deutsche Alltagswörter, die das NER fälschlich meldet. Wird per `--stopwords` als Presidio-`allow_list` mitgeschickt. |
| `../corpus-benchmark.py` | Benchmark-Runner: schickt den Korpus an Presidio, rechnet Recall/Precision. |
| `benchmark-results.json` | Wird bei jedem Lauf (über)schrieben — strukturiertes Ergebnis mit UTC-Timestamp. |

## Zweck

Erkennungsqualität ist bei einem PII-Anonymisierungs-Proxy die zentrale
Kennzahl. Dieser Korpus macht sie **messbar und vergleichbar über die Zeit**:
Jede Recognizer-Änderung lässt sich unmittelbar gegen einen festen Satz von
Fällen prüfen (siehe Projekt-`CLAUDE.md`: „Bei jeder Recognizer-Änderung gegen
Testfälle prüfen“). Der JSON-Report mit Timestamp erlaubt es, Fortschritt (oder
Regressionen) zwischen Läufen zu belegen.

## Korpus-Format

Jeder `case` hat:

- `id` — eindeutiger Bezeichner.
- `text` — der zu prüfende Text (YAML-Folded-Scalar `>-`, wird zu einer Zeile).
- `entities` — Liste der erwarteten PII. Jede Entität:
  - `type` — Presidio-Entity-Typ (`PERSON`, `EMAIL_ADDRESS`, `DE_STEUER_ID`, …).
  - `value` — **exakter Teilstring** aus `text` (kein Regex, keine Offsets). Der
    Runner sucht die Position selbst per `text.find(value)`.
  - `expected_recall` — `must_detect` (muss erkannt werden) oder `known_gap`
    (bekannte, akzeptierte Erkennungslücke, z.B. Quasi-Identifier).
- Ist `entities` eine **leere Liste** (`entities: []`), ist es ein **Negativ-Fall**
  (False-Positive-Köder): Der Text sieht stellenweise nach PII aus, enthält aber
  keine. Jede Presidio-Detektion hier ist ein False Positive.

## Was der Benchmark misst

- **Recall** = TP / (TP + FN) — Anteil der erwarteten Entitäten, die erkannt wurden.
- **Precision** = TP / (TP + FP) — Anteil der Detektionen, der korrekt war.

Getrennt ausgewiesen:

1. **`must_detect` gesamt** und **pro Entity-Typ** (Haupt-Kennzahl).
2. **`known_gap` separat** — wird gemessen und reportet, aber **nicht** in die
   Haupt-Recall-Zahl eingerechnet. So bleibt sichtbar, wann eine bekannte Lücke
   irgendwann doch erkannt wird, ohne den Haupt-Score zu verzerren.
3. **False Positives aus den Negativ-Fällen** — die saubere, definierte
   Precision-FP-Quelle.

### Matching-Logik

Eine erwartete Entität gilt als erkannt (True Positive), wenn Presidio eine
Entität mit **gleichem `entity_type`** und **deutlichem Span-Overlap** liefert
(Standard: der Schnitt deckt ≥ 50 % des kürzeren der beiden Spans ab — nicht
zwingend exakt gleicher Start/End). Matching ist 1:1 und greedy nach höchstem
Overlap.

### Bewusste Precision-Entscheidung (ehrlich dokumentiert)

Der Korpus annotiert pro Positiv-Fall nur die **fokussierten** Entitäten, nicht
jede PII im Text (z.B. nennt `location-002` nur die Orte, obwohl „Frau Vogt“
auch eine Person ist). Würde jede nicht-gematchte Presidio-Detektion in
Positiv-Fällen als False Positive zählen, ergäbe das eine **irreführend
niedrige** Precision — echte, nur nicht-annotierte PII würde bestraft. Deshalb
speist sich die Precision-FP-Menge **ausschließlich aus den Negativ-Fällen**.
Zusätzliche Detektionen in Positiv-Fällen werden trotzdem erfasst und im Report
unter `positive_case_unmatched_detections` gelistet (nichts wird verschluckt) —
sie fließen aber bewusst nicht in die Precision-Kennzahl ein.

## Zielwerte

Verbindlich ist `docs/foundation/erkennungsziel.md` (Grundbuch, Gesetz 12).
Kurzfassung des dort begründeten Ziels:

| Kennzahl | Ziel |
|----------|------|
| **Recall** (`must_detect`, gesamt) | **≥ 95 %** |
| **Recall** je Entity-Typ mit Support ≥ 3 | **≥ 90 %** |
| **Störquote** (PII-freie Texte mit ≥ 1 Fehlalarm) | **≤ 10 %** |
| **Precision** (aus Negativ-Fällen) | **≥ 90 %** |

`known_gap`-Fälle zählen **nicht** gegen diese Ziele — sie sind der
dokumentierte Backlog für zukünftige Recognizer.

### Störquote — warum zusätzlich zur Precision

`TP/(TP+FP)` mischt zwei Töpfe: die TP stammen aus Positiv-Fällen, die FP aus
Negativ-Fällen. Die Precision lässt sich deshalb verbessern, indem man dem
Korpus Positiv-Fälle hinzufügt — ohne dass ein einziger Fehlalarm verschwindet.
Die Störquote ist dagegen immun und beantwortet die Frage, die für die
Nutzbarkeit zählt: *In wie vielen PII-freien Texten stört die Erkennung?*

### Warum der Negativ-Teil zweigeteilt ist

`negativ-001..006` zielen auf die **Regex**-Recognizer (IBAN-, Telefon-, KFZ-,
Aktenzeichen-, Firmen-Muster). `negativ-007..032` zielen auf die
**statistische** Seite — das spaCy-NER, das PERSON/LOCATION/ORGANIZATION
liefert. Die zweite Gruppe fehlte ursprünglich vollständig; deshalb meldete der
Benchmark 100 % Precision, während DATENSCHLE-70 und -71 in Produktion sichtbar
falsch lagen. Jeder Fall der zweiten Gruppe ist ein **gemessener** Treffer des
laufenden Analyzers, kein vermuteter.

### Warum `regex_flags` mitgeschickt werden

Ohne den Parameter defaultet der Analyzer auf `DOTALL|MULTILINE|IGNORECASE`.
Unter `MULTILINE` sind `^`/`$` Zeilen-Anker statt Vollspan-Anker — ein Span wie
`"Zahlungsart\nLoewenstein"` würde dann komplett unterdrückt, samt echtem
Nachnamen. Der Benchmark sendet die Flags deshalb explizit aus
`de-stopwords.yml` und verweigert den Lauf, wenn sie dort fehlen.

### Positiv-Kontrollen als Anti-Kriterium

`person-004..014` enthalten echte Nachnamen in ASCII-Umschrift (`Mueller`,
`Schroeder`, `Weiss`, `Kraemer`, `Baecker`) — also genau die Schreibweise, die
in den Negativ-Fällen Fehlalarme auslöst. `person-012..014` kamen aus dem
Security-Audit dazu: zweizeilige Label-Wert-Paare und „Nachname, Vorname", an
denen die erste Fassung der Stoppwortliste echte Namen verloren hat. Sie sind die Gegenprobe: Jede
Maßnahme gegen ASCII-Fehlalarme MUSS diese Namen weiterhin erkennen. Fällt hier
einer aus, ist die Maßnahme falsch — unabhängig davon, wie gut die
Precision-Zahl danach aussieht.

## Aufruf

Voraussetzung: Der Presidio-Analyzer läuft (via `docker-compose.yml`) und ist
erreichbar. Standard-URL: `http://localhost:5001`.

```bash
# 1. Analyzer starten (falls noch nicht aktiv)
docker compose up presidio-analyzer

# 2. Abhängigkeiten installieren (einmalig)
pip install -r test/requirements.txt

# 3. Benchmark laufen lassen — Rohzustand des Analyzers
python3 test/corpus-benchmark.py

# 4. ... und mit der Nicht-PII-Wortliste: der ERREICHBARE Zustand.
#    Nicht der ausgelieferte — der Guardrail sendet die Liste noch nicht.
python3 test/corpus-benchmark.py --stopwords presidio/de-stopwords.yml
```

> **Welche Zahl beschreibt den heutigen Betrieb?** Die aus Lauf 3 (ohne Liste):
> Störquote **81,2 %**. Der Lauf mit Liste (37,5 %) beschreibt den Zustand
> **nach** der in `docs/foundation/erkennungsziel.md` §7 spezifizierten
> Guardrail-Änderung, die noch nicht umgesetzt ist. Wer die 37,5 % als
> Betriebszustand liest, liest sie falsch.

**Pflicht bei jeder Recognizer- oder Listen-Änderung:** beide Läufe vorher und
nachher, beide Seiten vergleichen. Eine Precision-Verbesserung ohne
Recall-Nachweis ist keine Verbesserung, sondern eine unbelegte Behauptung.

Der Runner druckt einen Report auf stdout und schreibt zusätzlich
`test/corpus/benchmark-results.json`.

### Optionen

| Flag / Env | Default | Wirkung |
|------------|---------|---------|
| `--url` / `PRESIDIO_ANALYZER_URL` | `http://localhost:5001` | Basis-URL des Analyzers. |
| `--corpus` | `test/corpus/de-pii-testkorpus.yaml` | Alternativer Korpus-Pfad. |
| `--output` | `test/corpus/benchmark-results.json` | Alternativer Report-Pfad. |
| `--timeout` / `PRESIDIO_TIMEOUT_SECONDS` | `30` | Netzwerk-Timeout pro Request (s). |
| `--overlap-ratio` / `OVERLAP_MIN_RATIO` | `0.5` | Mindest-Overlap-Anteil für einen Treffer. |
| `--stopwords` | _(aus)_ | Pfad zu `presidio/de-stopwords.yml`. Deren Muster werden als Presidio-`allow_list` mitgeschickt, zusammen mit dem `regex_flags`-Wert aus derselben Datei. Misst den **erreichbaren** Zustand — der Guardrail sendet die Liste noch nicht (§7). |
| `--no-stopwords` | _(Default)_ | Explizit ohne Liste messen; markiert den Vorher-Lauf in Skripten sichtbar. |

## Exit-Codes

- `0` — Benchmark sauber durchgelaufen (**unabhängig** vom Score-Ergebnis).
- `2` — technischer Fehler (Presidio nicht erreichbar, YAML kaputt, unerwartetes
  Response-Format, Korpus-Inkonsistenz) mit klarer Meldung auf stderr.

Der Exit-Code bewertet also den **Lauf**, nicht die Erkennungsqualität — CI kann
den Score separat aus `benchmark-results.json` gegen die Zielwerte prüfen.
