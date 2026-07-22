# Deutscher PII-Testkorpus & Benchmark

Ground-Truth-Korpus plus Benchmark-Runner, mit dem die PII-Erkennung der
Datenschleuse (Presidio-Standard-Recognizer + eigene deutsche Recognizer)
gegen einen festen Satz realistischer deutscher Texte gemessen wird.

## Dateien

| Datei | Zweck |
|-------|-------|
| `de-pii-testkorpus.yaml` | Ground-Truth-Korpus: pro Case ein Text + die exakt erwarteten PII-Teilstrings. |
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

Für privacy-kritische Erkennung ist ein False Negative (übersehene PII, die
ungeschützt ans LLM geht) **teurer** als ein False Positive (harmloser Text wird
unnötig maskiert). Der Zielwert gewichtet Recall daher höher:

| Kennzahl | Ziel | Begründung |
|----------|------|------------|
| **Recall** (`must_detect`, gesamt) | **≥ 95 %** | Übersehene PII ist der teure Fehler — DSGVO-Risiko. |
| **Precision** (aus Negativ-Fällen) | **≥ 90 %** | False Positives sind tolerierbar, aber Überschutz schadet der Nutzbarkeit. |

`known_gap`-Fälle zählen **nicht** gegen diese Ziele — sie sind der dokumentierte
Backlog für zukünftige Recognizer.

## Aufruf

Voraussetzung: Der Presidio-Analyzer läuft (via `docker-compose.yml`) und ist
erreichbar. Standard-URL: `http://localhost:5001`.

```bash
# 1. Analyzer starten (falls noch nicht aktiv)
docker compose up presidio-analyzer

# 2. Abhängigkeiten installieren (einmalig)
pip install -r test/requirements.txt

# 3. Benchmark laufen lassen
python3 test/corpus-benchmark.py
```

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

## Exit-Codes

- `0` — Benchmark sauber durchgelaufen (**unabhängig** vom Score-Ergebnis).
- `2` — technischer Fehler (Presidio nicht erreichbar, YAML kaputt, unerwartetes
  Response-Format, Korpus-Inkonsistenz) mit klarer Meldung auf stderr.

Der Exit-Code bewertet also den **Lauf**, nicht die Erkennungsqualität — CI kann
den Score separat aus `benchmark-results.json` gegen die Zielwerte prüfen.
