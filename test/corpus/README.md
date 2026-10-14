# Deutscher PII-Testkorpus & Benchmark

Ground-Truth-Korpus plus Benchmark-Runner, mit dem die PII-Erkennung der
Datenschleuse (Presidio-Standard-Recognizer + eigene deutsche Recognizer)
gegen einen festen Satz realistischer deutscher Texte gemessen wird.

## Dateien

| Datei | Zweck |
|-------|-------|
| `de-pii-testkorpus.yaml` | Ground-Truth-Korpus: pro Case ein Text + die exakt erwarteten PII-Teilstrings. |
| `../../presidio/de-stopwords.yml` | Nicht-PII-Wortliste: gemessene deutsche Alltagswörter, die das NER fälschlich meldet. Wird per `--stopwords` als Presidio-`allow_list` mitgeschickt. |
| `corpus-manifest.json` | No-Shrink-Anker: alle Case-ids samt Split. Erzeugt mit `python3 test/corpus-benchmark.py --write-manifest`. |
| `../test_corpus_v2.py` | Offline-Tests: Schema-/Annotationsregeln, Manifest-Vergleich in beide Richtungen, absolute Untergrenzen je Kategorie. |
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

### Korpus v2 (DATENSCHLE-94): Zusatzfelder und Regeln

Die ersten 84 Fälle (v1, ohne `category`) bleiben unverändert und unterliegen
nur dem Basis-Schema. Alle Fälle mit `category` und id-Präfix `v2-` sind v2 und
werden vom Loader streng validiert:

- `category` — Fehlerklasse (`nachname-wort`, `nachname-kopf`,
  `positiv-kontrolle`, `name-ohne-anrede`, `adresse-fliesstext`,
  `json-gemischt`, `quasi-identifier`, `titel-dateiname`, `kombi`,
  `person-fliesstext`, `ort-fliesstext`, `negativ-satzanfang`,
  `negativ-schema`, `negativ-fliesstext`).
- `split` — `dev` oder `holdout`. **Der Hold-out dient nie zum Abstimmen.**
  Tuning-Läufe (Wortliste, Recognizer) fahren mit `--split dev`; der Runner
  weist dev und Hold-out im Report immer getrennt aus (`splits`). Neue
  Hold-out-Fälle brauchen frisches Vokabular, keine Varianten bereits
  abgestimmter Wörter.
- `control: true` — Positiv-Kontrolle. Jede `must_detect`-Entität trägt dann
  `baseline_detected` (true/false): ob die Baseline (main bei der Härtung) sie
  gemessen erkannt hat. Abweichungen weist der Report unter `baseline_control`
  aus (Rückschritt bzw. Fortschritt) — nichts geht in der Gesamtzahl unter.

**Annotationsregeln A1–A6** stehen im Header von `de-pii-testkorpus.yaml` (dort
maßgeblich) und werden, soweit maschinenprüfbar, vom Loader erzwungen:

| Regel | Inhalt | Erzwungen |
|---|---|---|
| A1 | Span-Minimalität: kein Titel/Rolle/Label/Satzzeichen im Span, genau ein Vorkommen im Text, keine Überlappung | ja |
| A2 | v2-Positivfälle sind erschöpfend annotiert; Berufe/Rollen ohne Namen sind keine PII | Konvention |
| A3 | Satzinitiale Verben/Substantive, Schema-Schlüssel, Produktnamen sind nie PII (ASCII wie Umlaut) | Konvention |
| A4 | Alltagswort-Nachnamen sind PII nur bei Namens-Marker im Kontext; ohne Marker nicht raten | Konvention |
| A5 | Quasi-Identifier und Titel in Dateinamen-Form sind `known_gap`; enthaltene Eigennamen einzeln `must_detect` | teilweise |
| A6 | Nur Synthetisches; E-Mail nur auf reservierten Domains (`example.com/.org/.net/.de`) | ja (E-Mail) |

Warum nicht die nackte TLD `.example`: Presidios `EmailRecognizer` validiert die
TLD, `x@y.example` wird nie erkannt — der Fall würde den Validator messen, nicht
die Erkennung.

**No-Shrink:** `corpus-manifest.json` hält alle ids samt Split fest.
`test/test_corpus_v2.py` vergleicht Korpus und Manifest in beide Richtungen
(verschwundener Fall = rot, nicht registrierter neuer Fall = rot, Split-Wechsel =
rot) und prüft absolute Untergrenzen (≥ 150 neue Positiv-Fälle, ≥ 80
PII-freie Negativ-Texte, Hold-out ≥ 25 Positiv/≥ 30 Negativ, Kategorie-Minima).
Wer einen Fall bewusst entfernt, ändert das Manifest im selben Commit sichtbar.

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

### Aktueller Stand: Ziel nicht erreicht

Gemessen am 2026-10-14 über den gehärteten Korpus (325 Fälle: 84 v1 + 241 v2),
mit der Nicht-PII-Wortliste — das ist die **ausgelieferte Konfiguration**, die
der Guardrail seit DATENSCHLE-82 an jeden Presidio-Aufruf sendet
(`docs/foundation/erkennungsziel.md` §7). `test/guardrail-benchmark.py` liefert
durch den Guardrail-Pfad dieselben Zahlen. Belegt ist damit der Codepfad gegen
einen laufenden Analyzer (Presidio 2.2.362, `de_core_news_lg` 3.8.0, lokal ohne
Docker gestartet), kein Container-Start.

| Kennzahl | Rohzustand (ohne Liste) | mit Liste (ausgeliefert) | davon dev | davon Hold-out |
|---|---|---|---|---|
| Recall (`must_detect`) | 91,8 % (258/281) | 91,8 % (258/281) | 93,1 % (217/233) | 85,4 % (41/48) |
| Precision | 83,0 % | 89,3 % | 89,3 % | 89,1 % |
| Störquote | 42,1 % (48/114) | 26,3 % (30/114) | 29,8 % (25/84) | 16,7 % (5/30) |

Recall PERSON 87,0 % (120/138), ORGANIZATION 50,0 % (3/6); `known_gap` 3 von 24
erkannt. Recall, Precision und Störquote sind **rot**. Die 20
Positiv-Kontrollen weichen nicht von der Baseline ab (0 Abweichungen); alle
`nachname-kopf`-Wächter (`Erhart`, `Lienhart`, …) werden erkannt. Die größte
Recall-Lücke sind Nachnamen, die Alltagswörter sind (`Bauer`, `Koch`, `Menge`:
15 der 23 verfehlten Entitäten).

Zum Vergleich der alte Korpus (nur v1, 84 Fälle, am selben Tag gegen denselben
Stand reproduziert): Recall 100 % (54/54), Precision 81,8 %, Störquote 37,5 %
(12/32); ohne Liste Precision 67,5 %, Störquote 81,2 %. Der v1-Recall von 100 %
war kein Qualitätsbeleg (`de_core_news_lg` gibt 92,02 % für PERSON an) — der
Recall-Einbruch auf v2 ist das erwartete Ergebnis eines Korpus, der etwas
misst.

Die Zahlen sind eine Messung, kein Tuning-Ergebnis: Die Härtung ändert weder
Filter noch Recognizer noch Wortliste. Das eingecheckte `benchmark-results.json`
ist der Lauf **mit** Wortliste über alle 325 Fälle (`bestanden: false`). Es wird
ausschließlich durch einen echten Lauf ersetzt, nie von Hand editiert — eine
Handeintragung wäre keine Korrektur. Der Rohzustand (ohne Liste) hat kein
eingechecktes Artefakt; wer ihn belegen will, fährt Lauf 3 selbst.

Bei der Lektüre beachten: Die gepoolte Störquote verdünnt. Fließtext-Negative
stören kaum (1 von 22), satzinitiale Verben und Substantive weiterhin in 15 von
46 Fällen. `by_category` im Report weist das je Kategorie aus, und
`must_detect_misses` listet jede verfehlte Entität namentlich.

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

# 4. ... und mit der Nicht-PII-Wortliste: die ausgelieferte Konfiguration
#    (der Guardrail sendet dieselbe Liste an jeden /analyze-Aufruf).
python3 test/corpus-benchmark.py --stopwords presidio/de-stopwords.yml

# 5. Gegenprobe durch den Guardrail-Pfad selbst (gleiche Auswertung)
PYTHONPATH=litellm python3 test/guardrail-benchmark.py
```

> **Welche Zahl beschreibt den Betrieb?** Die aus Lauf 4 (mit Liste):
> Störquote **26,3 %**. Lauf 3 (42,1 %) ist der Rohzustand ohne Wortliste und
> zeigt, was die Liste bewirkt. Beide Zahlen belegen den Codepfad gegen einen
> laufenden Analyzer; ein echter Docker-Build/Container-Start ist damit nicht
> belegt.

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
| `--split` | `all` | `dev`, `holdout` oder `all`. Tuning-Läufe nutzen `dev`; der Hold-out wird nie zum Abstimmen verwendet. |
| `--write-manifest` | _(aus)_ | Schreibt `corpus-manifest.json` neben den Korpus und endet ohne Analyzer-Lauf. |
| `--stopwords` | _(aus)_ | Pfad zu `presidio/de-stopwords.yml`. Deren Muster werden als Presidio-`allow_list` mitgeschickt, zusammen mit dem `regex_flags`-Wert aus derselben Datei. Misst die ausgelieferte Konfiguration — der Guardrail sendet dieselbe Liste (§7). |
| `--no-stopwords` | _(Default)_ | Explizit ohne Liste messen; markiert den Vorher-Lauf in Skripten sichtbar. |

## Exit-Codes

- `0` — Benchmark sauber durchgelaufen (**unabhängig** vom Score-Ergebnis).
- `2` — technischer Fehler (Presidio nicht erreichbar, YAML kaputt, unerwartetes
  Response-Format, Korpus-Inkonsistenz) mit klarer Meldung auf stderr.

Der Exit-Code bewertet also den **Lauf**, nicht die Erkennungsqualität — CI kann
den Score separat aus `benchmark-results.json` gegen die Zielwerte prüfen.
