# Erkennungsziel — Recall und Precision der deutschen PII-Erkennung

> Entwurf zur Entscheidung durch Oliver (DATENSCHLE-5, V1-Gate).
> Bindend, sobald freigegeben. Änderungen sind eigene Work Items mit ADR
> (Gesetz 12).

Die Erkennungsrate für deutsche PII ist die Kernfunktion der Datenschleuse.
Für „das beste PII-Werkzeug im deutschsprachigen Raum" ist eine **gemessene**
Erkennungsrate das Argument — alles andere ist Behauptung. Dieses Dokument
legt fest, welche Zahl wir anstreben, und begründet sie.

---

## 1. Ausgangslage — was tatsächlich gemessen wurde

Alle Zahlen stammen aus `test/corpus-benchmark.py` gegen den laufenden
Analyzer (`de_core_news_lg`, Presidio-Analyzer auf Port 5001), Korpus
`test/corpus/de-pii-testkorpus.yaml`. Keine Schätzung, keine Hochrechnung.

### 1.1 Der Ausgangsbefund: ein Benchmark, der sich selbst bestätigt hat

Vor dieser Arbeit meldete der Benchmark **100 % Recall und 100 % Precision** —
während zwei Präzisionsdefekte in Produktion sichtbar falsch lagen
(DATENSCHLE-70, DATENSCHLE-71).

Der Grund war nicht, dass Precision gar nicht gemessen wurde. Sie wurde
gemessen — aber gegen nur sechs Negativ-Fälle, und alle sechs zielten auf die
**Regex**-Recognizer (IBAN-, Telefon-, KFZ-, Aktenzeichen-, Firmen-Muster).
Die **statistische** Seite — das spaCy-NER-Modell, das PERSON, LOCATION und
ORGANIZATION liefert — war vollständig unbeprobt.

Das ist der eigentliche Befund: Der Korpus prüfte die Fehlerklassen, die seine
Autoren kannten. Eine Kennzahl, die nur misst, woran gedacht wurde, ist keine
Qualitätssicherung, sondern eine Selbstbestätigung. **Merksatz für jede weitere
Kennzahl im Projekt: Eine Metrik ohne Gegenprobe misst die Vorstellungskraft
ihres Autors, nicht das System.**

### 1.2 Messung nach Erweiterung des Korpus

Korpus erweitert auf 82 Cases: 26 gemessene Negativ-Fälle (ASCII-Umschrift,
deutsche Schema-Schlüssel, Fachbegriffe) plus 8 Positiv-Kontrollen mit echten
Nachnamen in ASCII-Umschrift, dazu drei Positiv-Kontrollen aus dem
Security-Audit (zweizeiliges Label-Wert-Paar, „Nachname, Vorname").

| Kennzahl | vorher (45 Cases) | erweitert (82 Cases) | mit Stoppwortliste |
|---|---|---|---|
| Recall (`must_detect`) | 100,0 % (43/43) | 100,0 % (54/54) | **100,0 % (54/54)** |
| Precision | 100,0 % | 66,2 % | **81,8 %** |
| False Positives | 0 | 26 | **12** |
| Störquote | (nicht erhoben) | 81,2 % (26/32) | **37,5 % (12/32)** |

Die mittlere Spalte ist die ehrliche Ausgangslage: **vier von fünf PII-freien
Texten wurden gestört.**

> **Revision nach Security-Audit.** Eine frühere Fassung dieses Dokuments wies
> hier 96,2 % Precision und 6,2 % Störquote aus. Diese Zahlen waren unbrauchbar:
> Sie wurden durch Stoppwort-Einträge erzeugt, die auch **echte Namen**
> unterdrückten — vier von acht Recall-Kontrollnamen gingen im Klartext durch
> (Details in [ADR-0002](../adr/0002-nicht-pii-wortliste.md)). Der Rückbau auf
> das sicher Belegbare kostet 15 Prozentpunkte Precision. Die schlechtere Zahl
> ist die richtige.

### 1.3 Warum zusätzlich die Störquote

Die klassische Precision `TP/(TP+FP)` mischt zwei Töpfe: die True Positives
stammen aus Positiv-Fällen, die False Positives aus Negativ-Fällen. Sie lässt
sich dadurch verbessern, indem man dem Korpus Positiv-Fälle hinzufügt — ohne
dass ein einziger Fehlalarm verschwindet.

Die **Störquote** — Anteil der PII-freien Texte mit mindestens einem Fehlalarm —
ist gegen diesen Effekt immun und beantwortet die Frage, die für die Nutzbarkeit
zählt: *Wie oft zerschießt die Datenschleuse einen Text, in dem gar nichts zu
finden ist?* Sie ist damit die Kennzahl, die ein Anwender tatsächlich erlebt,
und wird gleichrangig zur Precision geführt.

---

## 2. Der Zielkonflikt — warum „einfach beides auf 99 %" keine Option ist

Recall und Precision stehen bei einem Anonymisierungs-Proxy in direktem
Widerspruch, und beide Fehler kosten etwas Verschiedenes:

| | Fehler | Wirkung | Wer merkt es? |
|---|---|---|---|
| **False Negative** | übersehene PII | Klardaten gehen ungeschützt ans LLM | niemand — bis zum Vorfall |
| **False Positive** | harmloser Text maskiert | Prompt wird unbrauchbar oder Tool-Call bricht | der Anwender, sofort |

Der naive Schluss lautet: Recall maximieren, False Positives hinnehmen. Der
Schluss ist falsch, und zwar aus zwei Gründen.

**Erstens** kippt Überschutz in Unterschutz. Ein Werkzeug, das jeden vierten
Satz zerschießt, wird abgeschaltet oder umgangen — und ein umgangenes Werkzeug
hat einen effektiven Recall von null. Precision ist bei einem freiwillig
eingesetzten Proxy keine Bequemlichkeit, sondern die Bedingung dafür, dass der
Recall überhaupt wirksam wird.

**Zweitens** — und das ist der Befund aus DATENSCHLE-71 — sind nicht alle False
Positives gleich harmlos. Weil der Guardrail auch JSON-Schlüssel maskiert, wird
aus `args["bestellnummer"]` ein `args["<LOCATION_0>"]`. Der Tool-Call geht
**durch** und ist beim Empfänger unbrauchbar: kein Fehler, kein Log, keine
Ausnahme. Diese FP-Klasse zerstört Funktionalität stillschweigend und ist damit
so teuer wie ein False Negative — nur an anderer Stelle.

Deshalb braucht das Ziel zwei Zahlen, nicht eine.

---

## 3. Vorgeschlagenes Ziel

| Kennzahl | Ziel | Gate |
|---|---|---|
| **Recall** (`must_detect`, gesamt) | **≥ 95 %** | V1 blockierend |
| **Recall** je musterbasiertem Typ (Support ≥ 3) | **≥ 98 %** | V1 blockierend |
| **Recall** PERSON / LOCATION / ORGANIZATION | **≥ 90 / 85 / 75 %** | V1 blockierend |
| **Störquote** (PII-freie Texte mit ≥ 1 Fehlalarm) | **≤ 10 %** | V1 blockierend |
| **Precision** (aus Negativ-Fällen) | **≥ 90 %** | V1 blockierend |
| Recall bei `known_gap` | keine Vorgabe | nur berichtet |

**Aktueller Stand gegen dieses Ziel:** Recall 100 %, Precision 81,8 %,
Störquote 37,5 % — **zwei Gates verfehlt** (Precision, Störquote).

Das ist beabsichtigt so ausgewiesen. Die Verfehlung hat genau eine Ursache:
DATENSCHLE-70 (ASCII-umschriebene Wörter) ist über den `allow_list`-Mechanismus
nicht lösbar, weil dieser nur den Span-Text sieht und Fehlalarm wie echter Name
denselben Span erzeugen. Solange der kontextsensitive Recognizer fehlt, bleibt
das Gate rot. Ein Absenken des Ziels wäre die Reaktion, vor der Abschnitt 3
ausdrücklich warnt.

### Begründung der einzelnen Werte

**Recall ≥ 95 % statt 100 %.** Ein 100-%-Ziel wäre unehrlich. Die Erkennung
beruht auf einem statistischen Sprachmodell; sie ist grundsätzlich nicht
vollständig, und das steht bereits als Projektregel in `CLAUDE.md`
(„Erkennungsrate ist nie 100 %"). Ein unerreichbares Ziel erzeugt entweder
Dauer-Rot oder — schlimmer — die Versuchung, den Korpus so zu schneiden, dass
er grün wird. Genau dieser Mechanismus hat den Benchmark bis heute bei
100 % gehalten.

**Recall zusätzlich pro Entity-Typ.** Ein Gesamt-Recall von 95 % kann einen
Typ mit 0 % Recall verdecken, wenn er selten annotiert ist. Genau das ist im
Projekt schon einmal passiert: `IP_ADDRESS` stand bei 0 % Recall, weil der
`IpRecognizer` gar nicht geladen war — die Registry ERSETZT die Presidio-
Defaults, statt sie zu ergänzen (dokumentiert in
`presidio/recognizers-config.yml`). Der Gesamtwert hätte das weiter verdeckt.
Die Schwelle greift erst ab Support ≥ 3, weil eine Quote über ein oder zwei
Fälle keine Aussage trägt.

Die Per-Typ-Ziele sind nach Erkennungsmechanismus gestaffelt und nicht pauschal
— hergeleitet aus den Eigenangaben des Modells in Abschnitt 5. Ein flaches
„90 % pro Typ" würde von ORGANIZATION mehr verlangen, als `de_core_news_lg` auf
eigenem Terrain liefert (76,3 %); ein solches Gate wird nicht erfüllt, sondern
umgangen.

**Störquote ≤ 10 %.** Die Zahl ist eine Produktentscheidung, keine abgeleitete
Größe: Höchstens jeder zehnte PII-freie Text darf gestört werden. Sie ist
bewusst als Obergrenze für einen *spürbaren* Effekt gewählt — bei 81 %
(Ausgangslage) ist das Werkzeug unbenutzbar, bei 10 % ist es ein bekanntes,
erklärbares Ärgernis.

**Precision ≥ 90 %.** Wird gleichrangig weitergeführt, weil sie die Schwere
misst (wie viele Fehlalarme insgesamt), während die Störquote die Häufigkeit
misst (in wie vielen Texten). Ein einzelner Text mit fünf Fehlalarmen und fünf
Texte mit je einem sind für den Anwender nicht dasselbe.

### Was das Ziel ausdrücklich NICHT behauptet

Ein erfülltes Gate ist eine Aussage über **diesen Korpus**, nicht über die
Welt. 79 handverlesene Fälle sind eine Regressionssicherung, keine
repräsentative Stichprobe deutscher Geschäftskommunikation. Die Zahl darf in
der Außenkommunikation nur mit dieser Einschränkung genannt werden — sonst
wiederholen wir nach außen genau den Fehler, den der alte Benchmark nach
innen gemacht hat.

Ebenso unberührt: Pseudonymisierung nimmt Daten **nicht** aus dem
DSGVO-Scope. Ein hoher Recall ist eine technische Maßnahme im Sinne von
Art. 25 DSGVO, kein Freibrief.

---

## 4. Umgesetzte Verbesserung (DATENSCHLE-70 / -71)

### 4.1 Gewähltes Instrument und die verworfenen Alternativen

Zur Wahl standen Kontext-Bedingung, Stoppwortliste, Score-Schwelle und
Normalisierung. Entschieden wurde nach Messung, nicht nach Plausibilität:

| Instrument | Befund | Ergebnis |
|---|---|---|
| **Score-Schwelle** | Fehlalarme und echte Namen kommen beide mit exakt 0,85 aus dem spaCy-NER. Die Schwelle kann nicht zwischen ihnen unterscheiden. | verworfen |
| **Kontext-Bedingung** | Presidios `context`-Feld **erhöht** nur Scores, es unterdrückt nicht. Für diesen Zweck gibt es den Mechanismus nicht. | verworfen |
| **Normalisierung** (`Spaeter` → `Später`) | Beseitigt einen Teil der Fehlalarme, kostet aber denselben Recall: `"Herr Später"` wird danach **gar nicht** mehr erkannt. Repariert `Fasse` und `Uebersetze` überhaupt nicht. | verworfen |
| **Stoppwortliste** via `allow_list` | Presidios eigener Unterdrückungs-Mechanismus. Wirkt gezielt, messbar, ohne Recall-Verlust. | **gewählt** |

Die Liste liegt in `presidio/de-stopwords.yml`. Sie steht dort und nicht in
`recognizers-config.yml`, weil die Recognizer-Registry Entitäten nur
**hinzufügen** kann; einen Unterdrückungs-Mechanismus hat sie nicht.

### 4.2 Warum die Liste keinen Recall kostet

`allow_list` vergleicht gegen den **vollständigen** erkannten Span. Jedes Muster
ist mit `\A...\z` verankert und unterdrückt deshalb nur, wenn der ganze Span
exakt das Stoppwort ist.

**Warum `\A...\z` und nicht `^...$`:** Der Analyzer defaultet `regex_flags` auf
`DOTALL|MULTILINE|IGNORECASE`. Unter `MULTILINE` matchen `^`/`$` an jedem
Zeilenumbruch **innerhalb** des Spans — sie sind dann Zeilen-Anker, kein
Vollspan-Anker:

```
Span "Zahlungsart\nLoewenstein"
  mit ^zahlungsart$   : Treffer -> ganzer Span weg, Nachname verloren
  mit \Azahlungsart\z : kein Treffer -> PERSON 'Loewenstein' bleibt
```

Genau daran ist die erste Fassung gescheitert (Security-Finding F1). Zusätzlich
wird `regex_flags: 0` explizit gesendet, statt den Server-Default zu erben.

`test/test_de_stopwords.py` erzwingt beides maschinell und baut den Matcher
dafür exakt so nach, wie der Analyzer ihn konstruiert — gejoint mit `|`, geprüft
mit `search`, mit den tatsächlich gesendeten Flags. Der frühere Test prüfte pro
Muster mit `fullmatch` ohne Flags und konnte den Defekt deshalb nicht finden.

### 4.3 Bewusst nicht behoben — DATENSCHLE-70 vollständig

Zwölf gemessene Fehlalarme bleiben stehen. Sie sind über `allow_list`
**grundsätzlich nicht** behebbar, nicht nur „noch nicht":

Der Mechanismus vergleicht ausschließlich den Span-Text. Fehlalarm und echter
Name erzeugen aber denselben Span:

```
"Aendere keinen einzigen Wert."  -> PERSON 'Aendere'   (Fehlalarm)
"Herr Aendere ruft an."          -> PERSON 'Aendere'   (Name)
```

Für den Matcher sind beide identisch — jede Unterdrückung trifft beide. Das
betrifft alle ASCII- und Umlaut-Verbformen sowie `spaeter`, `fasse`, `fuege`,
`menge` und `rueckruf`. Bei `fuege` (Füge) und `menge` (Menge) ist die
Namenslesart nicht theoretisch, sondern ein realer deutscher Familienname; beide
standen in der ersten Fassung auf der Liste und haben dort messbar Namen
unterdrückt.

Da das Anti-Kriterium „kein Recall-Verlust" nicht verhandelbar ist, bleiben
diese Fälle offen. Der erforderliche Mechanismus wäre ein kontextsensitiver
Recognizer im Analyzer-Image, der Anrede- und Titel-Kontext (`Herr`, `Frau`,
`Dr.`) auswertet, bevor er unterdrückt. Eigenes Work Item — und der einzige
Weg, das Störquoten-Gate zu erreichen.

### 4.4 Spannung zur Security-Baseline — offen benannt

> Entschieden: von Oliver genehmigt, festgehalten in
> [ADR-0002](../adr/0002-nicht-pii-wortliste.md).

`docs/foundation/security-baseline.md` verbietet Denylists: „sie sind erst
vollständig, wenn jemand die Lücke findet." Die Stoppwortliste ist der Form
nach eine Denylist und bewegt sich in die riskante Richtung — sie **reduziert**
Schutz.

Das ist eine bewusste, begründete Ausnahme, keine Übersehung. Die Baseline-Regel
adressiert die Frage, *welche Eingaben überhaupt geprüft werden* — dort ist
fail-closed richtig, weil eine Lücke ungeprüfte Daten durchlässt. Hier geht es
um die Frage, *welche geprüften Treffer verworfen werden*. Eine Lücke in dieser
Liste bedeutet: ein Fehlalarm bleibt bestehen. Der Fehlermodus zeigt also nach
außen in Richtung Überschutz, nicht Unterschutz.

Kompensierende Kontrollen, alle testgeprüft:

1. **Messbeleg-Pflicht.** Kein Eintrag ohne `probe`-Text, der den Fehlalarm am
   laufenden Analyzer nachweislich erzeugt. Der Test prüft die Gegenprobe und
   schlägt fehl, wenn ein Eintrag seinen Anlass verloren hat.
2. **Verankerungs-Pflicht.** `^...$` maschinell erzwungen (siehe 4.2).
3. **Kollisionsprüfung.** Kein Muster darf einen der Kontroll-Namen
   vollständig matchen.
4. **Aufnahmekriterium.** Nur Terme ohne plausible Eigennamen-Lesart.
   Der einzige Grenzfall (`menge`) ist bewusst nur kleingeschrieben
   aufgenommen, weil Schema-Schlüssel klein und Nachnamen groß geschrieben
   sind.

Jede Erweiterung der Liste ist damit eine dokumentierte, gemessene und
gegengeprüfte Einzelentscheidung — nicht das stille Wachsen einer Denylist.

---

## 5. Vergleichsrahmen — was das Modell überhaupt leisten kann

Statt fremde Marketing-Zahlen zu zitieren, nehmen wir die Primärquelle: die
Metadaten des tatsächlich installierten Modells. Jeder kann sie nachlesen:

```bash
docker exec datenschleuse-analyzer python -c \
  "import de_core_news_lg; print(de_core_news_lg.load().meta['performance'])"
```

**`de_core_news_lg` 3.8.0, Eigenangabe des Modells** (trainiert auf TIGER-Korpus
und WikiNER — also Zeitungs- und Wikipedia-Text):

| Klasse | Precision | **Recall** | F |
|---|---|---|---|
| PER | 0,8912 | **0,9202** | 0,9054 |
| LOC | 0,8720 | **0,8794** | 0,8757 |
| ORG | 0,7881 | **0,7630** | 0,7754 |
| MISC | 0,8004 | 0,7260 | 0,7614 |
| **gesamt** | 0,8534 | **0,8453** | 0,8493 |

### Der unbequeme Befund

**Unser Korpus meldet 100 % PERSON-Recall. Das Modell selbst gibt für PER
92,02 % an — auf Text, für den es trainiert wurde.**

Ein Korpus, auf dem das Modell besser abschneidet als auf seiner eigenen
Evaluationsmenge, ist nicht besonders gut — er ist besonders leicht. Unsere 79
Fälle sind handverlesen, kurz und syntaktisch einfach; das Modell sieht dort
keinen der Fälle, an denen es real scheitert (verschachtelte Sätze, seltene
Namen, Namen ohne Anrede, fremdsprachige Namen, Namen in Aufzählungen).

Daraus folgt zweierlei:

1. Die 100 % sind **kein Qualitätsbeleg**, sondern eine Aussage über den
   Schwierigkeitsgrad des Korpus. Sie dürfen so nicht nach außen kommuniziert
   werden.
2. Der nächste sinnvolle Schritt ist nicht, die Erkennung zu verbessern,
   sondern den **Korpus zu härten**, bis er das Modell tatsächlich fordert.
   Erst dann misst der Recall etwas. Eigenes Work Item.

### Warum die Recall-Ziele nach Mechanismus gestaffelt sind

Aus derselben Tabelle folgt, dass ein pauschales Per-Typ-Ziel nicht
verteidigungsfähig wäre. Ein flaches „90 % pro Typ" verlangt von ORGANIZATION
mehr, als das Modell auf eigenem Terrain liefert (76,3 %) — ein solches Gate
wird nicht erfüllt, sondern umgangen. Deshalb:

| Typklasse | Ziel | Begründung |
|---|---|---|
| musterbasiert (Regex/Prüfsumme) | **≥ 98 %** | deterministisch. Ein Fehlschlag ist ein Muster- oder Konfigurationsfehler, kein Modellproblem — hier gibt es keine Ausrede. |
| PERSON | **≥ 90 %** | knapp unter der Modellangabe von 92,0 %. |
| LOCATION | **≥ 85 %** | knapp unter 87,9 %. |
| ORGANIZATION | **≥ 75 %** | an der Modellangabe von 76,3 %. Ehrlich niedrig statt unerreichbar hoch. |

Neue Entity-Typen fallen per Default in die strenge musterbasierte Klasse
(`target_for_type()`). Diese Richtung ist die sichere: ein neuer
Custom-Recognizer wird streng geprüft, bis jemand bewusst entscheidet, ihn
niedriger einzustufen.

### Kommerzielle Anbieter

Bewusst nicht zitiert. Für AWS Comprehend PII, Google Cloud DLP und Azure AI
Language liegt uns keine belegbare, nachprüfbare Recall-Angabe für **deutsche**
PII vor. Eine Zahl ohne Quelle wäre hier schlimmer als keine — genau die
Behauptungs-Kultur, gegen die dieses Dokument gerichtet ist.

---

## 6. Betrieb

**Messen:**

```bash
# Rohzustand des Analyzers
python3 test/corpus-benchmark.py

# Mit Stoppwortliste — der Zustand, der ausgeliefert wird
python3 test/corpus-benchmark.py --stopwords presidio/de-stopwords.yml
```

**Gate maschinell prüfen** (Exit-Code 1 bei Verfehlung):

```bash
python3 test/corpus-benchmark.py --stopwords presidio/de-stopwords.yml --check-targets
```

Die Schwellen dieses Dokuments stehen als Konstanten in
`test/corpus-benchmark.py` und werden von `test/test_erkennungsziel_gate.py`
gegen dieses Dokument abgeglichen. Ein Ziel, das nur im Fließtext steht, ist
kein Gate, sondern ein Wunsch — man senkt es beim nächsten roten Lauf
stillschweigend ab.

Ohne `--check-targets` bewertet der Exit-Code weiterhin nur den LAUF (0 = sauber
gelaufen, 2 = technischer Fehler); der bisherige Vertrag bleibt unverändert.

**Pflicht bei jeder Recognizer- oder Listen-Änderung:** beide Läufe vorher und
nachher, beide Seiten vergleichen. Eine Precision-Verbesserung ohne
Recall-Nachweis ist kein Ergebnis, sondern eine unbelegte Behauptung.

**Offen:** Der Guardrail sendet die `allow_list` noch nicht. Solange das nicht
umgesetzt ist, wirkt die Liste im Benchmark, aber nicht in Produktion. Die
Zahlen dieses Dokuments beschreiben insoweit den erreichbaren, nicht den
ausgelieferten Zustand.

---

## 7. Erforderliche Guardrail-Änderung (Spezifikation, nicht umgesetzt)

`litellm/datenschleuse_guardrail.py` lag außerhalb des Scopes dieses Work Items
(parallele Lanes). Die nötige Änderung ist klein und an genau einer Stelle:

**Ort:** `DatenschleuseGuardrail._analyze()` — die einzige Stelle, an der
`POST /analyze` aufgerufen wird.

**Änderung:** Die Muster aus `presidio/de-stopwords.yml` einmalig im
Konstruktor laden und in `_analyze` an das Payload hängen:

```python
if self.allow_list:                       # aus de-stopwords.yml, entries[].pattern
    payload["allow_list"] = self.allow_list
    payload["allow_list_match"] = "regex"
```

### Der kritische Punkt: Konsistenz mit dem Verifikationsdurchlauf

`_analyze` bedient **beide** Durchläufe — die Maskierung *und* den
Verifikationsdurchlauf, der das fertig maskierte Ergebnis erneut prüft und bei
Restbefund fail-closed blockiert.

Genau deshalb muss die `allow_list` **in `_analyze` selbst** gesetzt werden und
nicht an den einzelnen Aufrufstellen. Würde sie nur im Maskierungspfad wirken,
entstünde ein garantierter Selbstblock: Die Maskierung überspringt
`bestellnummer`, der Verifikationsdurchlauf findet es im maskierten Ergebnis
weiterhin als `LOCATION` — und blockt jeden Request, der einen der
Stoppwort-Terme enthält. Aus einem Precision-Fix würde eine Verfügbarkeits-
Störung.

Beide Durchläufe müssen dieselbe Erkennungskonfiguration sehen. Ein Test, der
das absichert, gehört zur Änderung.

### Fail-closed-Verhalten beim Laden

Ist `de-stopwords.yml` nicht lesbar oder strukturell fehlerhaft, darf der
Guardrail **nicht** still ohne Liste weiterlaufen — das wäre eine unbemerkte
Verhaltensänderung. Richtig ist ein Startfehler; im laufenden Betrieb existiert
die Datei entweder oder der Dienst startet gar nicht erst. Die Fehlerbehandlung
kann `test/corpus-benchmark.py::load_stopwords` übernehmen, die genau diese
Prüfungen bereits implementiert: Mapping vorhanden, `allow_list_match == regex`,
`regex_flags` vorhanden und ganzzahlig, `entries` nicht leer, jedes `pattern`
ein String — und das **gejointe** Muster kompiliert. Der letzte Punkt ist kein
Detail: einzeln kompilierbare Muster können gejoint scheitern.

### Abnahme

Nach der Umsetzung ist die Wirkung end-to-end zu belegen, nicht nur im
Analyzer:

1. Ein Tool-Call mit `args["bestellnummer"]` muss den Guardrail mit
   **unverändertem Schlüssel** verlassen, während ein Wert wie `Herr Mueller`
   im selben Aufruf weiterhin maskiert wird.
2. Ein zweizeiliges Label-Wert-Paar (`"Zahlungsart\nLoewenstein"`) muss den
   Nachnamen weiterhin maskieren. Das ist der Regressionsnachweis für F1.
3. `"Menge, Andreas"` muss beide Namen maskieren — Regressionsnachweis für F2.
