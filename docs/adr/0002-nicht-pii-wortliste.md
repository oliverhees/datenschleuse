# ADR-0002: Nicht-PII-Wortliste zur Unterdrückung von NER-Fehlalarmen

- Status: akzeptiert
- Datum: 2026-08-20
- Work Item: [DATENSCHLE-5] (Defekte: DATENSCHLE-70, DATENSCHLE-71)

## Kontext

Das statistische Sprachmodell `de_core_news_lg` meldet deutsche Alltagswörter
als Eigennamen. Zwei Klassen wurden gemessen:

- **ASCII-Umschrift** (DATENSCHLE-70): `"Aendere keinen einzigen Wert."`
  → `PERSON 'Aendere' @0.85`. ASCII-Umschrift ist in Formularen, CLIs,
  Altsystemen und Exportdateien verbreitet — genau in den Datenbeständen, die
  durch die Datenschleuse laufen.
- **Deutsche Schema-Schlüssel** (DATENSCHLE-71): `"bestellnummer"`
  → `LOCATION @0.85`. Weil der Guardrail auch JSON-Schlüssel maskiert, wird aus
  `args["bestellnummer"]` ein `args["<LOCATION_0>"]`. Der Tool-Call geht
  **durch** und ist beim Empfänger unbrauchbar: kein Fehler, kein Log.

Gemessen am laufenden Analyzer über 79 Korpus-Fälle:
**26 False Positives, Störquote 81,2 %** — vier von fünf PII-freien Texten
wurden gestört. Ein Werkzeug in diesem Zustand wird abgeschaltet oder umgangen,
und ein umgangenes Werkzeug hat einen effektiven Recall von null.

Der Defekt war unsichtbar, weil der Benchmark-Korpus auf der Negativ-Seite nur
die **Regex**-Recognizer beprobte (IBAN, Telefon, KFZ, Aktenzeichen, Firma).
Die **statistische** Seite war unbeprobt — deshalb meldete er 100 % Precision,
während beide Defekte in Produktion sichtbar falsch lagen.

**Rahmenbedingung (Anti-Kriterium, nicht verhandelbar):** Keine Maßnahme darf
den Recall verschlechtern. Echte Nachnamen in ASCII-Umschrift (`Mueller`,
`Schroeder`, `Weiss`) müssen weiterhin erkannt werden.

## Entscheidung

Gemessene Nicht-PII-Wörter werden in `presidio/de-stopwords.yml` gepflegt und
über Presidios eigenen `allow_list`-Mechanismus (`allow_list_match: regex`) an
`/analyze` übergeben. **Jedes Muster ist mit `^...$` verankert.**

## Die Kollision mit der Security-Baseline — und warum die Ausnahme trägt

`docs/foundation/security-baseline.md` verbietet Denylists: „sie sind erst
vollständig, wenn jemand die Lücke findet." Diese Liste ist der Form nach eine
Denylist. Die Ausnahme wurde von Oliver bewusst genehmigt, nicht übersehen.

**Die tragende Unterscheidung ist die Richtung des Fehlermodus:**

Das Verbot zielt auf Listen, die bestimmen, **was als PII gilt** — auf die
Erkennungsseite. Dort ist eine Lücke gefährlich: ein nicht gelistetes Muster
bedeutet ungeschützte Daten beim Modell. Fail-closed ist dort richtig.

Diese Liste bestimmt, **was kein Name ist** — sie unterdrückt Fehltreffer.
Eine Lücke bedeutet hier: ein Fehlalarm bleibt bestehen. Der Fehlermodus zeigt
nach außen in Richtung Überschutz, nicht Unterschutz. Eine unvollständige
Nicht-PII-Liste kann per Konstruktion kein PII durchlassen — sie kann nur
Fehlalarme erzeugen. Und genau die werden gemessen.

Zur Abgrenzung: `recognizers-config.yml` enthält bereits `deny_list`-Recognizer
(DE_GENDER, DE_BERUF). Die sind das **Gegenteil** dieser Liste — sie fügen
Erkennung hinzu. Beide Richtungen existieren im Projekt und dürfen nicht
verwechselt werden.

## Die vier Gegenkontrollen (alle testgeprüft)

Alle erzwungen von `test/test_de_stopwords.py` — nicht dokumentiert, sondern
maschinell.

### 1. Verankerung (`^...$`) — die tragende Kontrolle

`allow_list` vergleicht gegen den **vollständigen** erkannten Span, nicht gegen
einzelne Tokens darin. Ein verankertes Muster unterdrückt deshalb nur, wenn der
ganze Span exakt das Stoppwort ist. Sobald das Modell den Span auf
Namenskontext verbreitert, greift die Unterdrückung nicht mehr:

```
"Frau Menge und Herr Mueller melden sich."     ('menge' steht auf der Liste)
  ohne Liste : PERSON 'Frau Menge', PERSON 'Herr Mueller'
  mit  Liste : PERSON 'Frau Menge', PERSON 'Herr Mueller'   (unverändert)
```

Ein unverankerter Eintrag lässt den Test fehlschlagen.

### 2. Messbeleg-Pflicht

Kein Eintrag ohne `probe`-Text, der den Fehlalarm am laufenden Analyzer
nachweislich erzeugt. Der Test prüft die **Gegenprobe**: Feuert eine Probe ohne
Liste nicht mehr, hat der Eintrag seinen Anlass verloren und der Test schlägt
fehl. Die Liste kann so nicht „auf Verdacht" wachsen.

### 3. Kollisionsprüfung gegen Kontrollnamen

Kein Muster darf einen der elf Kontroll-Namensspans vollständig matchen —
geprüft ohne laufenden Container, zusätzlich integrativ gegen den Analyzer.

### 4. Aufnahmekriterium

Nur Terme ohne plausible Eigennamen-Lesart: flektierte Verbformen (`aendere`,
`pruefe`) und Fachkomposita (`bestellnummer`, `rechnungsbetrag`). Der einzige
Grenzfall `menge` ist bewusst **nur kleingeschrieben** aufgenommen, weil
Schema-Schlüssel klein und Nachnamen groß geschrieben sind.

## Alternativen

Alle nach **Messung** verworfen, nicht nach Plausibilität:

### A) Score-Schwelle anheben (verworfen)
Fehlalarme und echte Namen kommen beide mit exakt `0.85` aus dem spaCy-NER.
Die Schwelle kann zwischen ihnen nicht unterscheiden — sie würde beide
gleichzeitig entfernen.

### B) Presidios `context`-Feld (verworfen)
Der Mechanismus **erhöht** Scores bei passendem Umfeld. Ein
Unterdrückungs-Gegenstück existiert nicht.

### C) Umlaut-Normalisierung vor der Analyse (verworfen)
`"Spaeter"` → `"Später"` beseitigt einen Teil der Fehlalarme, **kostet aber
denselben Recall**: `"Herr Später"` wird danach gar nicht mehr erkannt, während
`"Herr Spaeter"` vorher als PERSON erkannt wurde. Repariert `Fasse` und
`Uebersetze` überhaupt nicht. Zusätzlich verschiebt sie alle Offsets, was die
Re-Identifikation gefährdet.

### D) Zusätzliche Recognizer in `recognizers-config.yml` (nicht möglich)
Die Registry kann Entitäten nur **hinzufügen**. Einen
Unterdrückungs-Mechanismus hat sie nicht — deshalb liegt die Liste in einer
eigenen Datei.

## Konsequenzen

**Leichter:** Präzision ist jetzt messbar und wird durchgesetzt. Gemessen über
79 Korpus-Fälle:

| | vorher | nachher |
|---|---|---|
| Recall (`must_detect`) | 100,0 % (TP=51 FN=0) | **100,0 % (TP=51 FN=0)** |
| Precision | 66,2 % | **96,2 %** |
| False Positives | 26 | **2** |
| Störquote | 81,2 % (26/32) | **6,2 % (2/32)** |

Kein Recall-Verlust; alle 20 Entity-Typen bleiben bei 100 % Recall.

**Schwerer / zu beachten für künftige Work Items:**

1. **Die Liste wirkt noch nicht in Produktion.** Der Guardrail sendet die
   `allow_list` nicht. Spezifikation in `docs/foundation/erkennungsziel.md` §7.
   **Kritisch dabei:** `_analyze()` bedient auch den Verifikationsdurchlauf.
   Wird die Liste nur im Maskierungspfad gesetzt, blockt der
   Verifikationsdurchlauf fail-closed **jeden** Request, der einen
   Stoppwort-Term enthält.

2. **Zwei Fehlalarme bleiben bewusst stehen.** `spaeter` und `fasse` sind
   zugleich mögliche Nachnamen; `allow_list` sieht nur den Span-Text, keinen
   Kontext. Gemessen: mit ihnen auf der Liste verschwindet auch
   `"Herr Spaeter"` / `"Herr Fasse"`. Braucht einen kontextsensitiven
   Recognizer im Analyzer-Image — eigenes Work Item.

3. **Jede Erweiterung ist eine Einzelentscheidung.** Neue Einträge nur mit
   Messbeleg, Verankerung und Vorher/Nachher-Lauf beider Seiten.

4. **Der Korpus ist zu leicht.** Er meldet 100 % PERSON-Recall, während das
   Modell selbst 92,0 % angibt. Die 100 % sind kein Qualitätsbeleg, sondern
   eine Aussage über den Schwierigkeitsgrad des Korpus. Härtung ist ein eigenes
   Work Item; bis dahin darf die Zahl nicht nach außen kommuniziert werden.
