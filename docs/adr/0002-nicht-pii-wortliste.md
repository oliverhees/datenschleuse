# ADR-0002: Nicht-PII-Wortliste zur Unterdrückung von NER-Fehlalarmen

> Revidiert nach Security-Audit gegen `32e648c` (zwei High). Die Begründung
> der Ausnahme wurde dabei korrigiert — siehe „Korrektur nach dem
> Security-Audit" weiter unten.

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
`/analyze` übergeben. **Jedes Muster ist mit `\A...\z` verankert**, und
`regex_flags: 0` wird explizit mitgesendet. `^...$` ist ausdrücklich verboten
— warum, steht unter „Absolute Verankerung" weiter unten.

## Die Kollision mit der Security-Baseline — und warum die Ausnahme trägt

`docs/foundation/security-baseline.md` verbietet Denylists: „sie sind erst
vollständig, wenn jemand die Lücke findet." Diese Liste ist der Form nach eine
Denylist. Die Ausnahme wurde von Oliver bewusst genehmigt, nicht übersehen.

**Die tragende Unterscheidung ist die Richtung des Fehlermodus:**

Das Verbot zielt auf Listen, die bestimmen, **was als PII gilt** — auf die
Erkennungsseite. Dort ist eine Lücke gefährlich: ein nicht gelistetes Muster
bedeutet ungeschützte Daten beim Modell. Fail-closed ist dort richtig.

Diese Liste bestimmt, **was kein Name ist** — sie unterdrückt Fehltreffer.
Eine Lücke bedeutet hier: ein Fehlalarm bleibt bestehen.

### Korrektur nach dem Security-Audit: Lücke ist nicht das Risiko, Übermaß ist es

Die erste Fassung dieses ADR argumentierte, eine unvollständige Nicht-PII-Liste
könne „per Konstruktion kein PII durchlassen". Das stimmt für
**Unvollständigkeit** — und ging genau deshalb am eigentlichen Risiko vorbei.

Das Risiko dieser Listenart ist nicht die Lücke, sondern das **Übermaß**: ein
Eintrag, der mehr trifft als gemeint. Dort kehrt sich die Richtung des
Fehlermodus um — die Maßnahme entfernt dann **echte** Treffer, und der
Fehlermodus zeigt nach innen in Richtung Unterschutz.

Genau das ist passiert (F1/F2, gegen `32e648c` gemessen): Vier von acht
Recall-Kontrollnamen gingen im Klartext durch, weil `^...$` unter dem
Analyzer-Default `MULTILINE` ein Zeilen-Anker ist und nicht der Vollspan-Anker,
für den er gehalten wurde.

**Daraus folgt die eigentliche Begründung der Ausnahme:** Sie trägt nicht, weil
Lücken harmlos sind — sie trägt nur, solange das **Übermaß** mechanisch
begrenzt ist. Die Verankerung ist deshalb nicht eine Kontrolle unter vieren,
sondern **die** Kontrolle, die die Ausnahme überhaupt rechtfertigt. Fällt sie,
fällt die Ausnahme.

Konsequenz für jede künftige Erweiterung: Ein neuer Eintrag ist erst dann
zulässig, wenn maschinell belegt ist, dass er **nichts außer sich selbst**
trifft — nicht, wenn plausibel erscheint, dass er kein Name ist.

Zur Abgrenzung: `recognizers-config.yml` enthält bereits `deny_list`-Recognizer
(DE_GENDER, DE_BERUF). Die sind das **Gegenteil** dieser Liste — sie fügen
Erkennung hinzu. Beide Richtungen existieren im Projekt und dürfen nicht
verwechselt werden.

## Die vier Gegenkontrollen (alle testgeprüft)

Alle erzwungen von `test/test_de_stopwords.py` — nicht dokumentiert, sondern
maschinell.

### 1. Absolute Verankerung (`\A...\z`) — die tragende Kontrolle

`allow_list` vergleicht gegen den **vollständigen** erkannten Span. Ein
verankertes Muster darf deshalb nur greifen, wenn der ganze Span exakt das
Stoppwort ist.

**Entscheidend ist die Wahl der Anker.** `^` und `$` leisten das *nicht*: Der
Analyzer defaultet `regex_flags` auf `DOTALL|MULTILINE|IGNORECASE`, und unter
`MULTILINE` matchen `^`/`$` an jedem Zeilenumbruch **innerhalb** des Spans.
`\A` und `\z` verankern dagegen immer am String-Anfang bzw. -Ende, unabhängig
von den Flags.

```
Span "Zahlungsart\nLoewenstein"   ('zahlungsart' steht auf der Liste)
  mit ^zahlungsart$ : Treffer -> ganzer Span unterdrückt, Nachname verloren
  mit \Azahlungsart\z : kein Treffer -> PERSON 'Loewenstein' bleibt
```

Zusätzlich wird `regex_flags: 0` **explizit gesendet**, statt den Server-Default
zu erben. Der Test erzwingt beides und lässt jeden Eintrag mit `^`/`$` oder
ohne explizite Flags fehlschlagen.

### 2. Messbeleg-Pflicht

Kein Eintrag ohne `probe`-Text, der den Fehlalarm am laufenden Analyzer
nachweislich erzeugt. Der Test prüft die **Gegenprobe**: Feuert eine Probe ohne
Liste nicht mehr, hat der Eintrag seinen Anlass verloren und der Test schlägt
fehl. Die Liste kann so nicht „auf Verdacht" wachsen.

### 3. Kollisionsprüfung gegen Kontrollnamen

Kein Muster darf einen Kontroll-Namensspan vollständig matchen — geprüft ohne
laufenden Container, zusätzlich integrativ gegen den Analyzer. Maßgeblich ist
die Konstante `_RECALL_KONTROLLEN` in `test/test_de_stopwords.py` (derzeit 15
Fälle, inklusive der Layouts aus F1/F2); eine Zahl hier im Text wäre schon
zweimal veraltet gewesen. Seit der Vorrangs-Regel kommen die `deny_list`-Terme
des Betreibers als zweite Kollisionsmenge dazu (Konsequenz 2).

### 4. Aufnahmekriterium — maschinell statt geschätzt

Die erste Fassung verlangte „keine plausible Eigennamen-Lesart". Das war eine
Einschätzung, keine Kontrolle — und sie hat `menge` und `fuege` durchgelassen,
beides reale deutsche Familiennamen (Menge, Füge).

Jetzt gilt eine prüfbare Regel mit zwei Bedingungen, die beide erfüllt sein
müssen:

1. **Kompositum mit erlaubtem Kopf-Morphem.** Der Term endet auf einem Kopf aus
   `nummer, datum, art, status, betrag, preis, gebuehr, grund, fenster` und ist
   **echt länger** als dieser Kopf. Der bare Kopf selbst ist nicht zulässig.
2. **Kein Namensspan — maschinell belegt.** Der konkrete Term darf keinen der
   Kontroll-Namensspans matchen und muss seinen Fehlalarm am laufenden Analyzer
   nachweisen (Gegenkontrollen 2 und 3).

**Wichtig, weil die erste Fassung dieser Regel genau hier wieder falsch war:**
Die Kopf-Menge ist *nicht* namensfrei. `Preis` und `Grund` sind reale deutsche
Familiennamen; ein früherer Wortlaut behauptete das Gegenteil („Keines davon
kommt als barer deutscher Familienname vor") und wiederholte damit denselben
Fehlertyp, gegen den die Regel eingeführt wurde — eine plausible Behauptung
anstelle einer Kontrolle.

Die schützende Eigenschaft ist deshalb nicht der Kopf, sondern der
**zusammengesetzte** Term: Die konkreten vierzehn Einträge sind einzeln gegen
den laufenden Analyzer und gegen die Kontrollnamen geprüft und sind keine
deutschen Nachnamen. Der Kopf-Filter leistet nur die Verengung auf
Schema-Schlüssel-Komposita — er ersetzt die Einzelprüfung nicht. Deshalb ist
Bedingung 1 ohne Bedingung 2 wertlos, und deshalb ist der bare Kopf gesperrt.

Beides erzwingt `test/test_de_stopwords.py`.

Die Regel ist bewusst eng. Sie schließt Terme aus, die sehr wahrscheinlich
harmlos wären (`aendere`, `pruefe`) — aber „sehr wahrscheinlich" ist genau die
Kategorie, die das Audit ausgehebelt hat.

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
82 Korpus-Fälle:

| | ohne Liste | mit Liste |
|---|---|---|
| Recall (`must_detect`) | 100,0 % (TP=54 FN=0) | **100,0 % (TP=54 FN=0)** |
| Precision | 66,2 % | **81,8 %** |
| False Positives | 26 | **12** |
| Störquote | 81,2 % (26/32) | **37,5 % (12/32)** |

Kein Recall-Verlust; alle Entity-Typen bleiben bei 100 % Recall — inklusive der
drei Layouts aus dem Audit (zweizeiliges Label-Wert-Paar, „Nachname, Vorname").

**Das Gate ist damit rot** (Precision < 90 %, Störquote > 10 %). Das Ziel wird
nicht abgesenkt: Die Zahl bildet korrekt ab, dass DATENSCHLE-70 offen ist.

> Historische Einordnung: Eine frühere Fassung dieser Liste meldete 96,2 %
> Precision und 6,2 % Störquote. Diese Zahlen waren **unbrauchbar** — sie
> wurden durch Einträge erkauft, die echte Namen unterdrückten (F1/F2). Der
> Rückbau kostet 15 Prozentpunkte Precision und gewinnt die Korrektheit
> zurück.

**Schwerer / zu beachten für künftige Work Items:**

1. **Die Liste wirkt noch nicht in Produktion.** Der Guardrail sendet die
   `allow_list` nicht. Spezifikation in `docs/foundation/erkennungsziel.md` §7.
   **Kritisch dabei:** `_analyze()` bedient auch den Verifikationsdurchlauf.
   Wird die Liste nur im Maskierungspfad gesetzt, blockt der
   Verifikationsdurchlauf fail-closed **jeden** Request, der einen
   Stoppwort-Term enthält.

2. **Bekannte Grenze — der Betreiber-Vorrang ist nicht durchgesetzt.**
   Presidios `allow_list` wirkt **nach** der Erkennung und entfernt jeden
   Treffer, dessen Span sie matcht — auch einen, der aus einer `deny_list` in
   `presidio/recognizers-config.yml` stammt. Live belegt: `"Der Bürgermeister
   kommt morgen vorbei."` liefert ohne Liste korrekt `DE_BERUF`; mit einer
   `allow_list`, die dasselbe Wort enthält, verschwindet der Treffer
   **vollständig und ohne Warnung**.

   Das ist die falsche Richtung: `deny_list`-Einträge sind eine ausdrückliche
   Schutzanweisung des Betreibers, die Stoppwortliste ist eine mitgelieferte
   Vorgabe. Eine Vorgabe darf eine ausdrückliche Anweisung nicht still
   überstimmen — sonst entfernt ein Datenschleuse-Update lautlos Schutz, den
   der Betreiber selbst konfiguriert hat.

   **Heute folgenlos**, aus zwei Gründen: die Liste ist nicht verdrahtet, und
   es gibt keine Überschneidung. Beides ist ein Zustand, kein Mechanismus —
   deshalb gilt ab jetzt als bindende Anforderung:

   - **Datenebene:** Kein Muster aus `de-stopwords.yml` darf einen Term einer
     `deny_list` aus `recognizers-config.yml` matchen. Erzwungen von
     `test/test_de_stopwords.py::BetreiberVorrang` — ab sofort, ohne
     Guardrail-Anschluss.
   - **Laufzeit:** Sobald der Guardrail die Liste sendet (§7), muss er die
     Überschneidung beim Laden prüfen und bei einem Treffer **fail-closed**
     starten — nicht die Liste stillschweigend beschneiden und nicht still
     weiterlaufen. Ein Betreiber, der beides konfiguriert, hat einen
     Konflikt, den nur er auflösen kann.

   Die vier Gegenkontrollen decken diese Frage nicht ab: sie schützen die
   Erkennung des Modells vor der Liste, nicht die Konfiguration des
   Betreibers vor der Liste.

3. **DATENSCHLE-70 bleibt offen und ist über diesen Mechanismus nicht
   lösbar.** `allow_list` sieht ausschließlich den Span-Text, keinen Kontext —
   Fehlalarm und echter Name erzeugen denselben Span:
   `"Aendere keinen einzigen Wert."` → `PERSON 'Aendere'` und
   `"Herr Aendere ruft an."` → `PERSON 'Aendere'`. Jede Unterdrückung trifft
   beide. Das betrifft alle ASCII-Verbformen sowie `spaeter`, `fasse`,
   `fuege`, `menge`, `rueckruf`. Braucht einen kontextsensitiven Recognizer
   im Analyzer-Image — eigenes Work Item.

4. **Jede Erweiterung ist eine Einzelentscheidung.** Neue Einträge nur mit
   Messbeleg, absoluter Verankerung, erlaubtem Kopf-Morphem (als echtes
   Kompositum, nicht als barer Kopf), Kollisionsfreiheit gegen Kontrollnamen
   **und** gegen die `deny_list`-Terme des Betreibers sowie Vorher/
   Nachher-Lauf beider Seiten.

5. **Der Aufrufer muss `regex_flags` senden.** Wer sie wegläßt, erbt
   `DOTALL|MULTILINE|IGNORECASE` und schaltet F1 und F2 wieder scharf. Das gilt
   für den Guardrail genauso wie für den Benchmark.

6. **Der Korpus ist zu leicht.** Er meldet 100 % PERSON-Recall, während das
   Modell selbst 92,0 % angibt. Die 100 % sind kein Qualitätsbeleg, sondern
   eine Aussage über den Schwierigkeitsgrad des Korpus. Härtung ist ein eigenes
   Work Item; bis dahin darf die Zahl nicht nach außen kommuniziert werden.
