# ADR-0001: Eigene Begriffe und Muster als separater Regel-Layer statt in der Presidio-Registry

- Status: akzeptiert
- Datum: 2026-08-19
- Work Item: [DATENSCHLE-7]

## Kontext

Die automatische PII-Erkennung findet prinzipbedingt nie alles. Was sie
strukturell NICHT finden kann, ist alles, was pro Installation verschieden
ist: Kundennamen, Projektnamen, interne Kürzel, Produktbezeichnungen,
Mandantennamen. Weder das Sprachmodell noch ein generisches Regex kennt
"Nordwind Logistik" oder "PRJ-4711".

Anwender müssen solche Begriffe deshalb selbst hinterlegen können. Oliver hat
dafür ausdrücklich **Deny-Listen und Regex-Muster** entschieden, **nicht**
ML-Finetuning: deterministisch, sofort wirksam, jede Regel einzeln testbar.
ML-Training ist explizit außerhalb des Scopes — auch, weil auf PII zu
trainieren der Kernzusage des Produkts widerspräche (ISC-36).

Rahmenbedingungen aus den Akzeptanzkriterien:
- ISC-23: persistent hinterlegbar, **ohne den Stack neu zu bauen**
- ISC-24: kein Muster geht live, bevor ein Testfall dafür grün ist
- ISC-26 (Anti-Kriterium): ein fehlerhaftes Muster darf **nur die eine
  Entität** blockieren, niemals die Pipeline lahmlegen
- ISC-27: neues Muster in unter 2 Minuten eingegeben und getestet
- ISC-36: kein Roh-PII gespeichert, kein Training auf PII

## Entscheidung

Eigene Begriffe und Muster leben in einem **separaten Regel-Layer**
(`litellm/custom_rules.py` + `rules/custom-rules.yml`), dessen Treffer im
Presidio-`/analyze`-Format in `DatenschleuseGuardrail._analyze()` eingemischt
werden — **nicht** als zusätzliche Recognizer in
`presidio/recognizers-config.yml`.

## Alternativen

### A) Erweiterung von `presidio/recognizers-config.yml` (verworfen)

Naheliegend, weil dort bereits `deny_list`-Recognizer stehen (DE_GENDER,
DE_BERUF). Aus drei Gründen verworfen, jeder für sich ausreichend:

1. **Verletzt ISC-26 fundamental.** Die Datei wird vom Presidio-Analyzer beim
   Boot als Ganzes geladen. Ein einziges unbalanciertes Regex bringt nicht
   eine Regel zu Fall, sondern den **gesamten Analyzer-Worker** — und weil die
   Guardrail fail-closed arbeitet, blockt dann *jeder* Request. Ein Tippfehler
   des Anwenders legt damit die komplette Datenschleuse still. Das ist exakt
   das Szenario, das ISC-26 ausschließen soll. Die Registry hat keine
   Fehler-Isolation pro Regel und kann sie architektonisch auch nicht bekommen.

2. **Verletzt ISC-23/ISC-27.** Die Datei ist read-only in den Analyzer-Container
   gemountet und wird nur beim Boot gelesen. Jede Änderung bräuchte einen
   Container-Neustart inklusive Laden des spaCy-Modells `de_core_news_lg`
   (zweistelliger Sekundenbereich, plus Ausfallzeit für alle laufenden
   Requests). "Sofort wirksam" ist so nicht erreichbar.

3. **Kein Ort für Testfälle.** Das Presidio-Registry-Schema kennt kein Feld für
   ein Beispiel. ISC-24 ("kein ungetestetes Muster in der Pipeline") ließe sich
   dort nur prozessual behaupten, nicht technisch erzwingen.

Ein weiterer, praktischer Punkt: Anwenderregeln und unsere gepflegten
deutschen Recognizer würden sich dieselbe Datei teilen. Die Datei ist im Repo
versioniert; echte Kundennamen dürfen dort niemals landen (öffentliches
Repository).

### B) Wrapper-Endpoint am LiteLLM-Proxy (verworfen)

Ein HTTP-Endpoint zum Regelpflegen wäre bequem, öffnet aber eine
schreibende Angriffsfläche auf die Sicherheitskonfiguration des Proxys
(Authentifizierung, Autorisierung, CSRF, Audit). Für v1 ein schlechtes
Verhältnis von Nutzen zu Risiko: der Betreiber eines selbst gehosteten
Proxys hat ohnehin Dateizugriff. Die CLI schreibt dieselbe Datei ohne
zusätzliche Netzwerkfläche. Ein Endpoint bleibt später nachrüstbar — die
Regel-Logik ist bewusst framework-frei und wiederverwendbar.

### C) ML-Finetuning eines eigenen NER-Modells (außerhalb des Scopes)

Von Oliver ausdrücklich ausgeschlossen. Wäre nicht deterministisch, nicht pro
Regel testbar, nicht sofort wirksam — und würde bedeuten, auf echten PII-Daten
zu trainieren, was ISC-36 direkt widerspricht.

## Konsequenzen

**Leichter:**
- Ein neues Muster ist in Sekunden live (gemessen: 5 s für Anlegen + Testen),
  ohne Rebuild und ohne Neustart — die Regeldatei wird bei Änderung per
  mtime-Prüfung neu eingelesen.
- Fehler-Isolation ist pro Regel möglich: eigene Kompilierung, eigene
  Selbstverifikation, eigenes Zeitbudget beim Matchen.
- Testfälle wohnen **in** der Regel (`examples` / `counter_examples`). Beim
  Laden wird jede Regel gegen ihr eigenes Beispiel verifiziert; fällt sie
  durch, wird sie nicht aktiv, sondern sichtbar in Quarantäne gestellt.
  ISC-24 ist damit strukturell erzwungen statt prozessual gefordert.
- Anwenderdaten sind sauber von versioniertem Projektcode getrennt
  (`rules/custom-rules.yml` per `.gitignore` ausgeschlossen).

**Schwerer / zu beachten:**
- Es gibt jetzt **zwei** Orte für Erkennungslogik. Faustregel für künftige
  Work Items: allgemeingültige deutsche Entitäten (Steuer-ID, KFZ, Straße)
  gehören weiterhin in `presidio/recognizers-config.yml` und werden vom
  Projekt gepflegt; installationsspezifische Begriffe gehören in den
  Regel-Layer und werden vom Anwender gepflegt.
- Anwender-Regexe laufen im Guardrail-Prozess. Deshalb ist `regex` (statt
  stdlib `re`) eine harte Laufzeit-Abhängigkeit: nur damit gibt es einen
  `timeout` beim Matchen, der katastrophales Backtracking (ReDoS) auf die
  betroffene Regel begrenzt. Presidio hängt ohnehin von `regex` ab.
- Bewusster Trade-off bei einer **komplett** unlesbaren Regeldatei (kaputtes
  YAML, verschwundener Mount): der zuletzt gültige Regelsatz bleibt aktiv und
  der Fehler wird laut gemeldet (`load_error`, sichtbar in
  `datenschleuse-rules list`). Begründung: ISC-26 verlangt ausdrücklich, dass
  ein Regelfehler die Pipeline nicht lahmlegt; den laufenden Schutz wegen
  eines Tippfehlers abzuschalten wäre die schlechtere Richtung. Wer hier
  fail-closed will, braucht ein eigenes Work Item.
- Der Image-Redactor kennt diese Regeln nicht (er bringt eine eigene
  Presidio-Instanz mit) — dieselbe bereits dokumentierte Grenze wie bei den
  deutschen Custom-Recognizern. Ein eigener Kundenname auf einem Screenshot
  wird also nicht durch eine eigene Regel geschwärzt.
