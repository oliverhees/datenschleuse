# Mitwirken an der Datenschleuse

Danke, dass du mitmachen willst. Kurz und ehrlich: das hier ist ein
Community-Projekt für die DACH-KI-Szene, kein Konzern-OSS mit langer
Vorlaufzeit — kleine, klare Beiträge sind willkommen.

## Bevor du anfängst

- Bitte lies den [Verhaltenskodex](CODE_OF_CONDUCT.md).
- Für Sicherheitslücken: **nicht** über ein öffentliches Issue melden, siehe
  [SECURITY.md](SECURITY.md).
- Größere Änderungen (neue Features, Architektur-Umbauten) vorher als
  [Issue](../../issues) zur Diskussion stellen, bevor du Zeit in eine
  Implementierung steckst — erspart dir Frust, falls die Richtung nicht passt.

## Was hierher gehört — und was nicht

Der **offene Kern** (dieses Repo, AGPL-3.0) deckt Erkennung, Maskierung,
Streaming-Re-Identifikation, den Quasi-Identifier-Layer und das
Schutzklassen-Modell ab. **Cockpit-Dashboard und Self-Learning-Filter sind
proprietär** und leben nicht in diesem Repo (siehe
[Lizenz-Abschnitt der README](README.md#-lizenz)) — PRs dazu können hier
nicht angenommen werden.

## Projektmanagement

Wir nutzen ausschließlich **[GitHub Issues](../../issues)** — kein Plane,
kein Trello, kein externes Tool. Wenn du einen Bug findest, ein Feature
willst oder an etwas arbeitest: Issue aufmachen oder ein bestehendes
kommentieren, damit alle den Stand nachvollziehen können.

## Lokal entwickeln

```bash
cp .env.example .env
# .env mit deinem eurouter.ai-Key + generierten Secrets füllen (siehe Kommentare in .env.example)
docker compose up --build
bash test/test-anonymisierung.sh
```

Details: [README-Quickstart](README.md#-quickstart).

## Neue deutsche PII-Entität einreichen (Recognizer)

Das ist der häufigste Beitrag — und hat eine feste Regel, die nicht
verhandelbar ist (siehe `CLAUDE.md`):

**Recognizer + Testfall + Benchmark-Eintrag gehören immer zusammen.**

Konkret, für jede neue Entität:

1. **Recognizer** in `presidio/recognizers-config.yml` ergänzen. Score und
   `deny_list_score` explizit setzen (Presidios Loader defaultet
   `deny_list_score` stillschweigend auf `0.0`, nicht auf die dokumentierten
   `1.0` — ein bekannter Stolperstein).
2. **Testfälle** in `test/corpus/de-pii-testkorpus.yaml`: mindestens 2–3
   `must_detect`-Fälle mit realistischen Beispielsätzen, plus mindestens 1
   `must_not_detect`-Negativfall, der einen naheliegenden False Positive
   provoziert.
3. **Benchmark laufen lassen** und das Ergebnis mitliefern:
   ```bash
   python3 test/corpus-benchmark.py
   ```
   Ziel: ≥95 % Recall, ≥90 % Precision für die neue Entität. Erfinde die
   Zahlen nicht — wenn der Benchmark schlechter ausfällt, gehört das
   ehrlich in die PR-Beschreibung, nicht verschwiegen.
4. Falls sinnvoll: passenden Unit-Test in `test/test_recognizers_de.py`
   ergänzen (containerfreier Regex-Test, siehe bestehende Beispiele).

**Erkennungsrate ist nie 100 %.** Wenn ein Muster inhärent unscharf ist
(z. B. weil es auf Großschreibung im Deutschen basiert), dokumentiere die
Grenze im Code-Kommentar ehrlich, statt sie zu verschweigen — siehe
`DE_FIRMA` in `presidio/recognizers-config.yml` als Beispiel für diesen Stil.

## Pull Requests

- Ein PR = eine zusammenhängende Änderung. Kein Sammel-PR mit fünf
  unabhängigen Themen.
- Bestehende Tests müssen grün bleiben (`python3 test/test_datenschleuse_guardrail.py`,
  `python3 test/test_recognizers_de.py`, ggf. weitere im `test/`-Ordner).
- Beschreib in der PR kurz das *Warum*, nicht nur das *Was* — der Code zeigt
  ohnehin, was sich ändert.
- Bezieh dich auf ein Issue, falls vorhanden.

## Fragen

[Issues](../../issues) oder [Wiki](../../wiki).
