# ADR-0004: Die Prozess-Infrastruktur wird versioniert

- Status: **akzeptiert**
- Datum: 2026-08-20
- Work Item: [DATENSCHLE-72]
- Betroffene Dateien: `.gitignore`, `.claude/hooks/`, `.claude/agents/`,
  `.claude/commands/`, `.claude/settings.json`
- Verwandt: [DATENSCHLE-79] (Stop-Gate pro Worktree — die Hook-Änderung, die
  ohne diese Entscheidung nicht versionierbar war), [DATENSCHLE-62]
  (falsch-grünes Test-Gate), [DATENSCHLE-55] (Stop-Gate wertet das Ergebnis)

> **Kurzfassung.** `.gitignore` schloss `.claude/` pauschal aus. Damit lagen
> sämtliche Prozess-Gates dieses Projekts außerhalb von Git. Die Verfassung
> schrieb Prozesse vor, deren Ausführung nicht mitgeliefert wurde. Ab jetzt
> gilt die Trennlinie: **Was den Prozess definiert, kommt ins Repo. Was pro
> Lauf entsteht, bleibt draußen.**

---

## Kontext

`CLAUDE.md` ist die Verfassung dieses Projekts. Sie verlangt unter anderem:

- Gesetz 2: kein Code ohne grünen Test — durchgesetzt vom Stop-Gate-Hook.
- Gesetz 4: kein Force-Push, kein `--no-verify` — durchgesetzt vom Guard-Hook.
- Gesetz 5 / 10 / 11: Security-, QA- und UX-Audits vor dem Merge — ausgeführt
  von Agenten-Rollendefinitionen.
- „Mandatory external review": der `external-reviewer` läuft **vor jedem
  Commit**.

Durchgesetzt wurde davon nichts, was ein Klon des Repositorys mitbekommt.
Zeile 5 der `.gitignore` lautete `.claude/`, und darunter lag die komplette
Ausführungsschicht:

| Verzeichnis | Größe | Inhalt |
|---|---|---|
| `.claude/hooks/` | 52 K | Stop-Gate, Guard, Tracker, Verdict-Skript, Testsuite |
| `.claude/agents/` | 32 K | 7 Rollendefinitionen inkl. `external-reviewer` |
| `.claude/commands/` | 8 K | Slash-Befehl `/goal` |
| `.claude/settings.json` | 4 K | Die Verdrahtung, die die Hooks überhaupt aktiviert |

Das ist keine Ordnungsfrage. Drei belegte Befunde haben genau diese Wurzel.

### Befund 1 — ein Test, der Vertrauen erzeugt und nichts prüft

Die Stop-Gate-Testsuite meldete in CI grün, ohne irgendetwas zu prüfen: Die
Hooks, gegen die sie testet, existieren im CI-Checkout nicht. Gemessen in
einem frischen Klon von `main` mit `CI=true`:

```
Ran 18 tests in 0.001s

OK (skipped=14)
```

Vier Fälle prüfen die Entscheidungsfunktion selbst, **vierzehn prüfen nichts**.
Der Job ist grün. Ein Test ohne Deckung ist schlimmer als kein Test: Er
erzeugt Vertrauen, für das keine Prüfung stattgefunden hat. Am selben Muster
ist bereits DATENSCHLE-62 hängengeblieben.

### Befund 2 — Hooks ohne atomaren Stand

Eine Schwachstelle in der Marker-Zuordnung ließ sich nicht sauber schließen,
weil Hooks mitten in einer laufenden Sitzung ausgetauscht werden können.
Schreiber (`track.sh`) und Leser (`stop-gate.sh`) müssen exakt denselben
Marker-Schlüssel bilden; driften sie auseinander, findet das Gate nie einen
Marker und lässt alles durch — ein lautloser Totalausfall. `scope.sh` hält
die Berechnung deshalb an einer Stelle. Das schützt aber nur gegen
Copy-Paste-Drift, nicht gegen zeitliche Drift: Solange die Dateien außerhalb
von Git liegen, gibt es keinen Commit, der „Schreiber und Leser gehören
zusammen" verbindlich macht. In Git ist die Aktualisierung atomar.

### Befund 3 — eine Regel ohne Ausführung

Der `external-reviewer` soll laut Verfassung vor jedem Commit laufen. Seine
Definition existierte auf genau einem Rechner. Wer das Repository klont,
bekommt die Regel, aber nicht den Agenten, der sie ausführt. Dasselbe gilt
für `security-auditor`, `qa-manager`, `ux-reviewer`, `lead`, `controller`
und `client-liaison` — also für jedes Gate der Gesetze 5, 8, 10, 11 und 13.

Die Datenschleuse soll als Open-Source-Projekt veröffentlicht werden. Ein
Beitragender hätte bisher eine Verfassung vorgefunden, die auf Werkzeuge
verweist, die nicht im Repository sind.

## Entscheidung

Die prozessdefinierenden Teile von `.claude/` — Hooks, Agenten,
Slash-Befehle und die Hook-Verdrahtung `settings.json` — werden versioniert;
`.gitignore` schließt statt `.claude/` nur noch die Laufzeitpfade aus.

Trennlinie, bindend für künftige Einträge:

- **Ins Repo:** was den Prozess *definiert* und für alle gleich gelten muss.
- **Draußen:** was *pro Lauf* entsteht.

Ausgeschlossen bleiben damit:

| Pfad | Warum draußen |
|---|---|
| `.claude/worktrees/` | 173 M Arbeitskopien paralleler Agenten |
| `.claude/scopes/` | Sitzungszustand pro Lane; enthält wörtliche Shell-Transkripte |
| `.claude/hooklog.jsonl`, `.claude/worklog.jsonl` | Betriebsprotokolle |
| `.claude/.last_code_edit`, `.claude/.last_test_run` | Marker des laufenden Gates |
| `.claude/.stop_block_count` | Zähler der Stop-Gate-Notbremse |
| `.claude/settings.local.json` | persönliche Übersteuerung, gehört keinem Team |

`.claude/scopes/` war der einzige Grenzfall (108 K, Name mehrdeutig). Die
Prüfung des Inhalts entscheidet ihn eindeutig: Jedes Unterverzeichnis ist
nach einer Sitzungs-ID benannt und enthält ausschließlich `.last_test_run`
und `.last_code_edit`. Diese Marker führen das vollständige Kommando des
letzten Testlaufs mit — inklusive Pfaden und Heredoc-Inhalten aus fremden
Sitzungen. Reiner Laufzeitzustand, und obendrein nichts, was in ein
öffentliches Repository gehört.

## Alternativen

**Prozessdateien an einen anderen Ort verschieben** (z. B. `tooling/hooks/`)
und `.claude/` weiter pauschal ignorieren. Verworfen: Claude Code sucht
Hooks, Agenten und Befehle unter `.claude/`. Ein zweiter Ort erzwingt einen
Kopier- oder Symlink-Schritt bei jedem Klon — also genau die manuelle
Installation, deren Fehlen Befund 3 ausmacht. Ein Prozess, der einen
Extraschritt braucht, wird irgendwann nicht ausgeführt.

**Nur `.claude/hooks/` versionieren**, Agenten und Befehle draußen lassen.
Verworfen: Befund 3 betrifft ausschließlich `agents/`. Die Hälfte des
Problems zu lösen hätte die Verfassung weiter auf Werkzeuge verweisen
lassen, die nicht mitkommen.

**`settings.json` weglassen.** Verworfen: Ohne sie enthält ein frischer Klon
zwar die Hook-Skripte, aber nichts, was sie aufruft. Die Gates wären
vorhanden und unwirksam — dieselbe Klasse von Fehler wie Befund 1, nur eine
Ebene tiefer.

**Alles so lassen** und die Testsuite stattdessen rot färben. Verworfen: `test`
ist ein erforderlicher Check. Ein dauerhaft roter Job blockiert jeden PR
wegen einer bekannten Lücke — und ein Gate, das an einer bekannten Lücke
scheitert, wird abgeschaltet. Erst die Voraussetzung schaffen, dann scharf
schalten.

## Konsequenzen

### Was leichter wird

- **Die Deckungslücke ist geschlossen.** In einem frischen Klon dieses
  Branches liegt `.claude/hooks/` vor; die Stop-Gate-Tests finden ihre
  Skripte und prüfen wirklich, statt zu überspringen.
- **Die Bash-Testsuite kann in CI laufen.** `.claude/hooks/test-hooks.sh`
  (26 Fälle) braucht nur `bash`, `jq` und `git` — alles auf
  `ubuntu-latest` vorhanden. Sie war bisher schlicht nicht im Checkout.
- **Ein Klon bringt die Gates mit.** Wer das Repository klont, bekommt die
  Verfassung *und* ihre Durchsetzung — Voraussetzung für die geplante
  Open-Source-Veröffentlichung.
- **Hook-Änderungen sind atomar und nachvollziehbar.** Wer wann welche
  Regel geändert hat, steht in der Historie statt in einer Dateizeit.

### Was schwerer wird — der Preis

**Hook-Änderungen brauchen künftig einen PR und laufen durch die Gates.** Das
ist der Sinn der Sache, aber es kostet Geschwindigkeit: Was bisher eine
Sekunde dauerte (Datei editieren, wirkt sofort für alle), braucht jetzt
Branch, Commit, Review, vier grüne Checks und einen Merge. Eine Prozess-
Anpassung mitten in der Arbeit ist damit keine Nebenbei-Aktion mehr.

Zwei Nebenwirkungen, die daraus folgen:

- **Ein Henne-Ei-Fall.** Ein Hook, der die Gates blockiert, lässt sich nicht
  mehr trivial umgehen — sein Fix muss durch dieselben Gates. Beim Debuggen
  eines kaputten Gates ist das unangenehm. Der Ausweg ist keine Ausnahme im
  Prozess, sondern die Testsuite: `test-hooks.sh` fährt die echten Skripte
  in Wegwerf-Sandboxes und beweist die Wirkung, bevor der Hook scharf wird.
- **Getrackte Datei ≠ aktive Datei.** Claude Code liest die Hooks aus der
  Hauptauscheckung. Ein Merge auf `main` ändert nicht automatisch, was in
  einer laufenden Sitzung wirkt — die Hauptauscheckung muss den Stand ziehen.
  Zwischen Merge und Pull kann der Prozess im Repo und der Prozess auf dem
  Rechner auseinanderlaufen.

### Was künftige Work Items beachten müssen

- **Neue Laufzeitdatei unter `.claude/` → sofort eine Zeile in `.gitignore`.**
  Das ist kein Schönheitsfehler: `verdict.sh` bricht ab, sobald
  `git status --porcelain` irgendetwas außer `?? .gates/` meldet. Eine
  einzige nicht ignorierte Laufzeitdatei legt damit **alle** Gate-Verdicts
  im Projekt still — lautlos, weil niemand den Zusammenhang vermutet.
- **Kein Secret, kein Kundenname, kein absoluter Hostpfad in `.claude/`.**
  Das Verzeichnis ist ab jetzt Teil eines Repositorys, das öffentlich werden
  soll. Vor dem Hinzufügen jeder Datei gilt Gesetz 5 wie überall sonst.
- **Änderungen an `.claude/agents/` sind Prozessänderungen.** Sie ändern, wer
  im Team was prüft, und gehören entsprechend begründet ans Work Item.

### Offen

Die Bash-Suite ist damit *lauffähig* in CI, aber noch **nicht verdrahtet** —
`ci.yml` ruft sie nicht auf. Das ist bewusst ein eigenes Work Item: Ein
neuer Schritt im `test`-Job macht die Suite für jeden PR verbindlich, und
ihre zeitabhängigen Fälle (`sleep 0.01` zwischen Marker-Zeitstempeln)
sollten vorher auf Flakiness geprüft werden. Ein neu eingeführter Check,
der sporadisch rot wird, wird weggeklickt — siehe die Begründung zu Befund 1.
