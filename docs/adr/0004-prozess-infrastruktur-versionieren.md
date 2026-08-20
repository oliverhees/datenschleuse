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
Hooks, gegen die sie testet, existieren im CI-Checkout nicht.

> **Woher die Zahlen stammen — bitte zuerst lesen.** Die Suite ist
> `test/test_stop_gate_worktree.py` aus [DATENSCHLE-79]. Sie liegt auf
> `feature/DATENSCHLE-79-stop-gate-worktree` und ist **noch nicht
> gemerged**. Aus `main` allein sind die folgenden Zahlen deshalb *nicht*
> reproduzierbar — das ist keine Schlamperei, sondern die Reihenfolge:
> Diese Entscheidung schafft die Voraussetzung dafür, dass jene Suite
> überhaupt etwas prüfen kann. Wer nachmessen will, holt die Datei
> ausdrücklich dazu:
>
> ```
> git show fe1253d2556bc94cbcfed2397ee1e85975bb7f07:test/test_stop_gate_worktree.py \
>   > <klon>/test/test_stop_gate_worktree.py
> cd <klon>
> CI=true PYTHONPATH=litellm python3 -m unittest discover -s ./test \
>   -p "test_stop_gate_worktree.py"
> ```
>
> Bewusst an den **Commit-SHA** gepinnt, nicht an den Branchnamen: Wird
> `feature/DATENSCHLE-79-stop-gate-worktree` umbenannt, rebased oder
> verworfen, stirbt sonst der einzige Beleg dieses Dokuments. Ein SHA
> kostet nichts und hält. (Stand des Belegs: `fe1253d`.)

So gemessen in einem frischen Klon von `main`:

```
Ran 18 tests in 0.001s

OK (skipped=14)
```

Vier Fälle (`HookVerfuegbarkeitTest`) prüfen die Entscheidungsfunktion
selbst und laufen immer; **vierzehn (`StopGateWorktreeTest`) prüfen
nichts**. Der Job ist grün. Ein Test ohne Deckung ist schlimmer als kein
Test: Er erzeugt Vertrauen, für das keine Prüfung stattgefunden hat. Am
selben Muster ist bereits DATENSCHLE-62 hängengeblieben.

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
nach Worktree-Basename plus Prüfsumme des vollen Pfades benannt
(`scope.sh:45-52`) und enthält ausschließlich `.last_test_run`
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

- **Die Deckungslücke ist geschlossen — gemessen, nicht behauptet.**
  Derselbe Lauf wie oben, diesmal in einem frischen Klon dieses Branches
  von GitHub, wieder mit `CI=true`:

  | | vorher (`main`) | nachher (dieser Branch) |
  |---|---|---|
  | Ergebnis | `OK (skipped=14)` | `OK` |
  | übersprungen | 14 von 18 | **0 von 18** |
  | Laufzeit | 0,001 s | **4,047 s** |

  Die Laufzeit ist dabei der ehrlichste Wert: 0,001 s ist die Zeit, die
  ein Überspringen kostet. Die vier Sekunden danach sind echte
  Subprozesse gegen echte `git worktree`-Auscheckungen. Beides mit dem
  Kommando aus Befund 1 gemessen, die Suite jeweils gleich dazugeholt.

  **Geschlossen heißt hier: die Voraussetzung steht.** Der CI-Job führt
  diese Suite noch nicht aus — `test_stop_gate_worktree.py` kommt erst
  mit [DATENSCHLE-79] ins Repo, und `ci.yml` ruft `test-hooks.sh` nicht
  auf (siehe *Offen*). Was dieser Commit beseitigt, ist der Grund, aus
  dem die Prüfung bisher unmöglich war — nicht mehr und nicht weniger.
- **Die Bash-Testsuite kann in CI laufen.** `.claude/hooks/test-hooks.sh`
  (26 Fälle) braucht nur `bash`, `jq` und `git` — alles auf
  `ubuntu-latest` vorhanden. Verifiziert im frischen Klon, ohne gesetztes
  `CLAUDE_PROJECT_DIR`: `Ran 26 tests / OK`, Exit 0. Sie war bisher
  schlicht nicht im Checkout.
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
  Prozess, sondern die Testsuite: `test-hooks.sh` fährt `track.sh` und
  `stop-gate.sh` als echte Subprozesse in Wegwerf-Sandboxes und beweist
  ihre Wirkung, bevor der Hook scharf wird.
  **Geltungsbereich, damit dieser Satz nicht mehr verspricht als er hält:**
  Genau diese zwei Skripte deckt die Suite ab. `guard.sh`, `verdict.sh`,
  `worklog.sh` und `session-brief.sh` haben **keinen einzigen Test** —
  ausgerechnet der Guard nicht, der Gesetz 4 und 5 durchsetzt. Für die ist
  der Henne-Ei-Fall real und der Ausweg fehlt noch. Eigenes Item.
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
`ci.yml` ruft sie nicht auf. Das ist bewusst ein eigenes Work Item, denn
ein neuer Schritt im `test`-Job macht die Suite für jeden PR verbindlich;
das ist eine Prozessentscheidung, keine Nebenwirkung dieses ADRs.

Die naheliegende Sorge dagegen wurde **lokal** geprüft — was eine
Runner-Messung ausdrücklich nicht ersetzt: Die Suite enthält
zeitabhängige Fälle (`sleep 0.01` zwischen Marker-Zeitstempeln,
Auswertung über `-nt`), die auf einem langsamen oder überbuchten Runner
kippen könnten. Genau dort wurde nicht gemessen. Zehn aufeinanderfolgende
Läufe im frischen Klon auf dieser Maschine:

```
for i in $(seq 1 10); do
  env -u CLAUDE_PROJECT_DIR CI=true ./.claude/hooks/test-hooks.sh >/dev/null 2>&1
  echo "Lauf $i: exit $?"
done
```

Ergebnis: **10 von 10 grün, kein einziger roter Lauf.** Das widerlegt die
Sorge nicht, es verschiebt nur die Beweislast: Wer die Suite verdrahtet,
sollte die ersten Läufe auf dem Runner beobachten. Die Verdrahtung bleibt
ohnehin ein eigenes Item, damit ein neu eingeführter Pflicht-Check bewusst
beschlossen wird und nicht beiläufig entsteht.

### Was das externe Review aufgedeckt hat und hier NICHT gelöst wird

Das Review zu diesem Commit (`glm-5.2` + `kimi-k3` über PAL, plus eigener
Durchgang) hat Befunde am Hook-Code selbst gefunden. Dieser Commit
**veröffentlicht** diesen Code, er ändert ihn nicht — die Befunde gehören
deshalb in eigene Items und werden hier nur festgehalten, damit sie nicht
verlorengehen (Gesetz 7). In Schwere-Reihenfolge:

1. **Freigabeentscheidung vor der Veröffentlichung (🔴 Oliver).** Mit
   `settings.json` im Repo führt jeder Klon beim Öffnen in Claude Code
   Shell-Skripte aus dem Repo aus — bei SessionStart und um jeden
   Tool-Call. Heute harmlos; das Muster ist der Punkt: Jeder künftige PR
   auf `.claude/hooks/**` wäre Codeausführung auf jedem Maintainer-Rechner,
   und `guard.sh` sieht dabei jeden Kommandostring. Vor dem Public-Gang
   braucht es mindestens CODEOWNERS auf `.claude/**` und `.github/**` plus
   einen Absatz in `SECURITY.md`. Alternativen: `settings.json.example`
   mit Opt-in, oder eine Env-Schranke als erste Hook-Zeile.
   `settings.json` mitzuliefern bleibt funktional richtig — sonst hätte
   ein Klon Skripte ohne Auslöser.
2. **`client-liaison.md` beschrieb das Beschönigen von Security-Befunden**
   — ✅ **behoben, bevor irgendetwas öffentlich wurde.** Die Rolle wies an,
   „nicht *5 Critical Findings*" zu sagen, sondern *Härtungsbedarf*. In
   einem öffentlichen Repo für ein DSGVO-/PII-Produkt wäre das die denkbar
   ungünstigste Selbstbeschreibung gewesen. Rollendefinitionen zu ändern
   ist eine Prozessänderung nach Gesetz 13, also hat **Oliver entschieden**:
   Die Sprachregelung ist ersatzlos gestrichen. An ihrer Stelle steht jetzt
   eine Zeile — „Nichts wird beschönigt: Befunde beim Namen nennen, Zahlen
   mit Beleg, offene Punkte offen." Bewusst keine neue Sprachregelung mit
   umgekehrtem Vorzeichen: Das Zwei-Kanal-Prinzip bleibt richtig, Kunden
   brauchen keine Rohdaten. Was wegfällt, ist die Anweisung, die
   **Größenordnung** zu verschleiern.
3. **Ohne `jq` fallen `guard.sh`, `track.sh` und `stop-gate.sh` lautlos
   OFFEN** (im Review mit leerem PATH nachgestellt: ein Force-Push auf
   `main` wird durchgelassen). `jq` ist nirgends als Voraussetzung
   dokumentiert. Fix: Präflight `command -v jq || exit 2` plus eine Zeile
   in der Einrichtungsdoku. Dieselbe Fehlerklasse wie Befund 1, eine
   Ebene tiefer.
4. **`track.sh` lässt sich grünfärben.** `tail -1` über die
   Summary-Zeilen heißt „letzte passende Zeile gewinnt": `pytest; echo OK`
   nach einem echten `1 failed` ergibt `pass`. Auch
   `unittest -p "zzz_*.py"` (`Ran 0 tests` + `OK`) ergibt `pass` — das
   Fail-Signal `^Ran 0 tests` ist toter Code, weil unittest danach immer
   `OK` druckt. Vorschlag: bei mehreren Treffern gewinnt das strengste
   Ergebnis, nicht das letzte.
5. **Bash-Änderungen umgehen das Stop-Gate vollständig.** `track.sh` setzt
   `.last_code_edit` nur bei `Edit|Write|MultiEdit` und acht Endungen.
   `sed -i`, Heredoc, `git apply` setzen keinen Marker — `.sh`, `.yml`,
   `.sql`, Dockerfiles und damit die Hooks und `ci.yml` selbst sind vom
   Testgate ausgenommen.
6. **`MAX_BLOCKS=10` ist beliebig wiederholbar**, weil der Zähler beim
   Auslösen gelöscht wird; die Warnung erreicht im `/goal`-Modus keinen
   Menschen. `stop_hook_active` wird gelesen und nie verwendet.
7. **`guard.sh` prüft den rohen Kommandostring, nicht die Absicht.** Er
   blockte im Review zweimal an bloßen Erwähnungen verbotener Befehle im
   Argumenttext — dieselbe Fehlerklasse, die `track.sh` für Testkommandos
   bereits behoben hat. Ein dritter Fall trat beim Schreiben genau dieses
   Abschnitts auf: Der Versuch, den Befund über ein Bash-Heredoc zu
   dokumentieren, wurde geblockt, weil der beschriebene Schalter im
   Fließtext vorkam. Umgekehrt ist der Guard umgehbar über
   Quote-Splitting, die Kurzform desselben Schalters, `core.hooksPath`
   oder Secret-Zugriff per `python3`/`cp`. Er ist eine Gedächtnisstütze,
   keine Sicherheitsgrenze — und ab jetzt sind seine Regeln öffentlich
   lesbar.
8. **Die Gate-Skripte haben null CI-Deckung** (kein `test-hooks.sh`-Aufruf,
   kein Shellcheck). Der sicherheitskritischste Code im Repo ist der
   ungeprüfteste.
9. **`external-reviewer.md` nennt interne Routing-Details** (Provider,
   Modellnamen, Logpfad). Kein Secret, aber ohne Nutzen für Außenstehende.

Ebenfalls notiert, kleiner: Der Branchname dieses Commits trägt keine
Item-ID, weshalb `worklog.sh` für diese Lane `item: "n/a"` protokolliert —
die Datenquelle des Controllers läuft hier leer. Und `verdict.sh` committet
mit `[gate] …` statt `[ITEM-ID] …`, verletzt also die Konvention, die
`guard.sh` allen anderen aufzwingt.
