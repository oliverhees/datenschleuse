#!/usr/bin/env bash
# Laufzettel-Gate (methoden.md #3): prueft die SHA-gepinnten Verdicts unter .gates/.
#
# Frage, die dieser Check beantwortet:
#   "Ist der Stand, der gleich gemergt wird, inhaltlich derselbe, den die
#    Auditoren gesehen haben?"
#
# Das ist eine Frage nach INHALT, nicht nach der Anzahl von Commits. Bis
# DATENSCHLE-76 zaehlte der Check Commits (`git rev-list PINNED..HEAD`) und
# hat damit zwei Dinge mitgezaehlt, die nicht zum PR gehoeren:
#
#   1. den Probe-Merge refs/pull/N/merge. Bei `pull_request` checkt
#      actions/checkout nicht die Branch-Spitze aus, sondern einen von GitHub
#      fabrizierten Merge aus (main-Spitze, PR-Spitze). Diesen Commit hat
#      niemand geschrieben, er steht nicht im PR und er ueberlebt den Merge
#      nicht -- ein CI-Artefakt als "Code-Commit" zu zaehlen war schlicht falsch.
#
#   2. jeden fremden Commit, der nach dem Audit auf main landet. Bei fuenf
#      parallelen Lanes entwertet damit jeder fremde Merge alle offenen
#      Audits. Ein Gate, das strukturell immer rot ist, schuetzt nichts --
#      es wird uebergangen, und genau das ist passiert.
#
# Ob der gemergte Stand nach fremden Aenderungen auf main noch sicher ist,
# ist eine andere Frage. Ihr Instrument ist die Ruleset-Regel "Require
# branches to be up to date before merging" (DATENSCHLE-61): die erzwingt
# einen Rebase/Merge von main in den PR -- und der veraendert den Inhalt des
# PRs, was dieser Check dann korrekt als "Audit veraltet" meldet. Die beiden
# Mechanismen greifen ineinander; dieser hier darf die Frage nicht doppeln.
#
# Erwartete Umgebung:
#   BASE_REF     Ziel-Branch des PRs (z. B. "main")
#   PR_HEAD_SHA  Spitze des PR-Branches (github.event.pull_request.head.sha)
# Aufruf aus dem Repo-Root.

set -euo pipefail

BASE="origin/$BASE_REF"
# Bewusst OHNE --depth: ein 'git fetch --depth=N' macht ein vollstaendiges
# Repo nachtraeglich shallow. An der Shallow-Grenze verliert git die
# Elterninformation -- und genau davon haengen die Vorfahren- und
# Inhaltsvergleiche unten ab. Der Job checkt mit fetch-depth: 0 aus, die
# Historie ist also ohnehin vollstaendig da.
git fetch origin "$BASE_REF"

# --- PR-Spitze statt HEAD. Fail-closed, wenn sie fehlt. ---------------------
PR_HEAD="${PR_HEAD_SHA:-}"
if [ -z "$PR_HEAD" ]; then
  echo "❌ PR_HEAD_SHA ist nicht gesetzt. Ohne die echte PR-Spitze waere HEAD"
  echo "   der Probe-Merge von GitHub — darauf wird nicht geurteilt."
  exit 1
fi
if ! git cat-file -e "${PR_HEAD}^{commit}" 2>/dev/null; then
  echo "❌ PR-Spitze ${PR_HEAD:0:8} liegt nicht im Repo (fetch-depth: 0 noetig)."
  exit 1
fi

# Der Doku-Ausschluss ist INHALTSBASIERT, nicht pfadbasiert (DATENSCHLE-76).
#
# Bis dahin stand hier ':(exclude)docs' ':(exclude)*.md'. Beides war zu weit:
#   - ':(exclude)docs' schloss den GESAMTEN Teilbaum aus -- jeden Dateityp,
#     nicht nur Markdown.
#   - ':(exclude)*.md' griff repoweit auf jeder Tiefe, weil git-Pathspecs
#     ohne :(glob) ihr '*' auch ueber '/' matchen lassen.
# Damit waren docs/scripts/evil.py und litellm/sneaky.md fuer diesen Zaehler
# unsichtbar: der Check meldete "nur Doku" und las die Verdicts nie.
#
# Die Regel lautet jetzt: Doku ist *.md in der Repo-WURZEL und *.md unterhalb
# von docs/ (beliebig tief). Sonst nichts. Kein Dateityp ausser .md, kein
# anderer Ort. Das ':(glob)'-Magic ist noetig, damit '*' an '/' haltmacht.
#
# Gedeckt durch die Historie: alle Doku-only-Commits dieses Repos fallen in
# genau diese zwei Formen. Der engere Filter kostet also keinen realen
# Doku-PR. Wo er doch einmal zu streng ist -- etwa bei einem Bild unter
# docs/assets/ -- verlangt er ein Audit statt eines durchzulassen. Ein Gate,
# das falsch blockt, kostet eine Runde; eines, das falsch durchlaesst,
# kostet die Zusage.
#
# Gleiches Muster bei .gates: dort liegen ausschliesslich Verdicts. Ein
# ':(exclude).gates' haette ein '.gates/evil.py' mit ausgeblendet, also wird
# hier -- und beim Inhaltsvergleich unten -- nur '*.json' ausgenommen.
CODE_CHANGED=$(git diff --name-only "$BASE"..."$PR_HEAD" -- . \
  ':(exclude,glob).gates/*.json' \
  ':(exclude,glob)docs/**/*.md' \
  ':(exclude,glob)*.md' | wc -l)
if [ "$CODE_CHANGED" -eq 0 ]; then
  echo "Nur Doku/Gates geaendert — keine Verdicts noetig. ✅"
  exit 0
fi

UI_CHANGED=$(git diff --name-only "$BASE"..."$PR_HEAD" | grep -E '\.(tsx|jsx)$|styles?/' | wc -l || true)
REQUIRED="security qa"
[ "$UI_CHANGED" -gt 0 ] && REQUIRED="$REQUIRED ux"

FAIL=0
for GATE in $REQUIRED; do
  FILE=".gates/$GATE.json"
  if [ ! -f "$FILE" ]; then
    echo "❌ Verdict fehlt: $GATE"; FAIL=1; continue
  fi
  # Ein unlesbares Verdict ist kein Verdict. Fail-closed war es vorher schon
  # (set -e brach ab), aber als roher Python-Traceback -- das passt nicht zum
  # Meldungsstil der uebrigen Faelle und verschweigt, welches Gate klemmt.
  if ! META=$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
print(d["verdict"])
print(d["commit"])
' "$FILE" 2>/dev/null); then
    echo "❌ $GATE: $FILE ist kein lesbares Verdict (kaputtes JSON oder Feld fehlt) — erneutes Audit noetig."
    FAIL=1; continue
  fi
  VERDICT=$(printf '%s\n' "$META" | sed -n 1p)
  PINNED=$(printf '%s\n' "$META" | sed -n 2p)
  if [ "$VERDICT" != "pass" ]; then
    echo "❌ $GATE: Verdict ist '$VERDICT'"; FAIL=1; continue
  fi

  # Fail-closed: ein Verdict, dessen gepinnter Commit nicht existiert oder
  # nicht im PR liegt, ist kein Verdict. Nach einem Rebase ist das der
  # Normalfall — dann muss neu auditiert werden.
  if ! git cat-file -e "${PINNED}^{commit}" 2>/dev/null; then
    echo "❌ $GATE: gepinnter Commit ${PINNED:0:8} existiert nicht — erneutes Audit noetig."
    FAIL=1; continue
  fi
  if ! git merge-base --is-ancestor "$PINNED" "$PR_HEAD" 2>/dev/null; then
    echo "❌ $GATE: gepinnter Commit ${PINNED:0:8} liegt nicht im PR (Rebase?) — erneutes Audit noetig."
    FAIL=1; continue
  fi

  # Der eigentliche Test: Inhaltsvergleich auditierter Stand <-> PR-Spitze,
  # .gates/ ausgenommen. Ein Commit, der .gates UND Code aendert, faellt hier
  # auf — der Vergleich sieht Inhalt, nicht die Form der Commits. Damit gibt
  # es keine Tarnung als Gate-Commit.
  GEAENDERT=$(git diff --name-only "$PINNED" "$PR_HEAD" -- . ':(exclude,glob).gates/*.json')
  if [ -n "$GEAENDERT" ]; then
    ANZAHL=$(printf '%s\n' "$GEAENDERT" | wc -l)
    echo "❌ $GATE: $ANZAHL Datei(en) seit dem Audit geaendert (gepinnt: ${PINNED:0:8}) — erneutes Audit noetig."
    printf '%s\n' "$GEAENDERT" | sed 's/^/     /'
    FAIL=1
  else
    echo "✅ $GATE: pass @ ${PINNED:0:8} (frisch)"
  fi
done
exit $FAIL
