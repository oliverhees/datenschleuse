#!/usr/bin/env bash
# Laufzettel-Gate (methoden.md #3): prueft die SHA-gepinnten Verdicts unter .gates/.
#
# Bis DATENSCHLE-76 lag diese Logik als Shell-Block inline in ci.yml. Sie war
# damit nicht ausfuehrbar ohne GitHub Actions und deshalb auch nie getestet --
# eine der Ursachen dafuer, dass sich am Gate-System an einem Tag fuenf Befunde
# angesammelt haben. Als eigene Datei ist sie aus test/test_gates_laufzettel.py
# gegen synthetische Repos ausfuehrbar.
#
# Erwartete Umgebung:
#   BASE_REF  Ziel-Branch des PRs (z. B. "main")
# Aufruf aus dem Repo-Root.

set -euo pipefail

BASE="origin/$BASE_REF"
git fetch origin "$BASE_REF" --depth=200

CODE_CHANGED=$(git diff --name-only "$BASE"...HEAD -- . ':(exclude).gates' ':(exclude)docs' ':(exclude)*.md' | wc -l)
if [ "$CODE_CHANGED" -eq 0 ]; then
  echo "Nur Doku/Gates geaendert — keine Verdicts noetig. ✅"
  exit 0
fi

UI_CHANGED=$(git diff --name-only "$BASE"...HEAD | grep -E '\.(tsx|jsx)$|styles?/' | wc -l || true)
REQUIRED="security qa"
[ "$UI_CHANGED" -gt 0 ] && REQUIRED="$REQUIRED ux"

FAIL=0
for GATE in $REQUIRED; do
  FILE=".gates/$GATE.json"
  if [ ! -f "$FILE" ]; then
    echo "❌ Verdict fehlt: $GATE"; FAIL=1; continue
  fi
  VERDICT=$(python3 -c "import json;print(json.load(open('$FILE'))['verdict'])")
  PINNED=$(python3 -c "import json;print(json.load(open('$FILE'))['commit'])")
  if [ "$VERDICT" != "pass" ]; then
    echo "❌ $GATE: Verdict ist '$VERDICT'"; FAIL=1; continue
  fi
  STALE=$(git rev-list "$PINNED"..HEAD -- . ':(exclude).gates' | wc -l)
  if [ "$STALE" -gt 0 ]; then
    echo "❌ $GATE: $STALE Code-Commit(s) NACH dem Audit (gepinnt: ${PINNED:0:8}) — erneutes Audit noetig."
    FAIL=1
  else
    echo "✅ $GATE: pass @ ${PINNED:0:8} (frisch)"
  fi
done
exit $FAIL
