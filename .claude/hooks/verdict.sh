#!/usr/bin/env bash
# Laufzettel (methoden.md #3): schreibt ein SHA-gepinntes Gate-Verdict.
# Nutzung: verdict.sh <gate> <pass|fail>   (gate: security | qa | ux)
# Jeder neue Commit macht bestehende Verdicts automatisch ungültig,
# weil die CI den gepinnten SHA gegen den PR-HEAD prüft.

set -euo pipefail

GATE="${1:-}"
VERDICT="${2:-}"

case "$GATE" in security|qa|ux) ;; *)
  echo "Unbekanntes Gate: '$GATE' (erlaubt: security, qa, ux)" >&2; exit 1;;
esac
case "$VERDICT" in pass|fail) ;; *)
  echo "Verdict muss 'pass' oder 'fail' sein." >&2; exit 1;;
esac

ROOT=$(git rev-parse --show-toplevel)
SHA=$(git rev-parse HEAD)
BRANCH=$(git rev-parse --abbrev-ref HEAD)

if git status --porcelain | grep -qv '^?? .gates/'; then
  echo "ABBRUCH: Es gibt uncommittete Aenderungen. Ein Verdict gilt nur" >&2
  echo "fuer einen committeten Stand — erst committen, dann urteilen." >&2
  exit 1
fi

mkdir -p "$ROOT/.gates"
cat > "$ROOT/.gates/$GATE.json" <<EOF
{
  "gate": "$GATE",
  "verdict": "$VERDICT",
  "commit": "$SHA",
  "branch": "$BRANCH",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

cd "$ROOT"
git add .gates/"$GATE".json
git commit -m "[gate] $GATE: $VERDICT @ ${SHA:0:8}" --only .gates/"$GATE".json > /dev/null

echo "Verdict geschrieben: $GATE = $VERDICT (gepinnt an ${SHA:0:8})"
