#!/usr/bin/env bash
# Betriebsdatenerfassung (methoden.md #16): protokolliert Session-
# Ereignisse mit Branch und Item-ID für die Zeit-Auswertung durch
# den Controller.

INPUT=$(cat)
EVENT=$(echo "$INPUT" | jq -r '.hook_event_name // "unknown"')
SOURCE=$(echo "$INPUT" | jq -r '.source // ""')

DIR="${CLAUDE_PROJECT_DIR:-.}"
LOG="$DIR/.claude/worklog.jsonl"
mkdir -p "$DIR/.claude"

BRANCH=$(git -C "$DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "n/a")
ITEM=$(echo "$BRANCH" | grep -oE '[A-Za-z]+-[0-9]+' | head -1 || true)
[ -z "$ITEM" ] && ITEM="n/a"

echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"event\":\"$EVENT\",\"source\":\"$SOURCE\",\"branch\":\"$BRANCH\",\"item\":\"$ITEM\"}" >> "$LOG"

exit 0
