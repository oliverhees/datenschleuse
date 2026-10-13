#!/usr/bin/env bash
# PreToolUse-Guard: prüft jeden Bash-Befehl BEVOR er ausgeführt wird.
# Exit 0 = erlaubt | Exit 2 = geblockt (stderr geht als Begründung an Claude)

INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

[ -z "$CMD" ] && exit 0

block() {
  LOG="${CLAUDE_PROJECT_DIR:-.}/.claude/hooklog.jsonl"
  SAFE_CMD=$(echo "$CMD" | head -c 200 | tr '"' "'" | tr '\n' ' ')
  echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"hook\":\"guard\",\"reason\":\"$1\",\"cmd\":\"$SAFE_CMD\"}" >> "$LOG" 2>/dev/null || true
  echo "🚫 GEBLOCKT (Verfassung): $1" >&2
  exit 2
}

# --- Gesetz 4: Git-Disziplin ---------------------------------------------
echo "$CMD" | grep -qE 'git push [^|;&]*\b(main|master)\b' && \
  block "Kein direkter Push auf main/master. Erstelle einen PR."

echo "$CMD" | grep -qE 'git push [^|;&]*(--force|-f)\b' && \
  block "Force-Push ist verboten."

echo "$CMD" | grep -qE '\-\-no-verify' && \
  block "--no-verify umgeht die Leitplanken. Behebe stattdessen die Ursache."

echo "$CMD" | grep -qE 'git reset --hard [^|;&]*origin/(main|master)' && \
  block "Hard-Reset auf origin/main ist verboten."

# --- Gesetz 1: Plane statt GitHub Issues ---------------------------------
echo "$CMD" | grep -qE 'gh issue (create|comment|edit|close)' && \
  block "GitHub Issues laufen über Plane + Sync-Worker. Nutze den Plane MCP."

# --- Gesetz 1: Commit ohne Work-Item-ID ----------------------------------
if echo "$CMD" | grep -qE 'git commit' && echo "$CMD" | grep -qE '\-m'; then
  echo "$CMD" | grep -qE '\[[A-Za-z]+-[0-9]+\]' || \
    block "Commit-Message ohne Plane-ID. Format: [PROJ-123] deine message"
fi

# --- Gesetz 5: Secrets ----------------------------------------------------
echo "$CMD" | grep -qE '(cat|less|more|head|tail|grep|echo)[^|;&]*(\.env(\.[a-z]+)?|id_rsa|\.pem|credentials)\b' && \
  block "Zugriff auf Secret-Dateien ist verboten."

# --- Destruktives ---------------------------------------------------------
echo "$CMD" | grep -qE 'rm -rf?\s+(/|~|\$HOME|\.\.)(\s|$)' && \
  block "Destruktiver Lösch-Befehl außerhalb des Projekts."

echo "$CMD" | grep -qiE 'drop (table|database|schema)' && \
  block "DROP-Statements laufen nur über Migrations mit Review."

exit 0
