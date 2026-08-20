#!/usr/bin/env bash
# PostToolUse-Tracker: protokolliert Code-Aenderungen und Testlaeufe.
# Das Stop-Gate wertet die Marker spaeter aus.
#
# Zum Testlauf wird nicht nur der Zeitpunkt festgehalten, sondern das
# ERGEBNIS. Grund (DATENSCHLE-55): Frueher genuegte es, dass der
# Kommandostring nach einem Testbefehl aussah — ein rot gelaufener Test
# setzte denselben Marker wie ein gruener und passierte das Gate.
#
# Warum wird das Ergebnis aus der Ausgabe gelesen und nicht aus dem
# Exit-Code? Weil es keinen gibt: Der PostToolUse-Payload liefert fuer
# Bash nur stdout, stderr, interrupted, isImage und noOutputExpected —
# empirisch verifiziert, kein Exit-Code-Feld. Erschwerend feuert
# PostToolUse bei einem Kommando mit Exit != 0 gar nicht erst. Genau
# deshalb rutschen rote Laeufe durch, sobald jemand die Ausgabe pipet
# (z.B. "pytest ... | tail -40" endet mit Exit 0). Die Zusammenfassungs-
# zeile der Test-Runner ist die verlaessliche Quelle.

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // empty')
CWD=$(echo "$INPUT" | jq -r '.cwd // empty')

# Marker gehoeren dem Arbeitsverzeichnis, aus dem sie stammen. Sonst
# bewertet das Stop-Gate fremde Lanes als eigene (DATENSCHLE-79).
# shellcheck source=scope.sh
# Fehlt der Helfer (unvollstaendig kopierte Hooks), faellt die Zuordnung auf
# den gemeinsamen Marker zurueck. Das ist die alte, laute Variante -- aber
# scharf. Ohne diesen Zweig waere der Markerpfad leer, das Gate faende nichts
# und wuerde lautlos jede Session durchwinken.
if . "$(dirname "${BASH_SOURCE[0]}")/scope.sh" 2>/dev/null \
   && command -v marker_dir >/dev/null 2>&1 \
   && DIR=$(marker_dir "${CLAUDE_PROJECT_DIR:-.}/.claude" "$CWD"); then
  :
else
  DIR="${CLAUDE_PROJECT_DIR:-.}/.claude"
  mkdir -p "$DIR"
fi

# Bewertet die Ausgabe eines Testlaufs: pass | fail | unknown
# Fail-Signale haben immer Vorrang. Wer kein eindeutiges Erfolgssignal
# liefert, gilt nicht als gruen — kein Beweis ist kein Bestehen.
#
# Ausgewertet wird ausschliesslich die ZUSAMMENFASSUNGSZEILE des Runners,
# nicht die ganze Ausgabe. Ueber alles zu greppen war nachweislich falsch:
# Testnamen und Logzeilen enthalten dieselben Vokabeln ("1 failed",
# "2 errors") und kippten gruene Laeufe auf rot. Gefunden wird die letzte
# Zeile, die wie eine Runner-Zusammenfassung aussieht; nur sie entscheidet.
SUMMARY_RE='^OK([[:space:]]|\(|$)|^FAILED\b|^ERROR\b|^FAIL |^=+.*(passed|failed|error|no tests ran)|^Tests:|^[0-9]+ (passed|failed|error)|^Ran 0 tests|INTERNALERROR'

classify_test_output() {
  local summary
  # ANSI-Farbcodes entfernen, sonst scheitert die Verankerung am Zeilenanfang.
  summary=$(printf '%s' "$1" | sed 's/\x1b\[[0-9;]*m//g' | grep -E "$SUMMARY_RE" | tail -1)

  # Kein Runner-Fazit in der Ausgabe -> nichts bewiesen.
  [ -z "$summary" ] && { echo unknown; return; }

  # --- Fail-Signale -----------------------------------------------------
  # unittest "FAILED (errors=4)" | pytest "ERROR test_x.py" | jest "FAIL src/x"
  if echo "$summary" | grep -qE '^FAILED\b|^ERROR\b|^FAIL |no tests ran|^Ran 0 tests|INTERNALERROR'; then
    echo fail; return
  fi
  # pytest "=== 1 failed, 4 passed ===" | jest "Tests: 2 failed, 5 passed"
  if echo "$summary" | grep -qE '(^|[[:space:]=,])[1-9][0-9]* (failed|error|errors)\b'; then
    echo fail; return
  fi

  # --- Pass-Signale -----------------------------------------------------
  # unittest: "OK" / "OK (skipped=2)"   pytest & jest: "N passed"
  if echo "$summary" | grep -qE '^OK\b|(^|[[:space:]=,])[1-9][0-9]* passed\b'; then
    echo pass; return
  fi

  echo unknown
}

case "$TOOL" in
  Edit|Write|MultiEdit)
    FILE=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')
    # Nur echte Quellcode-Aenderungen zaehlen (nicht Doku/Configs)
    if echo "$FILE" | grep -qE '\.(ts|tsx|js|jsx|py|go|rs|swift|kt)$'; then
      touch "$DIR/.last_code_edit"
    fi
    ;;
  Bash)
    CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
    if echo "$CMD" | grep -qE '(npm (run )?test|yarn test|pnpm test|vitest|jest|maestro test|pytest|unittest|test-hooks\.sh)'; then
      STDOUT=$(echo "$INPUT" | jq -r '.tool_response.stdout // ""')
      STDERR=$(echo "$INPUT" | jq -r '.tool_response.stderr // ""')
      INTERRUPTED=$(echo "$INPUT" | jq -r '.tool_response.interrupted // false')

      if [ "$INTERRUPTED" = "true" ]; then
        STATUS=fail
      else
        STATUS=$(classify_test_output "$(printf '%s\n%s' "$STDOUT" "$STDERR")")
      fi

      # Ohne Runner-Fazit wird der Marker NICHT angefasst. Das Kommando-
      # muster trifft naemlich auch auf blosse Erwaehnungen zu — ein
      # "shellcheck ... test-hooks.sh" oder "grep pytest datei" ist kein
      # Testlauf. Frueher war das harmlos, heute wuerde es einen gueltigen
      # gruenen Nachweis entwerten und fremde Lanes grundlos blockieren.
      # Ein echter Lauf ohne sichtbares Fazit beweist ohnehin nichts: Der
      # Marker bleibt dann alt und die Zeitpruefung im Gate greift.
      [ "$STATUS" = "unknown" ] && exit 0

      # Beweisstueck fuer das Stop-Gate: Ergebnis, Kommando und der
      # Commit-Stand, auf dem der Lauf stattfand.
      # Der Stand, auf dem der Lauf WIRKLICH stattfand: der des Worktrees.
      # Vorher stand hier CLAUDE_PROJECT_DIR -- also der HEAD der
      # Hauptauscheckung. In einem Worktree auf anderem Stand nannte die
      # Blockmeldung damit einen Commit, den der Testlauf nie beruehrt hat.
      SHA=$(git -C "${CWD:-${CLAUDE_PROJECT_DIR:-.}}" rev-parse HEAD 2>/dev/null || echo unknown)
      jq -nc --arg s "$STATUS" --arg c "$CMD" --arg sha "$SHA" \
             --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
             --arg ev "$(printf '%s\n%s' "$STDOUT" "$STDERR" | tail -c 400)" \
        '{status:$s, cmd:$c, sha:$sha, ts:$ts, evidence:$ev}' \
        > "$DIR/.last_test_run"
    fi
    ;;
esac

exit 0
