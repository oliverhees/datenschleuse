#!/usr/bin/env bash
# Testsuite fuer die Verfassungs-Hooks (Gesetz 2: kein Code ohne Test).
#
# Getestet werden die ECHTEN Skripte track.sh und stop-gate.sh, jeweils in
# einem isolierten CLAUDE_PROJECT_DIR unter /tmp. Die Live-Umgebung des
# Projekts wird dabei nicht angefasst.
#
# Aufruf:  .claude/hooks/test-hooks.sh
# Exit 0 = alle Faelle gruen | Exit 1 = mindestens ein Fall rot

HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRACK="$HOOKS_DIR/track.sh"
STOP_GATE="$HOOKS_DIR/stop-gate.sh"

# Marker liegen seit DATENSCHLE-79 pro Arbeitsverzeichnis. Der Pfad wird
# hier mit DERSELBEN Funktion gebildet wie in den Hooks -- eine eigene
# Nachbildung wuerde beim naechsten Schluesselwechsel lautlos daneben
# greifen und die Suite gruen faerben, obwohl sie nichts mehr prueft.
# shellcheck source=scope.sh
. "$HOOKS_DIR/scope.sh"

# mdir <sandbox> -> Markerverzeichnis dieser Sandbox
mdir() { marker_dir "$1/.claude" "$1"; }

PASSED=0
FAILED=0

# --- Testinfrastruktur ----------------------------------------------------

# Legt ein frisches, isoliertes Projektverzeichnis an und gibt den Pfad aus.
new_sandbox() {
  local dir
  dir=$(mktemp -d "${TMPDIR:-/tmp}/hooktest.XXXXXXXX")
  mkdir -p "$dir/.claude"
  echo "$dir"
}

# Baut einen PostToolUse-Payload fuer das Bash-Tool.
# Wichtig: tool_response hat nachweislich KEINEN Exit-Code, nur
# stdout/stderr/interrupted. Genau das bildet dieser Payload ab.
bash_payload() {
  local cmd="$1" stdout="$2" stderr="${3:-}" interrupted="${4:-false}"
  jq -nc --arg cmd "$cmd" --arg out "$stdout" --arg err "$stderr" \
        --argjson intr "$interrupted" --arg cwd "${S:-$PWD}" \
    '{tool_name:"Bash", hook_event_name:"PostToolUse", cwd:$cwd,
      tool_input:{command:$cmd},
      tool_response:{stdout:$out, stderr:$err, interrupted:$intr,
                     isImage:false, noOutputExpected:false}}'
}

edit_payload() {
  local file="$1"
  jq -nc --arg f "$file" --arg cwd "${S:-$PWD}" \
    '{tool_name:"Edit", hook_event_name:"PostToolUse", cwd:$cwd,
      tool_input:{file_path:$f}, tool_response:{}}'
}

stop_payload() {
  local active="${1:-false}"
  jq -nc --argjson a "$active" --arg cwd "${S:-$PWD}" \
    '{hook_event_name:"Stop", cwd:$cwd, stop_hook_active:$a}'
}

ok()   { PASSED=$((PASSED+1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { FAILED=$((FAILED+1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }

assert_eq() { # <erwartet> <ist> <beschreibung>
  if [ "$1" = "$2" ]; then ok "$3"; else bad "$3 (erwartet '$1', war '$2')"; fi
}

# Fuehrt track.sh mit einem Payload aus und gibt den ermittelten Status zurueck.
# Ausgabe: "pass" | "fail" | "unknown" | "KEIN_MARKER" | "LEER"
track_status() {
  local sandbox="$1" payload="$2"
  echo "$payload" | CLAUDE_PROJECT_DIR="$sandbox" bash "$TRACK" >/dev/null 2>&1
  local marker; marker="$(mdir "$sandbox")/.last_test_run"
  [ ! -f "$marker" ] && { echo "KEIN_MARKER"; return; }
  [ ! -s "$marker" ] && { echo "LEER"; return; }
  jq -r '.status // "KEIN_STATUSFELD"' "$marker" 2>/dev/null || echo "KEIN_JSON"
}

# Fuehrt stop-gate.sh aus und gibt den Exit-Code zurueck (0 = darf stoppen).
gate_exit() {
  local sandbox="$1" active="${2:-false}"
  stop_payload "$active" | CLAUDE_PROJECT_DIR="$sandbox" bash "$STOP_GATE" >/dev/null 2>&1
  echo $?
}

# --- Realer Defektbeweis --------------------------------------------------
# Wortlaut eines echten, ROT gelaufenen Testlaufs aus dieser Codebase.
# Durch "| tail -40" endet die Pipeline mit Exit 0 — deshalb reicht der
# Kommandostring als Nachweis niemals aus.
REAL_RED_CMD='python3 -m unittest discover -s ./test -p "test_custom_rules.py" 2>&1 | tail -40'
REAL_RED_OUT='datenschleuse_guardrail.DatenschleuseBlocked: Presidio Analyzer nicht erreichbar

----------------------------------------------------------------------
Ran 36 tests in 0.513s

FAILED (errors=4)'

echo
echo "=== track.sh — Ergebnis eines Testlaufs korrekt erfassen ==="

S=$(new_sandbox)
assert_eq "fail" "$(track_status "$S" "$(bash_payload "$REAL_RED_CMD" "$REAL_RED_OUT")")" \
  "Realer roter unittest-Lauf (FAILED (errors=4)) wird als fail erfasst"

S=$(new_sandbox)
assert_eq "pass" "$(track_status "$S" "$(bash_payload \
  'python3 -m unittest discover -s ./test' $'Ran 36 tests in 0.421s\n\nOK')")" \
  "Gruener unittest-Lauf (OK) wird als pass erfasst"

S=$(new_sandbox)
assert_eq "pass" "$(track_status "$S" "$(bash_payload \
  'python3 -m unittest discover -s ./test' $'Ran 8 tests in 0.1s\n\nOK (skipped=2)')")" \
  "unittest OK mit skipped zaehlt als pass"

S=$(new_sandbox)
assert_eq "fail" "$(track_status "$S" "$(bash_payload \
  'pytest test/' '=========== 1 failed, 4 passed in 0.12s ============')")" \
  "pytest mit 1 failed wird als fail erfasst"

S=$(new_sandbox)
assert_eq "pass" "$(track_status "$S" "$(bash_payload \
  'pytest test/' '=========== 5 passed in 0.12s ============')")" \
  "pytest mit 5 passed wird als pass erfasst"

S=$(new_sandbox)
assert_eq "fail" "$(track_status "$S" "$(bash_payload \
  'pytest test/' '=========== 2 errors in 0.3s ============')")" \
  "pytest mit errors wird als fail erfasst"

S=$(new_sandbox)
assert_eq "fail" "$(track_status "$S" "$(bash_payload \
  'pytest test/' '=========== no tests ran in 0.01s ============')")" \
  "Kein einziger gelaufener Test ist kein Beweis (no tests ran = fail)"

S=$(new_sandbox)
assert_eq "KEIN_MARKER" "$(track_status "$S" "$(bash_payload \
  'python3 -m unittest discover -s ./test -v 2>&1 | grep -c "ok$"' '18')")" \
  "Lauf ohne auswertbare Zusammenfassung gilt nicht als Nachweis"

# Regression: Kommandos, die ein Testskript nur ERWAEHNEN (shellcheck, grep,
# ls), sind keine Testlaeufe. Real aufgetreten: ein shellcheck-Aufruf mit
# "test-hooks.sh" im Argument entwertete einen gueltigen gruenen Marker.
S=$(new_sandbox)
echo '{"status":"pass","cmd":"frueherer gruener Lauf"}' > "$(mdir "$S")/.last_test_run"
assert_eq "pass" "$(track_status "$S" "$(bash_payload \
  'shellcheck -S warning .claude/hooks/track.sh .claude/hooks/test-hooks.sh' \
  '  shellcheck nicht installiert')")" \
  "Blosse Erwaehnung eines Testskripts entwertet einen gruenen Marker nicht"

# Ein echtes rotes Ergebnis ueberschreibt einen gruenen Marker sehr wohl.
S=$(new_sandbox)
echo '{"status":"pass","cmd":"frueherer gruener Lauf"}' > "$(mdir "$S")/.last_test_run"
assert_eq "fail" "$(track_status "$S" "$(bash_payload 'pytest test/' \
  '=========== 1 failed, 4 passed in 0.12s ============')")" \
  "Roter Lauf ueberschreibt einen vorher gruenen Marker"

S=$(new_sandbox)
assert_eq "fail" "$(track_status "$S" "$(bash_payload \
  'pytest test/' 'Ran 3 tests' '' 'true')")" \
  "Abgebrochener Testlauf (interrupted) ist fail"

S=$(new_sandbox)
assert_eq "KEIN_MARKER" "$(track_status "$S" "$(bash_payload 'ls -la' 'a b c')")" \
  "Nicht-Testkommando legt gar keinen Testlauf-Marker an"

S=$(new_sandbox)
assert_eq "fail" "$(track_status "$S" "$(bash_payload \
  'npx jest' 'Tests:       2 failed, 5 passed, 7 total')")" \
  "jest mit failed wird als fail erfasst"

S=$(new_sandbox)
assert_eq "pass" "$(track_status "$S" "$(bash_payload \
  'npx jest' 'Tests:       7 passed, 7 total')")" \
  "jest komplett gruen wird als pass erfasst"

# Regression: Ein gruener Lauf, dessen Protokoll weiter oben Fail-Vokabular
# enthaelt (Testnamen, Logzeilen), darf nicht als rot gewertet werden.
# Real aufgetreten: diese Suite selbst enthaelt die Zeile "1 failed" als
# Testbeschreibung und kippte damit ihr eigenes gruenes Ergebnis.
S=$(new_sandbox)
assert_eq "pass" "$(track_status "$S" "$(bash_payload 'pytest test/' \
  $'PASS  pytest mit 1 failed wird als fail erfasst\nPASS  2 errors werden erkannt\ncollecting ...\n=========== 12 passed in 0.31s ============')")" \
  "Fail-Vokabular im Protokoll kippt einen gruenen Lauf nicht"

# Gegenprobe: Das Ergebnis am Ende zaehlt, auch wenn oben "passed" steht.
S=$(new_sandbox)
assert_eq "fail" "$(track_status "$S" "$(bash_payload 'pytest test/' \
  $'test_a.py .... 4 passed so far\nRan 36 tests in 0.5s\n\nFAILED (errors=4)')")" \
  "Zusammenfassung am Ende schlaegt frueheres passed-Vokabular"

echo
echo "=== stop-gate.sh — nur ein gruener Lauf oeffnet das Gate ==="

S=$(new_sandbox)
assert_eq "0" "$(gate_exit "$S")" \
  "Ohne Code-Aenderung darf gestoppt werden"

S=$(new_sandbox); touch "$(mdir "$S")/.last_code_edit"
assert_eq "2" "$(gate_exit "$S")" \
  "Code geaendert, nie getestet -> Stop abgelehnt"

S=$(new_sandbox); touch "$(mdir "$S")/.last_code_edit"
: > "$(mdir "$S")/.last_test_run"        # Legacy: 0-Byte-Marker ohne Ergebnis
assert_eq "2" "$(gate_exit "$S")" \
  "Legacy-Marker ohne Ergebnis gilt nicht als gruen -> Stop abgelehnt"

S=$(new_sandbox); touch "$(mdir "$S")/.last_code_edit"
echo '{"status":"fail"}' > "$(mdir "$S")/.last_test_run"
assert_eq "2" "$(gate_exit "$S")" \
  "ROTER Testlauf -> Stop abgelehnt (Kernanforderung DATENSCHLE-55)"

S=$(new_sandbox); touch "$(mdir "$S")/.last_code_edit"
echo '{"status":"unknown"}' > "$(mdir "$S")/.last_test_run"
assert_eq "2" "$(gate_exit "$S")" \
  "Unklares Testergebnis -> Stop abgelehnt"

S=$(new_sandbox); touch "$(mdir "$S")/.last_code_edit"
sleep 0.01; echo '{"status":"pass"}' > "$(mdir "$S")/.last_test_run"
assert_eq "0" "$(gate_exit "$S")" \
  "GRUENER Testlauf nach Code-Aenderung -> Stop erlaubt, keine Reibung"

S=$(new_sandbox)
echo '{"status":"pass"}' > "$(mdir "$S")/.last_test_run"
sleep 0.01; touch "$(mdir "$S")/.last_code_edit"   # Edit NACH dem Testlauf
assert_eq "2" "$(gate_exit "$S")" \
  "Code-Aenderung nach gruenem Lauf entwertet ihn -> Stop abgelehnt"

echo
echo "=== stop-gate.sh — Bypass ueber stop_hook_active ist geschlossen ==="

S=$(new_sandbox); touch "$(mdir "$S")/.last_code_edit"
echo '{"status":"fail"}' > "$(mdir "$S")/.last_test_run"
assert_eq "2" "$(gate_exit "$S" "true")" \
  "Roter Lauf bleibt auch bei stop_hook_active=true abgelehnt"

S=$(new_sandbox); touch "$(mdir "$S")/.last_code_edit"
sleep 0.01; echo '{"status":"pass"}' > "$(mdir "$S")/.last_test_run"
assert_eq "0" "$(gate_exit "$S" "true")" \
  "Gruener Lauf passiert auch bei stop_hook_active=true"

# Terminierungsgarantie: Das Gate darf den Agenten nicht endlos festhalten.
S=$(new_sandbox); touch "$(mdir "$S")/.last_code_edit"
echo '{"status":"fail"}' > "$(mdir "$S")/.last_test_run"
# Geprueft wird, DASS innerhalb begrenzt vieler Versuche freigegeben wird.
# Frueher stand hier "der 12. Versuch ist 0" -- das galt nur, weil der
# Zaehler nach dem Ausloesen voll stehen blieb und die Lane damit DAUERHAFT
# offen war (Fail-Open, gefunden im externen Review zu DATENSCHLE-79). Die
# Notbremse raeumt ihren Zaehler jetzt weg und gilt EINER Blockade; die
# Terminierungsgarantie bleibt, die Lane bewaffnet sich danach neu.
FREIGABEN=0
for _ in $(seq 1 12); do
  [ "$(gate_exit "$S" "true")" = "0" ] && FREIGABEN=$((FREIGABEN + 1))
done
if [ "$FREIGABEN" -ge 1 ]; then
  ok "Nach begrenzt vielen Blocks gibt das Gate frei (kein Endlos-Loop)"
else
  bad "Nach begrenzt vielen Blocks gibt das Gate frei (kein Endlos-Loop) (nie freigegeben)"
fi

echo
if [ "$FAILED" -eq 0 ]; then
  echo "Ran $((PASSED+FAILED)) tests"
  echo "OK"
  exit 0
else
  echo "Ran $((PASSED+FAILED)) tests"
  echo "FAILED (failures=$FAILED)"
  exit 1
fi
