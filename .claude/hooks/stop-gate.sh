#!/usr/bin/env bash
# Stop-Gate: Der Agent darf sich nicht "fertig" melden, wenn nach der
# letzten Code-Aenderung kein GRUENER Testlauf stattfand.
# Exit 2 = Stop wird abgelehnt, Agent muss weiterarbeiten.
#
# Gesetz 2 sagt: fertig ist nur, was gruen gelaufen ist — "vermutlich"
# zaehlt nicht. Frueher pruefte dieses Gate lediglich, OB ein Testlauf
# stattfand, nicht WIE er ausging (DATENSCHLE-55). Jetzt entscheidet das
# Ergebnis, das track.sh im Marker hinterlegt.

INPUT=$(cat)
ACTIVE=$(echo "$INPUT" | jq -r '.stop_hook_active // false')
CWD=$(echo "$INPUT" | jq -r '.cwd // empty')

# Bewertet werden ausschliesslich Laeufe und Aenderungen aus DEMSELBEN
# Arbeitsverzeichnis wie die Session, die enden will (DATENSCHLE-79).
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
EDIT="$DIR/.last_code_edit"
TEST="$DIR/.last_test_run"
COUNT="$DIR/.stop_block_count"

# Wie oft dieses Gate denselben Zustand ablehnt, bevor es freigibt.
# Ohne diese Schranke koennte das Gate den Agenten endlos festhalten;
# der Zaehler wird bei jeder neuen Code-Aenderung zurueckgesetzt, damit
# er sich nicht durch blosses Wiederholen freikaufen laesst.
MAX_BLOCKS=10

pass_gate() { rm -f "$COUNT"; exit 0; }

deny() {
  # Zaehler zuruecksetzen, sobald seit dem letzten Block neuer Code kam.
  if [ -f "$COUNT" ] && [ -f "$EDIT" ] && [ "$EDIT" -nt "$COUNT" ]; then
    rm -f "$COUNT"
  fi
  local n
  n=$(cat "$COUNT" 2>/dev/null || echo 0)
  n=$((n + 1))
  echo "$n" > "$COUNT"

  if [ "$n" -ge "$MAX_BLOCKS" ]; then
    # Zaehler zuruecksetzen: Die Notbremse gilt EINER Blockade, nicht der
    # Lane auf Lebenszeit. Bliebe der Zaehler voll stehen, laege er beim
    # naechsten Stop sofort ueber der Schranke -- die Lane waere dauerhaft
    # offen, ueber Session-Grenzen hinweg, weil die Datei liegen bleibt.
    rm -f "$COUNT"
    echo "WARNUNG: Das Test-Gate hat $n mal abgelehnt und gibt jetzt frei," >&2
    echo "damit die Session nicht haengenbleibt. Der Testnachweis fehlt" >&2
    echo "weiterhin — melde das als Blocker, statt es zu verschweigen." >&2
    exit 0
  fi

  echo "🚫 STOP ABGELEHNT: $1" >&2
  exit 2
}

# Keine Code-Aenderung in dieser Session -> alles gut
[ ! -f "$EDIT" ] && pass_gate

# Code geaendert, aber nie getestet -> Block
if [ ! -f "$TEST" ]; then
  deny "Es wurde Code geaendert, aber kein Testlauf ausgefuehrt. Fuehre die Tests aus (Gesetz 2), bevor du fertig meldest."
fi

# Code-Aenderung ist NEUER als der letzte Testlauf -> Block
if [ "$EDIT" -nt "$TEST" ]; then
  deny "Die letzte Code-Aenderung liegt NACH dem letzten Testlauf. Fuehre die Tests erneut aus (Gesetz 2)."
fi

# --- Das Ergebnis zaehlt, nicht die Absicht ------------------------------
STATUS=$(jq -r '.status // empty' "$TEST" 2>/dev/null)

case "$STATUS" in
  pass)
    pass_gate
    ;;
  fail)
    CMD=$(jq -r '.cmd // "?"' "$TEST" 2>/dev/null)
    EVIDENCE=$(jq -r '.evidence // ""' "$TEST" 2>/dev/null | tail -5)
    deny "Der letzte Testlauf ist ROT gelaufen. Fertig ist nur, was gruen ist (Gesetz 2).
Kommando: $CMD
Ausgabe (Auszug):
$EVIDENCE
Repariere die Ursache und lasse die Tests erneut laufen."
    ;;
  unknown)
    CMD=$(jq -r '.cmd // "?"' "$TEST" 2>/dev/null)
    deny "Der letzte Testlauf liefert kein auswertbares Ergebnis — damit ist nicht belegt, dass er gruen war.
Kommando: $CMD
Lasse die Tests so laufen, dass die Zusammenfassung sichtbar bleibt (z.B. 'OK' bzw. 'N passed' in der Ausgabe), statt sie wegzufiltern."
    ;;
  *)
    # Kein Statusfeld: Marker stammt aus der Zeit vor DATENSCHLE-55 oder
    # ist beschaedigt. Fail-closed — ein Marker ohne Ergebnis ist kein
    # Nachweis.
    deny "Der Testlauf-Marker enthaelt kein Ergebnis (alter oder beschaedigter Marker). Fuehre die Tests erneut aus, damit das Ergebnis erfasst wird."
    ;;
esac
