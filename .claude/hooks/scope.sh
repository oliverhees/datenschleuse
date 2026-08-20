#!/usr/bin/env bash
# Marker-Zuordnung fuer track.sh und stop-gate.sh (DATENSCHLE-79).
#
# In diesem Projekt arbeiten mehrere Agenten gleichzeitig in eigenen
# Worktrees unter .claude/worktrees/agent-*. Die Hooks werden fuer alle aus
# derselben Hauptauscheckung gestartet, CLAUDE_PROJECT_DIR zeigt fuer alle
# dorthin. Daraus folgte genau EIN Markerpaar fuer alle Lanes:
#
#     $CLAUDE_PROJECT_DIR/.claude/.last_code_edit
#     $CLAUDE_PROJECT_DIR/.claude/.last_test_run
#
# Das Gate bewertete damit fremde Laeufe als eigene. Ein roter Test in
# Worktree A blockierte die Session in B -- obwohl Gesetz 2 diesen roten
# Test ausdruecklich VERLANGT (erst rot, dann Implementierung). Ein
# Waechter, der regelmaessig grundlos anschlaegt, wird reflexhaft
# weggeklickt; dann faengt er auch den einen Fall nicht mehr, fuer den er
# gebaut wurde.
#
# Deshalb bekommt jedes Arbeitsverzeichnis sein eigenes Markerverzeichnis.
# Schluessel ist die WORKTREE-WURZEL des cwd, nicht das cwd selbst: sonst
# zaehlte jedes Unterverzeichnis, in das eine Session wechselt, als eigene
# Lane -- und ein roter Lauf waere durch ein blosses `cd` entwertet.
#
# WICHTIG: Schreiber (track.sh) und Leser (stop-gate.sh) muessen exakt
# denselben Schluessel bilden. Driften sie auseinander, findet das Gate nie
# einen Marker und laesst alles durch -- ein lautloser Totalausfall. Genau
# darum steht die Berechnung hier an EINER Stelle und nicht zweimal.

# marker_dir <basis-verzeichnis> <cwd> -> Pfad des Markerverzeichnisses
# Legt das Verzeichnis an und gibt seinen Pfad aus.
marker_dir() {
  local basis="$1" cwd="$2" wurzel name schluessel dir

  # Fehlt cwd im Payload, gilt das Arbeitsverzeichnis des Hook-Prozesses.
  # Claude Code startet den Hook im Verzeichnis der Session; der
  # Rueckfallweg trifft damit dieselbe Lane.
  [ -z "$cwd" ] && cwd="$PWD"

  wurzel=$(git -C "$cwd" rev-parse --show-toplevel 2>/dev/null)
  # Kein Git-Verzeichnis (oder git fehlt): dann ist das cwd selbst die Lane.
  [ -z "$wurzel" ] && wurzel="$cwd"

  # Lesbarer Name fuers Debuggen, plus Pruefsumme des vollen Pfades gegen
  # Namensgleichheit zweier Worktrees an verschiedenen Orten.
  name=$(basename "$wurzel")
  # printf statt echo: der Zeilenumbruch von basename wuerde sonst selbst
  # zu einem '_' und der Name endete auf '_-<pruefsumme>' -- lesbar soll er
  # aber sein, das ist sein einziger Zweck.
  name=$(printf '%s' "$name" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-40)
  schluessel=$(printf '%s' "$wurzel" | cksum | cut -d' ' -f1)

  dir="$basis/scopes/$name-$schluessel"

  # Laesst sich das Verzeichnis nicht anlegen oder ist es nicht beschreibbar
  # (Rechte, volle Platte), darf hier KEIN Pfad herauskommen. Sonst liefen
  # alle Schreibvorgaenge ins Leere, das Gate faende nichts vor und hielte
  # die Lane fuer sauber -- ein Fail-Open, das es vor der Eingrenzung nicht
  # gab, weil das Basisverzeichnis immer existierte. Stattdessen Fehler
  # melden; die Aufrufer fallen dann auf den gemeinsamen Marker zurueck.
  mkdir -p "$dir" 2>/dev/null || return 1
  [ -w "$dir" ] || return 1

  printf '%s' "$dir"
}
