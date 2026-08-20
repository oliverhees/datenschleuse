#!/usr/bin/env bash
# Pre-Egress-Check (DATENSCHLE-87)
#
# Laeuft VOR jedem Senden an den externen Review (PAL MCP -> Inferenz-
# Anbieter). Er beantwortet genau eine Frage: Darf diese Nutzlast die
# Maschine verlassen?
#
#     Exit 0 = darf gesendet werden
#     Exit 2 = geblockt, es wird NICHT gesendet
#
# Aufruf:
#     .claude/hooks/pre-egress.sh                 # prueft `git diff HEAD`
#     .claude/hooks/pre-egress.sh <datei>...      # prueft diese Nutzlast(en)
#
# --- Warum fail-closed, und zwar ausnahmslos ------------------------------
#
# Dieses Projekt hat wiederholt Pruefungen hervorgebracht, die gruen melden,
# ohne zu pruefen: ein Gate, dem `jq` fehlte, und dessen Ausfall als
# Freigabe durchging (DATENSCHLE-80). Ein Marker-Pfad, den Schreiber und
# Leser unterschiedlich bildeten, sodass das Stop-Gate nie etwas fand
# (DATENSCHLE-79). Ein CVE-Scan auf eine Bereichsangabe statt auf die
# aufgeloeste Version, der beruhigend nichts meldete (DATENSCHLE-59).
#
# Dieser Check sitzt vor einem Egress. Faellt er aus, muss der Egress
# ausfallen -- nicht der Check. Deshalb gilt hier durchgaengig: Jeder
# Zustand, der KEIN nachgewiesenes "sauber" ist, ist ein Block. Fehlendes
# Werkzeug, unbrauchbares Werkzeug, Scannerfehler, unlesbare Nutzlast,
# leere Nutzlast, unerwarteter Fehler -- alles Exit 2.
#
# --- Was dieser Check NICHT kann ------------------------------------------
#
# Er erkennt Schluesselmaterial und verbotene Pfade. Er kann NICHT
# erkennen, ob ein Diff der Fix zu einer noch unveroeffentlichten
# Sicherheitsluecke ist oder ob darin echte Kundendaten stehen. Diese
# beiden Grenzen entscheidet der delegierende Agent bzw. Oliver
# (CLAUDE.md, "Datengrenze fuer den externen Review"). Der Check sagt das
# bei jedem gruenen Lauf dazu, damit niemand ihn fuer mehr haelt, als er
# ist.

set -euo pipefail

ARBEIT=""

aufraeumen() {
  [ -n "$ARBEIT" ] && [ -d "$ARBEIT" ] && rm -rf "$ARBEIT"
  return 0
}
trap aufraeumen EXIT

block() {
  printf '\n🚫 EGRESS GEBLOCKT: %s\n' "$1" >&2
  printf '   Es wird nichts an den externen Review gesendet.\n' >&2
  if [ $# -gt 1 ]; then
    printf '   %s\n' "$2" >&2
  fi
  exit 2
}

# Jeder nicht abgefangene Fehler ist ein Block, kein Durchlauf.
trap 'block "unerwarteter Fehler in Zeile $LINENO"' ERR

# --- Verbotene Pfade ------------------------------------------------------
#
# Deterministische Ebene VOR dem Scanner: Diese Pfade gehen nie hinaus,
# unabhaengig davon, was in ihnen steht und ob ein Scanner anschlaegt.
# Die Liste ist bewusst kurz gehalten. Ein Waechter, der staendig grundlos
# anschlaegt, wird reflexhaft weggeklickt -- dann faengt er auch den einen
# Fall nicht mehr, fuer den er gebaut wurde.
VERBOTEN='(^|/)\.env($|\.)|(^|/)id_(rsa|dsa|ecdsa|ed25519)($|\.)|\.(pem|key|p12|pfx|jks|keystore|asc|gpg)$|(^|/)\.ssh/|(^|/)\.(npmrc|pypirc|netrc)$|(^|/)\.aws/'

# Vorlagen ohne Inhalt sind kein Schluesselmaterial.
erlaubte_vorlage() {
  case "$1" in
    *.example|*.sample|*.template|*.dist) return 0 ;;
  esac
  return 1
}

verbotener_pfad() {
  erlaubte_vorlage "$1" && return 1
  printf '%s\n' "$1" | grep -qE "$VERBOTEN"
}

# --- Werkzeug-Praeflight --------------------------------------------------
#
# Dieselbe Fehlerklasse wie das fehlende jq in DATENSCHLE-80 -- dort fiel
# das Gate offen. Hier faellt es zu.
command -v grep >/dev/null 2>&1 || block "grep fehlt"
command -v mktemp >/dev/null 2>&1 || block "mktemp fehlt"
command -v cat >/dev/null 2>&1 || block "cat fehlt"
command -v gitleaks >/dev/null 2>&1 || block \
  "gitleaks ist auf diesem Rechner nicht installiert." \
  "Installation: https://github.com/gitleaks/gitleaks -- bis dahin laeuft kein externer Review."

ARBEIT=$(mktemp -d "${TMPDIR:-/tmp}/pre-egress.XXXXXXXX") || block "kein Arbeitsverzeichnis anlegbar"
# Gescannt wird ausschliesslich SCANRAUM. Das Scan-Protokoll liegt bewusst
# DANEBEN und nicht darin -- sonst scannte gitleaks seine eigene Ausgabe.
SCANRAUM="$ARBEIT/nutzlast"
mkdir -p "$SCANRAUM"
NUTZLAST="$SCANRAUM/nutzlast.txt"
SCAN_LOG="$ARBEIT/scan.log"
: > "$NUTZLAST"

# --- Nutzlast ermitteln ---------------------------------------------------
if [ $# -gt 0 ]; then
  for datei in "$@"; do
    [ -f "$datei" ] && [ -r "$datei" ] || block "Nutzlast nicht lesbar: $datei"
    cat -- "$datei" >> "$NUTZLAST" || block "Nutzlast nicht lesbar: $datei"
  done
else
  command -v git >/dev/null 2>&1 || block "git fehlt"
  git rev-parse --show-toplevel >/dev/null 2>&1 || block \
    "kein Git-Arbeitsbaum -- der zu sendende Diff laesst sich nicht ermitteln"
  git diff HEAD > "$NUTZLAST" 2>/dev/null || block "git diff HEAD fehlgeschlagen"
fi

# Leer heisst hier nicht "sauber", sondern "die Ermittlung ist schiefgegangen".
# Wer nicht weiss, WAS er sendet, kann nicht wissen, dass es unbedenklich ist.
# Geprueft wird auf substanziellen Inhalt, nicht auf Dateigroesse: eine Datei
# mit einem einzelnen Zeilenumbruch ist nach `-s` nicht leer, als Diff aber
# genauso nichtssagend.
if ! grep -q '[^[:space:]]' "$NUTZLAST" 2>/dev/null; then
  block "Nutzlast ist leer" \
    "Entweder gibt es nichts zu senden -- dann entfaellt der Review -- oder die Ermittlung ist fehlgeschlagen."
fi

# --- Ebene 1: Pfadpruefung ------------------------------------------------
#
# Gelesen werden NUR Kopfzeilen eines Unified Diffs, nie Inhaltszeilen.
# Grund: Ein Diff, der selbst einen Diff enthaelt (etwa diese Testsuite),
# traegt Zeilen wie "++++ b/…" im Rumpf. Wer stumpf auf "+++ " matcht,
# blockt an der blossen ERWAEHNUNG -- dieselbe Fehlerklasse, an der
# guard.sh dreimal grundlos angeschlagen hat (ADR-0004, Befund 7).
# Deshalb der Zustand: innerhalb eines Hunks (@@) wird nichts gewertet.
im_hunk=0
while IFS= read -r zeile || [ -n "$zeile" ]; do
  kandidat=""
  case "$zeile" in
    'diff --git '*)
      im_hunk=0
      # Der gesamte Rest wird geprueft. Dateinamen mit Leerzeichen liessen
      # sich sonst nicht sicher trennen; die Ueberschaetzung geht in die
      # sichere Richtung.
      kandidat=${zeile#diff --git } ;;
    '@@ '*)
      im_hunk=1 ;;
    '--- '*|'+++ '*)
      [ "$im_hunk" -eq 1 ] && continue
      kandidat=${zeile#* }
      kandidat=${kandidat%%$'\t'*}   # Zeitstempel abschneiden
      kandidat=${kandidat#a/}
      kandidat=${kandidat#b/} ;;
  esac

  [ -z "$kandidat" ] && continue
  [ "$kandidat" = "/dev/null" ] && continue

  if verbotener_pfad "$kandidat"; then
    block "verbotener Pfad in der Nutzlast: $kandidat" \
          "Secrets und Schluesselmaterial verlassen diese Maschine nie (Gesetz 5)."
  fi
done < "$NUTZLAST"

# --- Ebene 2: Secret-Scan -------------------------------------------------
#
# gitleaks kennt zwei Aufrufformen, je nach Version. Welche nutzbar ist,
# wird ermittelt statt geraten -- und wenn keine nutzbar ist, wird
# geblockt, nicht gesendet.
gitleaks_scan() {
  if gitleaks dir --help >/dev/null 2>&1; then
    gitleaks dir --redact "$SCANRAUM"
  elif gitleaks detect --help >/dev/null 2>&1; then
    gitleaks detect --no-git --redact --source "$SCANRAUM"
  else
    return 3
  fi
}

if gitleaks_scan > "$SCAN_LOG" 2>&1; then
  :
else
  RC=$?
  # --redact ist gesetzt: was hier herauskommt, enthaelt kein Klartext-
  # Schluesselmaterial (Gesetz 5: keine Secrets in Logs).
  printf '\n--- gitleaks (redigiert) ---\n' >&2
  cat -- "$SCAN_LOG" >&2 || true
  printf -- '--- Ende gitleaks ---\n' >&2
  case "$RC" in
    3) block "gitleaks ist vorhanden, aber weder 'dir' noch 'detect' nutzbar" \
             "Version pruefen: gitleaks version" ;;
    1) block "gitleaks hat Schluesselmaterial in der Nutzlast gefunden" \
             "Ursache beheben, nicht umgehen." ;;
    *) block "gitleaks ist mit Fehler abgebrochen (Exit $RC)" \
             "Ein Scannerfehler ist kein Freibrief. Ursache beheben, dann erneut." ;;
  esac
fi

# --- Freigabe -------------------------------------------------------------
printf '✅ Pre-Egress-Check bestanden — kein Schluesselmaterial, kein verbotener Pfad.\n'
printf '   Nicht maschinell geprueft und deshalb DEINE Entscheidung:\n'
printf '   1. Ist das der Fix zu einer noch unveroeffentlichten Sicherheitsluecke\n'
printf '      (inkl. reproduzierendem Test)? Dann wird nicht gesendet.\n'
printf '   2. Stehen echte Kunden- oder Personendaten darin? Dann wird nicht gesendet.\n'
printf '   Siehe CLAUDE.md, "Datengrenze fuer den externen Review".\n'
exit 0
