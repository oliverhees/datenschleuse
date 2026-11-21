#!/usr/bin/env bash
# Datenschleuse -- creates .env from .env.example with generated secrets.
#
# Fills the four secrets that must never be an example value: master key,
# admin UI password, database password and the QI state key. Everything else
# stays as in .env.example. The values are only written to the file (mode
# 0600), never printed. An existing .env (also a symlink, also one that
# appears while the script runs) is never touched. If a value cannot be
# generated or looks wrong, nothing is written and the exit code is not 0.
#
# Usage:  bash tools/init-env.sh
# Needs:  bash, openssl, awk, tr
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
example="$root/.env.example"
target="$root/.env"

if [ -L "$target" ]; then
  echo "$target ist ein Symlink und wird nicht ersetzt." >&2
  echo "Symlink entfernen oder die Zieldatei selbst befuellen (Kommandos: siehe .env.example)." >&2
  exit 1
fi
if [ -e "$target" ]; then
  echo "$target existiert schon und wird nicht veraendert." >&2
  echo "Fehlende oder leere Werte dort selbst eintragen (Kommandos: siehe .env.example)." >&2
  exit 1
fi
if [ ! -f "$example" ]; then
  echo "$example fehlt." >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl wird gebraucht, um Zufallswerte zu erzeugen." >&2
  exit 1
fi

umask 077
tmp="$(mktemp "$root/.env.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

fail() {
  echo "Abbruch: $1. Es wurde keine .env angelegt." >&2
  exit 1
}

# One assignment per value: under `set -e` a failing command substitution in a
# plain assignment stops the script (it does not in `VAR=$(cmd) prog`).
hex_a="$(openssl rand -hex 32)" || fail "openssl rand ist fehlgeschlagen"
hex_b="$(openssl rand -hex 32)" || fail "openssl rand ist fehlgeschlagen"
hex_c="$(openssl rand -hex 32)" || fail "openssl rand ist fehlgeschlagen"
b64="$(openssl rand -base64 32)" || fail "openssl rand ist fehlgeschlagen"
state_key="$(printf '%s' "$b64" | tr '+/' '-_')"

# Form checks (never print a value): 64 hex characters, and a 44 character
# URL-safe base64 string (a Fernet key: 32 bytes).
is_hex64() { [ "${#1}" -eq 64 ] && [[ "$1" =~ ^[0-9a-f]+$ ]]; }
is_fernet() { [ "${#1}" -eq 44 ] && [[ "$1" =~ ^[A-Za-z0-9_-]{43}=$ ]]; }
is_hex64 "$hex_a" || fail "der erzeugte Master-Key hat eine unerwartete Form"
is_hex64 "$hex_b" || fail "das erzeugte UI-Passwort hat eine unerwartete Form"
is_hex64 "$hex_c" || fail "das erzeugte Datenbank-Passwort hat eine unerwartete Form"
is_fernet "$state_key" || fail "der erzeugte State-Key hat eine unerwartete Form"

# Values go to awk through the environment, not through its arguments, so
# they never show up in a process list.
DS_MASTER_KEY="sk-$hex_a" \
DS_UI_PASSWORD="$hex_b" \
DS_DB_PASSWORD="$hex_c" \
DS_STATE_KEY="$state_key" \
awk '
  BEGIN {
    value["DATENSCHLEUSE_MASTER_KEY"] = ENVIRON["DS_MASTER_KEY"]
    value["UI_PASSWORD"] = ENVIRON["DS_UI_PASSWORD"]
    value["DATENSCHLEUSE_DB_PASSWORD"] = ENVIRON["DS_DB_PASSWORD"]
    value["DATENSCHLEUSE_STATE_KEY"] = ENVIRON["DS_STATE_KEY"]
  }
  {
    name = $0
    sub(/=.*/, "", name)
    if (($0 ~ /^[A-Z_]+=/) && (name in value)) { print name "=" value[name]; next }
    print
  }
' "$example" >"$tmp" || fail "die Vorlage konnte nicht geschrieben werden"

# Create the target atomically and never over an existing one: a hard link
# fails when the name exists (also as a dangling symlink), unlike `mv`.
# The temporary file is removed by the trap in both cases.
if ! ln -- "$tmp" "$target" 2>/dev/null; then
  echo "$target ist inzwischen entstanden (oder kann nicht angelegt werden) und wird nicht veraendert." >&2
  exit 1
fi

echo "$target angelegt (nur du kannst sie lesen)."
echo "Erzeugt: DATENSCHLEUSE_MASTER_KEY, DATENSCHLEUSE_STATE_KEY, UI_PASSWORD, DATENSCHLEUSE_DB_PASSWORD."
echo "Noch von dir: EUROUTER_API_KEY in .env eintragen (dein eigener Key von eurouter.ai)."
