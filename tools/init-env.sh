#!/usr/bin/env bash
# Datenschleuse -- creates .env from .env.example with generated secrets.
#
# Fills the four secrets that must never be an example value: master key,
# admin UI password, database password and the QI state key. Everything else
# stays as in .env.example. The values are only written to the file (mode
# 0600), never printed. An existing .env is never touched.
#
# Usage:  bash tools/init-env.sh
# Needs:  bash, openssl, awk, tr
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
example="$root/.env.example"
target="$root/.env"

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

# Values go to awk through the environment, not through its arguments, so
# they never show up in a process list.
DS_MASTER_KEY="sk-$(openssl rand -hex 32)" \
DS_UI_PASSWORD="$(openssl rand -hex 32)" \
DS_DB_PASSWORD="$(openssl rand -hex 32)" \
DS_STATE_KEY="$(openssl rand -base64 32 | tr '+/' '-_')" \
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
' "$example" >"$tmp"

mv "$tmp" "$target"
trap - EXIT

echo "$target angelegt (nur du kannst sie lesen)."
echo "Erzeugt: DATENSCHLEUSE_MASTER_KEY, DATENSCHLEUSE_STATE_KEY, UI_PASSWORD, DATENSCHLEUSE_DB_PASSWORD."
echo "Noch von dir: EUROUTER_API_KEY in .env eintragen (dein eigener Key von eurouter.ai)."
