#!/usr/bin/env bash
# SessionStart-Brief: feuert bei Session-Start, Resume, Clear UND nach
# einer Kontext-Kompaktierung. Alles auf stdout landet direkt in
# Claudes frischem Kontext.

INPUT=$(cat)
SOURCE=$(echo "$INPUT" | jq -r '.source // "startup"')

echo "=== SESSION-BRIEFING (Quelle: $SOURCE) ==="
echo "Gesetz 7 gilt: Der vorherige Kontext ist weg oder komprimiert."
echo "PFLICHT vor der ersten Aktion:"
echo "1. Aktives Plane Work Item laden (Status, Kommentare, offene Punkte)."
echo "2. Memory Hub + CONTEXT.md konsultieren."
echo "3. git status + aktuellen Branch pruefen."
echo "Arbeitsstand wird AUSSCHLIESSLICH daraus rekonstruiert —"
echo "niemals aus vermeintlicher Erinnerung."

exit 0
