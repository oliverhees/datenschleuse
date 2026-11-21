#!/usr/bin/env bash
# Datenschleuse — Testfall: Prompt mit Fake-Personendaten durchschicken.
# Zeigt, ob der Proxy laeuft und antwortet. Ob die PII wirklich maskiert ankam,
# pruefst du im Container-Log (docker compose logs datenschleuse | grep -i presidio)
# oder spaeter ueber das Audit-Log.

set -euo pipefail

# Kein Standardwert: ein oeffentlich bekannter Key waere keine Anmeldung.
if [ -z "${DATENSCHLEUSE_MASTER_KEY:-}" ]; then
  echo "DATENSCHLEUSE_MASTER_KEY ist nicht gesetzt. Nimm den Wert aus deiner .env:" >&2
  echo "  set -a; . ./.env; set +a; bash test/test-anonymisierung.sh" >&2
  exit 2
fi
MASTER_KEY="$DATENSCHLEUSE_MASTER_KEY"
PROXY="${PROXY:-http://localhost:4000}"

echo "== Testprompt mit Fake-PII an die Datenschleuse =="
curl -sS "$PROXY/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $MASTER_KEY" \
  -d '{
    "model": "datenschleuse-gpt",
    "messages": [
      {
        "role": "user",
        "content": "Fasse zusammen: Herr Max Mustermann (max.mustermann@example.de, Tel. 030 12345678) aus Berlin hat die Steueridentifikationsnummer 12 345 678 901 und das Kennzeichen B-MM 1234. Seine IBAN ist DE89 3704 0044 0532 0130 00."
      }
    ]
  }' | python3 -m json.tool
