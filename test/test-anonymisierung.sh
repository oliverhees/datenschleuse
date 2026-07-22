#!/usr/bin/env bash
# Datenschleuse — Testfall: Prompt mit Fake-Personendaten durchschicken.
# Zeigt, ob der Proxy laeuft und antwortet. Ob die PII wirklich maskiert ankam,
# pruefst du im Container-Log (docker compose logs datenschleuse | grep -i presidio)
# oder spaeter ueber das Audit-Log.

set -euo pipefail

MASTER_KEY="${DATENSCHLEUSE_MASTER_KEY:-sk-datenschleuse-lokal}"
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
