#!/usr/bin/env bash
# Reproduzierbarer Round-Trip-Beweis (DATENSCHLE-67).
#
#   Klartext -> Platzhalter -> LLM -> Platzhalter -> Klartext
#
# Ein Aufruf, ein Exit-Code, ein Ordner voller Artefakte. Wer den Beweis
# nachvollziehen will, tippt genau eine Zeile:
#
#   ./test/run-e2e-roundtrip.sh
#
# Voraussetzungen (werden geprueft, nicht angenommen):
#   - Docker + Compose
#   - laufender presidio-analyzer des Produktiv-Stacks (docker compose up -d)
#   - laufender Ollama-Container mit llama3.1:8b
#
# Der Testlauf erzeugt seinen EIGENEN Master-Key und seinen EIGENEN
# Fernet-State-Key. Es wird NIE ein Wert aus .env gelesen (Gesetz 5).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
E2E_DIR="${REPO_ROOT}/test/e2e"
COMPOSE_FILE="${E2E_DIR}/docker-compose.e2e.yml"
ARTIFACT_DIR="${E2E_DIR}/artifacts"

: "${DS_E2E_OLLAMA_CONTAINER:=lokyy-brain-ollama-1}"
: "${DS_E2E_MODEL:=datenschleuse-e2e}"
: "${DS_E2E_KEEP_UP:=0}"   # 1 = Stack nach dem Lauf stehen lassen (Debugging)

log() { printf '\n\033[1m>>> %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFEHLER: %s\033[0m\n' "$*" >&2; exit 2; }

# --- Vorbedingungen ---------------------------------------------------------
command -v docker >/dev/null || fail "docker nicht gefunden"
docker compose version >/dev/null 2>&1 || fail "docker compose (v2) nicht gefunden"
docker inspect "${DS_E2E_OLLAMA_CONTAINER}" >/dev/null 2>&1 \
  || fail "Ollama-Container '${DS_E2E_OLLAMA_CONTAINER}' laeuft nicht"
docker inspect datenschleuse-analyzer >/dev/null 2>&1 \
  || fail "presidio-analyzer laeuft nicht -- vorher 'docker compose up -d' im Repo-Root"
docker image inspect datenschleuse-datenschleuse:latest >/dev/null 2>&1 \
  || fail "Image datenschleuse-datenschleuse:latest fehlt -- vorher 'docker compose build'"

# Netz des Ollama-Containers automatisch bestimmen (kein Raten).
DS_E2E_OLLAMA_NETWORK="${DS_E2E_OLLAMA_NETWORK:-$(docker inspect -f \
  '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' \
  "${DS_E2E_OLLAMA_CONTAINER}" | head -n1)}"
DS_E2E_PRESIDIO_NETWORK="${DS_E2E_PRESIDIO_NETWORK:-$(docker inspect -f \
  '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' \
  datenschleuse-analyzer | head -n1)}"
DS_E2E_OLLAMA_URL="${DS_E2E_OLLAMA_URL:-http://${DS_E2E_OLLAMA_CONTAINER}:11434}"

# --- Eigene, ephemere Schluessel (nichts wird gelesen, alles neu erzeugt) ---
DS_E2E_MASTER_KEY="sk-e2e-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
DS_E2E_STATE_KEY="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_')"
DS_E2E_UPSTREAM_KEY="sk-e2e-local-ollama"
export DS_E2E_MASTER_KEY DS_E2E_STATE_KEY DS_E2E_UPSTREAM_KEY
export DS_E2E_OLLAMA_NETWORK DS_E2E_PRESIDIO_NETWORK DS_E2E_OLLAMA_URL

cleanup() {
  if [ "${DS_E2E_KEEP_UP}" = "1" ]; then
    log "Stack bleibt stehen (DS_E2E_KEEP_UP=1). Abraeumen: docker compose -f ${COMPOSE_FILE} down"
    return
  fi
  log "Raeume den E2E-Stack ab"
  docker compose -f "${COMPOSE_FILE}" logs --no-color --tail 400 \
    > "${ARTIFACT_DIR}/stack.log" 2>&1 || true
  docker compose -f "${COMPOSE_FILE}" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "${ARTIFACT_DIR}"

log "Netze: ollama=${DS_E2E_OLLAMA_NETWORK} presidio=${DS_E2E_PRESIDIO_NETWORK}"
log "Modell im Ollama-Container pruefen"
docker exec "${DS_E2E_OLLAMA_CONTAINER}" ollama list

log "E2E-Stack starten (Proxy :4001, Tap :4600)"
docker compose -f "${COMPOSE_FILE}" up -d --force-recreate

log "Warte auf den Tap"
for i in $(seq 1 60); do
  curl -sf http://localhost:4600/__tap/health >/dev/null 2>&1 && break
  [ "$i" = "60" ] && fail "Tap wurde nicht erreichbar"
  sleep 1
done
echo "Tap erreichbar."

log "Warte auf die Datenschleuse"
for i in $(seq 1 120); do
  if curl -sf http://localhost:4001/health/liveliness >/dev/null 2>&1; then break; fi
  if [ "$i" = "120" ]; then
    docker compose -f "${COMPOSE_FILE}" logs --tail 80 ds-e2e-litellm
    fail "Proxy wurde nicht erreichbar"
  fi
  sleep 1
done
echo "Proxy erreichbar: $(curl -s http://localhost:4001/health/liveliness)"

log "Beweislauf"
DS_E2E_PROXY_URL="http://localhost:4001" \
DS_E2E_TAP_URL="http://localhost:4600" \
DS_E2E_MODEL="${DS_E2E_MODEL}" \
DS_E2E_ARTIFACTS="${ARTIFACT_DIR}" \
python3 "${REPO_ROOT}/test/e2e_roundtrip.py" | tee "${ARTIFACT_DIR}/run.log"
STATUS="${PIPESTATUS[0]}"

log "Artefakte: ${ARTIFACT_DIR}"
ls -la "${ARTIFACT_DIR}"
exit "${STATUS}"
