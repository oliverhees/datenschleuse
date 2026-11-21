#!/bin/sh
# Smoke test of the two built images, as they are published.
#
# Starts the analyzer and the proxy the way the most restrictive deployment
# does: read-only root filesystem (only tmpfs /tmp and /app/state writable),
# all capabilities dropped, no-new-privileges, and the analyzer in an INTERNAL
# Docker network without any route to the internet. Then it checks:
#
#   1. both containers become healthy (analyzer: model loaded without network),
#   2. they run as the documented non-root users,
#   3. the analyzer did not create gunicorn's control socket,
#   4. the Public Suffix List cache was prepared (no fetch on the first e-mail),
#   5. the proxy serves no API documentation pages,
#   6. a block carries the stable identification (header + body field),
#   7. the proxy image started without a master key, with an empty one and with
#      a malformed one or a known placeholder exits with an error and never serves requests (H1),
#   8. a request with an e-mail address is NOT blocked (the analyzer works
#      offline; the unreachable dummy upstream makes it fail afterwards, which
#      is expected and carries no block identification).
#
# Not run in the development environment of DATENSCHLE-105 (no Docker daemon);
# its first real run is the first release run.
#
# Usage:  PROXY_IMAGE=<ref> ANALYZER_IMAGE=<ref> sh test/smoke-images.sh
# Needs:  docker, curl, python3. Runs in .github/workflows/release.yml against the
#         pushed (still untagged) digests; locally with any Docker installation.
set -eu

: "${PROXY_IMAGE:?PROXY_IMAGE is required}"
: "${ANALYZER_IMAGE:?ANALYZER_IMAGE is required}"
PORT="${SMOKE_PORT:-4799}"
P="ds-smoke-$$"
WORK="$(mktemp -d)"

cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        echo "--- analyzer log (tail)" >&2
        docker logs --tail 60 "$P-analyzer" >&2 2>&1 || true
        echo "--- proxy log (tail)" >&2
        docker logs --tail 60 "$P-proxy" >&2 2>&1 || true
    fi
    docker rm -f "$P-proxy" "$P-analyzer" >/dev/null 2>&1 || true
    docker network rm "$P-int" "$P-ext" >/dev/null 2>&1 || true
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT INT TERM

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }
ok() { echo "ok   $*"; }

wait_healthy() {
    i=0
    while [ "$i" -lt "$2" ]; do
        state="$(docker inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null || echo missing)"
        [ "$state" = "healthy" ] && return 0
        [ "$state" = "missing" ] && fail "$1 is gone"
        i=$((i + 5))
        sleep 5
    done
    fail "$1 not healthy after $2 s (state: $state)"
}

docker network create --internal "$P-int" >/dev/null
docker network create "$P-ext" >/dev/null

# Minimal proxy config: same guardrail as litellm/config.yaml, one model whose
# upstream is unreachable on purpose -- nothing ever leaves the runner.
cat > "$WORK/config.yaml" <<'EOF'
model_list:
  - model_name: smoke
    litellm_params:
      model: openai/smoke
      api_base: http://127.0.0.1:9/v1
      api_key: sk-smoke-upstream-dummy
guardrails:
  - guardrail_name: "datenschleuse-reid"
    litellm_params:
      guardrail: datenschleuse_guardrail.DatenschleuseGuardrail
      mode: ["pre_call", "post_call"]
      default_on: true
      presidio_language: "de"
      presidio_score_threshold: 0.0
      qi_risk_preset: "balanced"
litellm_settings:
  turn_off_message_logging: true
general_settings:
  master_key: os.environ/DATENSCHLEUSE_MASTER_KEY
EOF
chmod 0644 "$WORK/config.yaml"

MASTER_KEY="sk-smoke-$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
STATE_KEY="$(python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"

docker run -d --name "$P-analyzer" --network "$P-int" --network-alias presidio-analyzer \
    --read-only --tmpfs /tmp:size=64m --cap-drop ALL --security-opt no-new-privileges:true \
    "$ANALYZER_IMAGE" >/dev/null
wait_healthy "$P-analyzer" 300
ok "analyzer healthy (internal network, read-only)"

# H1: the image must refuse to start without a usable master key. Each case
# runs with the same config and mounts as below and must EXIT (not become
# healthy, not stay running); the log must name the variable and must not
# contain the value that was passed.
check_refuses_without_key() {
    label=$1
    shift
    name="$P-nokey"
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" --network "$P-ext" \
        --read-only --tmpfs /tmp:size=64m --tmpfs /app/state:size=16m,mode=1777 \
        --cap-drop ALL --security-opt no-new-privileges:true \
        -v "$WORK/config.yaml:/app/config.yaml:ro" \
        -e "DATENSCHLEUSE_STATE_KEY=$STATE_KEY" \
        -e PRESIDIO_ANALYZER_API_BASE=http://presidio-analyzer:3000 \
        "$@" "$PROXY_IMAGE" >/dev/null
    i=0
    while [ "$i" -lt 120 ]; do
        running="$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || echo gone)"
        [ "$running" = "false" ] && break
        i=$((i + 3))
        sleep 3
    done
    [ "$running" = "false" ] || fail "proxy image without a master key ($label) is still running"
    [ "$(docker inspect -f '{{.State.ExitCode}}' "$name")" != "0" ] || fail "proxy image without a master key ($label) exited with 0"
    docker logs "$name" 2>&1 | grep -Eq 'DATENSCHLEUSE_MASTER_KEY is missing, empty or malformed|DATENSCHLEUSE_MASTER_KEY is a publicly known placeholder' \
        || fail "proxy image without a master key ($label): error message missing"
    if [ "${LEAK_CHECK:-}" ] && docker logs "$name" 2>&1 | grep -qF "$LEAK_CHECK"; then
        fail "proxy image ($label): log contains the rejected value"
    fi
    docker rm -f "$name" >/dev/null
    ok "image refuses to start without a master key ($label)"
}
check_refuses_without_key "variable not set"
check_refuses_without_key "empty" -e "DATENSCHLEUSE_MASTER_KEY="
LEAK_CHECK="not-a-valid-key-value" check_refuses_without_key "wrong form" \
    -e "DATENSCHLEUSE_MASTER_KEY=not-a-valid-key-value"
# M3: the placeholder that used to ship in .env.example (a public value).
# The message must say "placeholder"; the value itself must not be logged.
LEAK_CHECK="sk-datenschleuse-lokal" check_refuses_without_key "known placeholder" \
    -e "DATENSCHLEUSE_MASTER_KEY=sk-datenschleuse-lokal"

docker run -d --name "$P-proxy" --network "$P-ext" -p "127.0.0.1:$PORT:4000" \
    --read-only --tmpfs /tmp:size=64m --tmpfs /app/state:size=16m,mode=1777 \
    --cap-drop ALL --security-opt no-new-privileges:true \
    -v "$WORK/config.yaml:/app/config.yaml:ro" \
    -e "DATENSCHLEUSE_MASTER_KEY=$MASTER_KEY" -e "DATENSCHLEUSE_STATE_KEY=$STATE_KEY" \
    -e PRESIDIO_ANALYZER_API_BASE=http://presidio-analyzer:3000 \
    "$PROXY_IMAGE" >/dev/null
docker network connect "$P-int" "$P-proxy"
wait_healthy "$P-proxy" 180
ok "proxy healthy (read-only, without database)"

[ "$(docker inspect -f '{{.Config.User}}' "$P-proxy")" = "65532:65532" ] || fail "proxy user"
[ "$(docker inspect -f '{{.Config.User}}' "$P-analyzer")" = "1001" ] || fail "analyzer user"
[ "$(docker exec "$P-proxy" id -u)" = "65532" ] || fail "proxy runs as $(docker exec "$P-proxy" id -u)"
[ "$(docker exec "$P-analyzer" id -u)" = "1001" ] || fail "analyzer runs as $(docker exec "$P-analyzer" id -u)"
ok "non-root users"

docker exec "$P-analyzer" sh -c 'test ! -e /app/gunicorn.ctl' || fail "gunicorn control socket exists"
ok "no gunicorn control socket"
docker exec "$P-analyzer" sh -c 'test -n "$(ls -A "$TLDEXTRACT_CACHE")"' || fail "public suffix cache missing"
ok "public suffix list cache prepared"

for path in /docs /redoc /openapi.json; do
    code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT$path")"
    [ "$code" = "404" ] || fail "$path answered $code"
done
ok "no API documentation pages"

post() {
    curl -s -D "$WORK/headers" -o "$WORK/body" -w '%{http_code}' \
        -H "authorization: Bearer $MASTER_KEY" -H 'content-type: application/json' \
        "http://127.0.0.1:$PORT/v1/chat/completions" -d "$1"
}

code="$(post '{"model":"smoke","messages":[{"role":"user","content":"Hallo","foo":"bar"}]}')"
[ "$code" = "500" ] || fail "block answered $code"
grep -qi '^x-datenschleuse-error: datenschleuse_blocked' "$WORK/headers" || fail "block header missing"
python3 - "$WORK/body" <<'EOF' || fail "block body"
import json, sys
err = json.load(open(sys.argv[1]))["error"]
assert err["type"] == "None", err["type"]
assert err["provider_specific_fields"]["datenschleuse"] == {
    "code": "datenschleuse_blocked", "reason": "request_rejected"}, err
EOF
ok "block carries the stable identification (compat mode)"

code="$(post '{"model":"smoke","messages":[{"role":"user","content":"Bitte schreib an max.muster@example.com eine kurze Antwort."}]}')"
if grep -qi '^x-datenschleuse-error' "$WORK/headers"; then
    fail "request with e-mail was blocked: $(cat "$WORK/body")"
fi
ok "e-mail request passed the guardrail (upstream answered $code, expected: unreachable)"

echo "SMOKE OK"
