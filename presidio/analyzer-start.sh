#!/bin/sh
# Start script of the Datenschleuse analyzer image (presidio/Dockerfile.analyzer).
#
# 1. Copy the Public Suffix List cache built into the image to the writable
#    $TLDEXTRACT_CACHE, so the e-mail recognizer never fetches it from the
#    network (tldextract needs a writable lock file next to the cache).
# 2. Start gunicorn without the control socket (it would be created in the
#    read-only working directory) on the port the image documents.
set -eu
src=/opt/datenschleuse/tldextract-cache
dst="${TLDEXTRACT_CACHE:-/tmp/tldextract-cache}"
if [ -d "$src" ]; then
    mkdir -p "$dst"
    cp -R "$src/." "$dst/"
fi
exec gunicorn --no-control-socket -w "${WORKERS:-1}" -b "0.0.0.0:${PORT:-3000}" "app:create_app()"
