#!/usr/bin/env bash
# Prints the LiteLLM version of the pinned base image (litellm/Dockerfile).
# Single source of truth for the version CI installs to run the tests that
# need the real LiteLLM (DATENSCHLE-106). Fails (exit 1, no output) when the
# FROM line has no vX.Y.Z tag.
set -euo pipefail
root="$(pwd)"
version="$(sed -n 's#^FROM ghcr\.io/berriai/litellm:v\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)@sha256:.*#\1#p' "$root/litellm/Dockerfile")"
if [ -z "$version" ] || [ "$(printf '%s\n' "$version" | wc -l)" -ne 1 ]; then
  echo "Keine eindeutige LiteLLM-Version in litellm/Dockerfile gefunden." >&2
  exit 1
fi
printf '%s\n' "$version"
