#!/bin/sh
# Build the three release images for ONE platform and push them by digest only
# (no tag). Called by .github/workflows/release.yml in build-amd64/build-arm64.
#
# Env (set by the workflow): PLATFORM, VERSION, PROXY_IMAGE, ANALYZER_IMAGE,
# BUILDKIT_IMAGE, GITHUB_REPOSITORY, GITHUB_SHA, GITHUB_OUTPUT.
# Writes the outputs proxy=, analyzer=, analyzer_md= (sha256:... digests).
set -eu

: "${PLATFORM:?}" "${VERSION:?}" "${PROXY_IMAGE:?}" "${ANALYZER_IMAGE:?}"
: "${BUILDKIT_IMAGE:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_SHA:?}" "${GITHUB_OUTPUT:?}"

docker buildx create --name datenschleuse-release --driver docker-container \
    --driver-opt "image=$BUILDKIT_IMAGE" --use >/dev/null

meta="$(mktemp -d)"
trap 'rm -rf "$meta"' EXIT

# build <output-name> <image> <dockerfile> <title> [--build-arg ...]
build() {
    out=$1 image=$2 dockerfile=$3 title=$4
    shift 4
    docker buildx build \
        --platform "$PLATFORM" \
        --file "$dockerfile" \
        --provenance=mode=max \
        --sbom=true \
        --label "org.opencontainers.image.title=$title" \
        --label "org.opencontainers.image.source=https://github.com/$GITHUB_REPOSITORY" \
        --label "org.opencontainers.image.version=$VERSION" \
        --label "org.opencontainers.image.revision=$GITHUB_SHA" \
        --output "type=image,name=$image,push-by-digest=true,name-canonical=true,push=true" \
        --metadata-file "$meta/$out.json" \
        "$@" \
        .
    digest=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$meta/$out.json")
    printf '%s' "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || { echo "invalid digest: $digest" >&2; exit 1; }
    echo "$out=$digest" >> "$GITHUB_OUTPUT"
    echo "$PLATFORM $out: $image@$digest"
}

build proxy "$PROXY_IMAGE" litellm/Dockerfile "Datenschleuse"
build analyzer "$ANALYZER_IMAGE" presidio/Dockerfile.analyzer "Datenschleuse analyzer" \
    --build-arg SPACY_MODEL=de_core_news_lg
build analyzer_md "$ANALYZER_IMAGE" presidio/Dockerfile.analyzer "Datenschleuse analyzer (md)" \
    --build-arg SPACY_MODEL=de_core_news_md
