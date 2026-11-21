# Datenschleuse LiteLLM-Image mit eingebautem Custom-Guardrail.
#
# Warum ein eigenes Image statt des Stock-Images?
# LiteLLM laedt den Custom-Guardrail per Import-Pfad
# (`guardrail: datenschleuse_guardrail.DatenschleuseGuardrail`). Damit dieser
# Import gelingt, muss datenschleuse_guardrail.py auf dem PYTHONPATH liegen und
# ggf. Extra-Dependencies installiert sein. Das Stock-Image kennt weder den
# Custom-Code noch die Requirements -> wir setzen minimal darauf auf.
#
# Build (via docker-compose oder direkt) -- Build-Kontext ist das Repo-Root,
# weil das Image auch die YAML-Konfiguration aus presidio/ enthaelt:
#   docker build -f litellm/Dockerfile -t datenschleuse .
#
# Gegen die konkret verwendete LiteLLM-Version verifizieren:
#   - Arbeitsverzeichnis/Config-Pfad des Stock-Images (aktuell /app)
#   - dass /app auf dem PYTHONPATH liegt (unten explizit gesetzt)
#
# BASIS-IMAGE: Release-Tag PLUS Digest (DATENSCHLE-59).
# Vorher stand hier `main-latest` -- ein rollender Tag auf den JEWEILS letzten
# main-Merge von BerriAI. Nachgemessen am 2026-08-19: `main-latest` trug das
# Label org.opencontainers.image.revision=007bd43c, ein Commit von *demselben
# Tag* (03:31 UTC). Zwei Builds am selben Tag konnten also unterschiedliche
# Software enthalten, und nachtraeglich war nicht feststellbar, welche
# ausgeliefert wurde. Fuer ein Sicherheitsprodukt ist das nicht haltbar.
#
# Jetzt: das veroeffentlichte Release v1.97.0 (2026-08-16), zusaetzlich per
# Digest festgenagelt. Der Tag ist die menschenlesbare Absicht, der Digest die
# Garantie -- Tags sind verschiebbar, Digests nicht. Docker zieht bei dieser
# Schreibweise ausschliesslich nach Digest.
#
# UPDATE-VERFAHREN: docs/foundation/supply-chain.md ("Digest-Update").
# Kurz: nie von Hand raten, sondern
#   docker buildx imagetools inspect ghcr.io/berriai/litellm:<neuer-tag>
# und den Digest daraus uebernehmen -- als eigenes Work Item mit gruenem CI.
FROM ghcr.io/berriai/litellm:v1.97.0@sha256:468c25f35f3e5ec4e414974f00deab93337b1b4d9953cabcfd3722e59415f834

WORKDIR /app

# ---------------------------------------------------------------------------
# 1. Dependencies: checked, not installed
# ---------------------------------------------------------------------------
# Before, this step ran `ensurepip` and `pip install -r requirements-guardrail.txt`
# (version RANGES). Measured on 2026-11-21 from the venv layer of the pinned
# base image: httpx, PyYAML, cryptography and regex are all already there, so
# pip never installed anything -- it only added pip itself to the image and
# would have pulled an unpinned version the day the base image stopped
# shipping one of them. Now the exact versions are pinned in runtime-pins.txt
# and CHECKED; a mismatch fails the build. No package is downloaded, and the
# image contains no pip.
COPY litellm/runtime-pins.txt /opt/datenschleuse/runtime-pins.txt
COPY litellm/check_runtime_pins.py /opt/datenschleuse/check_runtime_pins.py
RUN python -I /opt/datenschleuse/check_runtime_pins.py /opt/datenschleuse/runtime-pins.txt

# ---------------------------------------------------------------------------
# 2. Guardrail code (on the import path /app)
# ---------------------------------------------------------------------------
# qi_generalization.py = reine Logik, qi_state.py = verschluesselter
# TTL-Session-Store (cryptography), sensitivity_classifier.py = Schutzklassen
# (PyYAML), custom_rules.py = eigene Begriffe/Muster (PyYAML + regex,
# DATENSCHLE-7), de_stopwords.py = Lader der Nicht-PII-Wortliste
# (DATENSCHLE-82; der Guardrail importiert es ohne Fallback -- fehlt die Zeile,
# startet der Dienst mit ModuleNotFoundError).
COPY litellm/datenschleuse_guardrail.py /app/datenschleuse_guardrail.py
COPY litellm/qi_generalization.py /app/qi_generalization.py
COPY litellm/qi_state.py /app/qi_state.py
COPY litellm/sensitivity_classifier.py /app/sensitivity_classifier.py
COPY litellm/custom_rules.py /app/custom_rules.py
COPY litellm/de_stopwords.py /app/de_stopwords.py

# ---------------------------------------------------------------------------
# 3. Configuration baked in, so the image runs without any mount
# ---------------------------------------------------------------------------
# docker-compose.yml still mounts the same files over these paths (iteration
# without rebuild); an operator using the published image mounts only what
# they want to change -- typically config.yaml with their own model list.
# recognizers-config.yml MUST be the same file the analyzer image carries
# (operator-precedence check, test/test_deploy_layout.py); both images are
# built from the same commit.
COPY litellm/config.yaml /app/config.yaml
COPY presidio/sensitivity-keywords.yml /app/config/sensitivity-keywords.yml
COPY presidio/de-stopwords.yml /app/config/de-stopwords.yml
COPY presidio/recognizers-config.yml /app/config/recognizers-config.yml

# ---------------------------------------------------------------------------
# 4. Writable places: /tmp and /app/state, nothing else
# ---------------------------------------------------------------------------
# /app/state: encrypted QI session state (SQLite), a volume in compose.
# Mode 1777 (world-writable, sticky) is a DECISION, not an oversight (security
# audit L4): the repository compose runs the proxy under the host user's UID
# (default 1000, because the rules file written by the CLI is owner-only),
# not under the image's 65532, and a NEW named volume inherits owner and mode
# of this directory. An owner-only directory (0700, 65532) would lock the
# compose default out of its own state. The container holds one process (the
# proxy) and the content is Fernet-encrypted regardless. Tighten to owner-only
# once the compose default and the image user are the same UID.
# /app/rules: custom rules (DATENSCHLE-7), a READ-ONLY bind mount from the
# host; without a mount the guardrail simply sees no custom rules. The CLI
# (tools/datenschleuse-rules) stays on the host on purpose.
RUN mkdir -p /app/state /app/rules && chmod 1777 /app/state && chmod 0755 /app/rules

# ---------------------------------------------------------------------------
# 5. Runtime defaults -- secure without extra configuration
# ---------------------------------------------------------------------------
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV HOME=/tmp
ENV SENSITIVITY_KEYWORDS_PATH=/app/config/sensitivity-keywords.yml
ENV DATENSCHLEUSE_STOPWORDS_PATH=/app/config/de-stopwords.yml
ENV DATENSCHLEUSE_RECOGNIZERS_PATH=/app/config/recognizers-config.yml
ENV DATENSCHLEUSE_CUSTOM_RULES_PATH=/app/rules/custom-rules.yml
ENV DATENSCHLEUSE_STATE_DB=/app/state/qi_state.db
ENV DATENSCHLEUSE_IMAGE_POLICY=block
# Fail closed without authentication (DATENSCHLE-105, H1): without a master
# key LiteLLM only logs a warning and then accepts every request while the
# image listens on 0.0.0.0. With this flag the guardrail refuses to start
# unless DATENSCHLEUSE_MASTER_KEY (or the key the config resolves) is `sk-`
# followed by at least 16 characters. The compose files fail earlier with
# `${DATENSCHLEUSE_MASTER_KEY:?}`; this covers `docker run` without compose.
ENV DATENSCHLEUSE_REQUIRE_MASTER_KEY=true
# No network fetch at start: LiteLLM otherwise downloads its model cost map
# from GitHub on import.
ENV LITELLM_LOCAL_MODEL_COST_MAP=True
# No API documentation pages (/docs, /redoc) and no machine-readable API
# schema (/openapi.json) -- none of them is needed to use the proxy.
ENV NO_DOCS=True
ENV NO_REDOC=True
ENV NO_OPENAPI=True
# Admin UI off by default in the IMAGE. Measured against LiteLLM 1.97.0: the
# flag makes the UI report itself disabled and refuses SSO login; the static UI
# files are still served and POST /login still exists -- without a database it
# cannot create a session ("Not connected to DB"). The repository's
# docker-compose.yml switches the UI back on (DISABLE_ADMIN_UI=False), because
# the README documents /ui for that setup with its Postgres.
ENV DISABLE_ADMIN_UI=True

# Non-root (65532 = "nonroot" convention of the Wolfi/Chainguard base). The
# base image runs as root.
USER 65532:65532

EXPOSE 4000

# /health/liveliness answers without the master key. Port 4000 is the
# documented port; change the check together with --port.
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:4000/health/liveliness', timeout=3)"]

# Entrypoint of the base image (docker/prod_entrypoint.sh -> `litellm "$@"`)
# stays. No --detailed_debug: verbose logs are opt-in, see docs/DEPLOY.md.
CMD ["--config", "/app/config.yaml", "--port", "4000"]
