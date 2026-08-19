# Datenschleuse LiteLLM-Image mit eingebautem Custom-Guardrail.
#
# Warum ein eigenes Image statt des Stock-Images?
# LiteLLM laedt den Custom-Guardrail per Import-Pfad
# (`guardrail: datenschleuse_guardrail.DatenschleuseGuardrail`). Damit dieser
# Import gelingt, muss datenschleuse_guardrail.py auf dem PYTHONPATH liegen und
# ggf. Extra-Dependencies installiert sein. Das Stock-Image kennt weder den
# Custom-Code noch die Requirements -> wir setzen minimal darauf auf.
#
# Build (via docker-compose oder direkt):
#   docker build -t datenschleuse-litellm ./litellm
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

# 1. Extra-Dependencies (httpx ist i.d.R. schon da; explizit fuer Reproduzierbarkeit)
#
# Live-Build-Befund (verifiziert 2026-07-22): das Basis-Image ist Wolfi-basiert
# und hat KEIN `pip`-Binary und KEIN `pip`-Modul vorinstalliert (nur die nackte
# venv unter /app/.venv). `python -m ensurepip` bootstrapt pip aus der Python-
# Stdlib heraus, das funktioniert auf Wolfi (kein apt, kein System-Package-Mgr
# noetig, laeuft als root).
COPY requirements-guardrail.txt /app/requirements-guardrail.txt
RUN python -m ensurepip --upgrade \
    && python -m pip install --no-cache-dir -r /app/requirements-guardrail.txt

# 2. Custom-Guardrail-Code + Quasi-Identifier-Module + Schutzklassen-
#    Klassifizierer ins Image kopieren (auf den Importpfad). qi_generalization.py
#    = reine Logik, qi_state.py = verschluesselter TTL-Session-Store (braucht
#    cryptography, s.o.), sensitivity_classifier.py = reine Logik (braucht
#    PyYAML zum Laden der Keyword-Config, s.o.).
COPY datenschleuse_guardrail.py /app/datenschleuse_guardrail.py
COPY qi_generalization.py /app/qi_generalization.py
COPY qi_state.py /app/qi_state.py
COPY sensitivity_classifier.py /app/sensitivity_classifier.py

# 3. Verzeichnis fuer den lokalen, verschluesselten QI-Session-State (SQLite).
#    Wird per Volume in docker-compose.yml persistiert (DATENSCHLEUSE_STATE_DB).
RUN mkdir -p /app/state

# 4. Sicherstellen, dass /app importierbar ist (Import 'datenschleuse_guardrail')
ENV PYTHONPATH=/app

# Kein eigener ENTRYPOINT/CMD noetig -- der des Basis-Images (litellm) bleibt
# aktiv; Config + Port werden wie gehabt via docker-compose command uebergeben.
