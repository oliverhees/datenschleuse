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
FROM ghcr.io/berriai/litellm:main-latest

WORKDIR /app

# 1. Extra-Dependencies (httpx ist i.d.R. schon da; explizit fuer Reproduzierbarkeit)
COPY requirements-guardrail.txt /app/requirements-guardrail.txt
RUN pip install --no-cache-dir -r /app/requirements-guardrail.txt

# 2. Custom-Guardrail-Code ins Image kopieren (auf den Importpfad)
COPY datenschleuse_guardrail.py /app/datenschleuse_guardrail.py

# 3. Sicherstellen, dass /app importierbar ist (Import 'datenschleuse_guardrail')
ENV PYTHONPATH=/app

# Kein eigener ENTRYPOINT/CMD noetig -- der des Basis-Images (litellm) bleibt
# aktiv; Config + Port werden wie gehabt via docker-compose command uebergeben.
