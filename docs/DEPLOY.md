# Datenschleuse per Coolify deployen

Eigene Instanz, eigener eurouter.ai-Key, eigene Domain. **Single-Tenant:** eine
Instanz gehoert einem Betreiber, die PII-Pipeline ist fuer alle gleich, nur der
Upstream-Key ist deiner. Kein Multi-User-Sharing, kein fremdes Kontingent.

Dateien fuer den Deploy:
- `deploy/coolify/docker-compose.yaml` — der Stack, Coolify-tauglich (Proxy via
  Coolify, keine festen Container-Namen, keine Host-Ports, Secrets nur als
  `${ENV}`, ausschliesslich Verzeichnis-Bind-Mounts). Liegt bewusst in einem
  eigenen Unterordner, nicht am Repo-Root — dort liegt das lokale
  `docker-compose.yml` fuer den Self-Hosting-Quickstart (siehe README).
- `coolify-template.json` — Liste aller zu setzenden Variablen (inkl. Generier-Hinweisen).
- `.env.example` — dieselben Variablen mit Erklaerung.

---

## Voraussetzungen

- Eine laufende Coolify-Instanz auf einem eigenen Server (z. B. Hetzner).
  Server-Haertung als One-Liner: siehe
  [coolify-server-hardening](https://github.com/oliverhees/coolify-server-hardening).
- Ein eurouter.ai-Account + API-Key (https://www.eurouter.ai?ref=06ZUHPBK).
- Eine (Sub-)Domain, die auf den Coolify-Server zeigt (z. B. `datenschleuse.deine-domain.de`).

---

## Weg A — Coolify-UI (empfohlen)

1. **Projekt → New Resource → Docker Compose** (Quelle: dieses Git-Repo,
   Branch `main`, Base Directory `/deploy/coolify`) — Coolify findet die
   `docker-compose.yaml` dort automatisch.
2. **Environment-Variablen** setzen (Reiter *Environment Variables*) — die Werte
   aus `coolify-template.json` / `.env.example`:

   | Variable | Pflicht | erzeugen mit |
   |----------|:------:|--------------|
   | `EUROUTER_API_KEY` | ✅ | dein eurouter.ai-Key |
   | `DATENSCHLEUSE_MASTER_KEY` | ✅ | `echo "sk-$(openssl rand -hex 32)"` (muss mit `sk-` beginnen) |
   | `DATENSCHLEUSE_STATE_KEY` | ✅ | `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
   | `UI_PASSWORD` | ✅ | `openssl rand -hex 32` |
   | `DATENSCHLEUSE_DB_PASSWORD` | ✅ | `openssl rand -hex 32` |
   | `UI_USERNAME` | – | Default `admin` |
   | `DATENSCHLEUSE_DB_USER` / `_NAME` | – | Default `datenschleuse` |
   | `DATENSCHLEUSE_STATE_TTL_SECONDS` | – | Default `86400` (24 h) |

3. **Domain vergeben:** Coolify erkennt am Service `datenschleuse` die
   `SERVICE_FQDN_DATENSCHLEUSE_4000`-Markierung und schlaegt automatisch eine
   Domain vor. Trag deine eigene ein (z. B. `https://datenschleuse.deine-domain.de`) —
   TLS via Let's Encrypt macht Coolifys Proxy automatisch.
4. **Deploy** klicken. Coolify baut die Images (LiteLLM + Presidio-Analyzer) und
   startet den Stack. Nur der `datenschleuse`-Service ist von aussen erreichbar;
   Postgres und Presidio bleiben im internen Netz.

---

## Weg B — ohne Coolify, direkt per Compose (One-Liner)

Auf jedem Docker-Host (Reverse-Proxy/TLS stellst du dann selbst davor):

```bash
git clone https://github.com/<dein-user>/datenschleuse.git && cd datenschleuse \
  && cp .env.example .env && $EDITOR .env \
  && docker compose -f deploy/coolify/docker-compose.yaml up -d --build
```

`.env` vorher mit echten Werten fuellen (siehe Tabelle oben). Ohne die
Pflicht-Variablen bricht der Start bewusst ab (fail-closed) — kein Proxy ohne
Master-Key, kein unverschluesselter State, kein Admin-UI mit Default-Passwort.

---

## Danach: Tool auf die Datenschleuse biegen

In deinem OpenAI-kompatiblen Client (Hermes, Cursor, …):

- **Base-URL:** `https://<deine-domain>/v1`
- **API-Key:** dein `DATENSCHLEUSE_MASTER_KEY`
- **Modell:** `datenschleuse-gpt`, `datenschleuse-claude` oder `datenschleuse-gemma`
  (die konfigurierten `model_name` aus `litellm/config.yaml`; `GET /v1/models`
  listet sie auf)

Admin-UI (Spend-Logs ohne Message-Content): `https://<deine-domain>/ui`
(Login: `UI_USERNAME` / `UI_PASSWORD`).

---

## Ehrliche Hinweise

- **Live gegen eine echte Coolify-Instanz getestet und verifiziert** (2026-07-23).
  Dabei zwei reale Bugs gefunden und gefixt, die kein lokaler Test gezeigt
  haette: (1) einzelne Datei-Bind-Mounts trafen eine Race in Coolifys
  Checkout-Kopierschritt und wurden dauerhaft zu leeren Verzeichnissen statt
  Dateien — behoben durch ausschliessliche Verzeichnis-Mounts (siehe Kommentar
  am Kopf von `docker-compose.yaml`). (2) Die Coolify-eigene Custom-Domain-
  Zuordnung (`SERVICE_FQDN_*`) laesst sich nach dem ersten Deploy nicht per
  Env-Var-Update nachtraeglich umbiegen — die Domain muss beim Anlegen der
  Resource oder danach manuell in der Coolify-UI gesetzt werden, nicht nur
  als Environment-Variable.
- **Health-Check-Endpoint** (`/health/liveliness`) gegen die konkret gebaute
  LiteLLM-Version gegenpruefen — die Schreibweise kann versionsabhaengig sein.
  Faellt der Check falsch-negativ aus, im Compose auskommentieren.
- **`DATENSCHLEUSE_MASTER_KEY`** wird in beiden Compose-Dateien (lokal und
  Coolify) explizit an den Container uebergeben, mit `:?`-Guard — kein Start
  ohne Auth moeglich.
