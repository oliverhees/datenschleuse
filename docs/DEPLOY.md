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
   | `DATENSCHLEUSE_REID_KEY` | – | Fernet-Key wie oben. Ohne ihn erzeugt die Guardrail beim Start einen **prozesslokalen** — richtig fuer einen Worker, **falsch ab zwei**: mehrere Worker teilen dann keinen Schluessel und die Re-Identifikation schlaegt scheinbar zufaellig fehl. Die Guardrail warnt beim Start. |
   | `DATENSCHLEUSE_REID_TTL` | – | Default `3600` (1 h). Muss > 0 sein — ein Wert <= 0 bricht den Start ab, statt die Re-Identifikation still abzuschalten. |
   | `DATENSCHLEUSE_APPROVAL_HEADER_SECRET` | – | `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`. Schaltet den **Header-Freigabeweg fuer Schutzklasse 2** ein. Ohne ihn ist dieser Weg AUS (sicherer Default) — nicht "offen fuer alle". Mindestens 32 Zeichen: der Schalter schaltet Schutz AB, ein ratbares Geheimnis ist auf ihm keines. Wird beim Start geprueft, der Proxy startet sonst nicht. Siehe unten. |
   | `DATENSCHLEUSE_MAX_ANALYZER_CALLS` | – | Default `1200`. Obergrenze fuer Presidio-Analyseaufrufe **pro Request** — die eigentliche Kostenbremse. Siehe unten. |
   | `DATENSCHLEUSE_MAX_MESSAGES` | – | Default `4096`. Obergrenze fuer die Anzahl Nachrichten pro Request (Strukturgroesse). Siehe unten. |

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

## Die drei Schutz- und Grenzschalter

Alle drei sind optional und haben brauchbare Vorgaben. Wer sie nicht setzt,
bekommt den sicheren Fall. Wer sie falsch setzt, erfaehrt es **beim Start** —
nicht beim ersten Request.

### `DATENSCHLEUSE_APPROVAL_HEADER_SECRET` — Freigabe fuer Schutzklasse 2

Die Datenschleuse stuft jede Anfrage in Schutzklassen ein. Stufe 3 blockt
immer. Stufe 2 blockt ebenfalls — **es sei denn**, der Betreiber hat sie
freigegeben. Freigeben darf ausschliesslich der Betreiber, nie der Client:
ein Gate, das der Kontrollierte selbst abschalten kann, ist kein Gate.

Es gibt zwei Betreiber-Wege. Der eine ist die Key-/Team-Konfiguration im
Proxy. Der andere ist dieser Header — und der ist **nur aktiv, wenn ein
Geheimnis konfiguriert ist**. Ohne Geheimnis waere der Header wieder blosse
Client-Eingabe.

```bash
# Geheimnis erzeugen
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

```bash
# Verwenden (Client-Seite)
curl ... -H "X-Datenschleuse-Sensitivity-Approval: <das Geheimnis>"
```

Beim Start geprueft, der Proxy startet sonst gar nicht erst:

- muss eine Zeichenkette sein,
- mindestens **32 Zeichen** — es soll **erzeugt** und nicht ausgedacht
  werden; eine deutsche Passphrase mit 32+ Zeichen ist zulaessig,
- als UTF-8 darstellbar,
- nicht nur Leerzeichen (das wuerde den Weg still abschalten, waehrend die
  Konfiguration so aussieht, als sei er aktiv).

Der Wert wird konstantzeitig verglichen und danach **in jedem Fall**
redigiert — auch bei falschem Wert, auch wenn die Pruefung fehlschlaegt.
Er wandert nicht ins Log.

### `DATENSCHLEUSE_MAX_ANALYZER_CALLS` — die Kostenbremse

Jedes Textfragment einer Anfrage geht einzeln an Presidio. Das sind nicht
nur die Nachrichten: auch jeder Text-Part, jeder `tool_calls`-Eintrag, jeder
Schluessel und Wert in `arguments`, jedes Feld in `tools`. Eine **einzige**
Nachricht kann damit zehntausende Aufrufe ausloesen.

Der Default `1200` ist so hergeleitet:

- **gemessen:** rund 23,6 ms pro Analyseaufruf,
- **gesetzt:** 30 s als Obergrenze fuer die Zeit, die eine *einzelne*
  Anfrage einen Worker belegen darf — das ist eine Betreiber-Toleranz,
  keine Messung,
- 30 s / 23,6 ms ≈ 1271 → abgerundet 1200.

Zur Groessenordnung: ein normaler Chat mit fuenf Nachrichten kostet fuenf
Aufrufe. Er sieht die Grenze nie. Wer sehr grosse Tool-Schemata oder viele
Bild-Parts faehrt, hebt sie an:

```bash
DATENSCHLEUSE_MAX_ANALYZER_CALLS=3000
```

Die Blockmeldung nennt immer, wie viele Aufrufe die Anfrage gebraucht haette
— damit klar ist, um welche Groessenordnung es geht, statt nur, dass etwas
zu gross war.

### `DATENSCHLEUSE_MAX_MESSAGES` — die Strukturgroesse

Begrenzt die Anzahl Nachrichten pro Anfrage. Seit dem Analyzer-Budget ist
das **nicht** mehr die Kostenbremse, sondern nur noch eine Schranke gegen
absurd grosse Historien (100 000 leere Nachrichten kosten null Analysen,
aber sehr wohl Speicher).

Der Default `4096` entspricht rund 1350 Tool-Runden — weit jenseits dessen,
was eine einzelne Agenten-Sitzung erreicht. Der frühere Wert von 256 fiel
nach rund 85 Tool-Runden und traf damit Coding-Agenten im Normalbetrieb.

**Wichtig zu wissen:** Dieser Block wiederholt sich. Der Client schickt die
Historie beim naechsten Versuch erneut mit, also blockt auch der
Folge-Request. Die Meldung sagt das ausdruecklich und nennt den Schalter —
sonst waere die Sitzung tot, ohne dass jemand weiss warum.

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
