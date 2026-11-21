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
  && bash tools/init-env.sh && $EDITOR .env \
  && docker compose -f deploy/coolify/docker-compose.yaml up -d --build
```

`tools/init-env.sh` legt `.env` mit erzeugten Werten fuer Master-Key,
State-Key, Admin-UI- und Datenbank-Passwort an (gibt sie nicht aus, ueberschreibt
keine vorhandene `.env`); im Editor traegst du `EUROUTER_API_KEY` ein. Von Hand
geht es mit den Kommandos aus der Tabelle oben. Ohne die Pflicht-Variablen
bricht der Start bewusst ab (fail-closed) — kein Proxy ohne Master-Key, kein
unverschluesselter State, kein Admin-UI und keine Datenbank mit Beispiel-Passwort.

---

## Weg C — fertige Images (ab der ersten veröffentlichten Version)

Ab der ersten veröffentlichten Version (Git-Tag `v*`, gebaut von
`.github/workflows/release.yml`) gibt es fertige Images für `linux/amd64` und
`linux/arm64`; bauen musst du dann nichts mehr. **Bis dahin existieren diese
Images nicht** — Weg A und B bauen aus dem Repo.

| Image | Inhalt |
|---|---|
| `ghcr.io/oliverhees/datenschleuse:<version>` | Proxy (LiteLLM + Guardrail), Port 4000 |
| `ghcr.io/oliverhees/datenschleuse-analyzer:<version>` | Erkennung mit `de_core_news_lg` (alle Erkennungszahlen der README gelten für dieses Modell) |
| `ghcr.io/oliverhees/datenschleuse-analyzer:<version>-md` | Erkennung mit `de_core_news_md` — deutlich weniger Speicher, Erkennungsqualität **nicht** gemessen |

**Per Digest pinnen.** Ein Tag ist verschiebbar, ein Digest nicht — dieselbe
Regel, die dieses Repo für seine eigenen Basis-Images anwendet
(`docs/foundation/supply-chain.md`). Den Digest zeigt die Zusammenfassung des
Release-Laufs, oder:

```bash
docker buildx imagetools inspect ghcr.io/oliverhees/datenschleuse:<version>
```

In deiner Compose-Datei dann:

```yaml
services:
  datenschleuse:
    image: ghcr.io/oliverhees/datenschleuse:<version>@sha256:<digest>
  presidio-analyzer:
    image: ghcr.io/oliverhees/datenschleuse-analyzer:<version>@sha256:<digest>
```

Herkunftsnachweis und SBOM hängen am Image:

```bash
docker buildx imagetools inspect ghcr.io/oliverhees/datenschleuse:<version> \
  --format '{{ json .Provenance }}'
docker buildx imagetools inspect ghcr.io/oliverhees/datenschleuse:<version> \
  --format '{{ json .SBOM }}'
```

Was die Images ohne weitere Konfiguration mitbringen:

- **Laufen ohne Mounts.** Guardrail-Code, Schutzklassen-, Wortlisten- und
  Recognizer-Konfiguration sind im Image (`/app/config/`, `/conf/`). Mounten
  musst du nur, was du ändern willst — in der Regel `/app/config.yaml` mit
  deiner Modell-Liste. `recognizers-config.yml` muss im Proxy und im Analyzer
  **dieselbe** sein (beide Images aus derselben Version nehmen).
- **Kein Root.** Proxy UID 65532, Analyzer UID 1001.
- **Schreibgeschütztes Dateisystem möglich** (`read_only: true`). Beschreibbar
  sein müssen nur `/tmp` (beide) und `/app/state` (Proxy,
  verschlüsselter QI-Zustand). Gemessen ist das für den Proxy **ohne**
  Datenbank; mit Postgres führt LiteLLM beim Start Prisma-Migrationen aus —
  dafür ist ein schreibgeschütztes Dateisystem nicht geprüft.
- **Keine Netz-Abrufe beim Start**: Kostentabelle lokal, Sprachmodell und
  Public-Suffix-Liste sind im Image. Die Erkennung kann deshalb in einem
  Docker-Netz ohne Internet laufen (`internal: true`); nur der Proxy braucht
  den Weg zum Modell-Anbieter.
- **Healthcheck** in beiden Images (Proxy: `/health/liveliness`, Analyzer:
  `/health`, erst grün, wenn das Modell geladen ist).
- **gunicorn ohne Steuer-Socket** im Analyzer (`--no-control-socket`; der
  Socket entstünde sonst im schreibgeschützten Arbeitsordner).
- **Keine API-Doku-Seiten** (`/docs`, `/redoc`, `/openapi.json` antworten 404)
  und **Admin-UI aus** (`DISABLE_ADMIN_UI=True`). Gemessen gegen LiteLLM
  1.97.0: Das UI meldet sich dann als abgeschaltet und verweigert die
  SSO-Anmeldung; die statischen Dateien unter `/ui` werden weiter
  ausgeliefert, und ohne Datenbank kann keine UI-Sitzung entstehen. Wer das UI
  will, setzt `DISABLE_ADMIN_UI=False` und betreibt die Datenbank wie im
  Repo-Compose.
- **Bilder blockiert** (`DATENSCHLEUSE_IMAGE_POLICY=block`).
- **Kein Start ohne Master-Key.** (Image: `ENV DATENSCHLEUSE_REQUIRE_MASTER_KEY=true`;
  die drei Compose-Dateien dieses Repos setzen den Schalter zusätzlich selbst
  im `environment:` des Proxys, damit auch ein älteres, nicht neu gebautes
  Image geprüft wird.) Fehlt `DATENSCHLEUSE_MASTER_KEY`, ist er leer,
  hat er nicht die Form `sk-` plus mindestens 32 Zeichen ohne Leerzeichen
  oder ist er ein öffentlich bekannter Platzhalter (zum Beispiel der frühere
  Wert aus der `.env.example`), beendet sich der Proxy beim Start mit einer
  Fehlermeldung (ohne den Wert zu nennen). Das gilt auch bei `docker run` ohne Compose; ohne diese Sperre würde
  LiteLLM nur warnen und jede Anfrage durchlassen, obwohl der Proxy im Container
  auf `0.0.0.0` lauscht. Geprüft wird der Schlüssel, den LiteLLM aus deiner
  Konfiguration auflöst (nicht nur die Variable). Gemessen mit LiteLLM 1.97.0
  ohne Docker (Prozess-Exit-Code selbst gelesen, 2026-11-21): ohne Schlüssel
  und mit `bad-key` bricht der Start ab, Exit-Code 3 (das Log endet mit
  „Application startup failed“); mit `sk-` plus 40 Zeichen Start. Der Image-Test dazu (`test/smoke-images.sh`)
  lief noch nicht, weil hier kein Docker vorhanden war. Nur wer bewusst ohne
  Anmeldung hinter einem eigenen Gateway arbeitet, schaltet die Prüfung mit
  `DATENSCHLEUSE_REQUIRE_MASTER_KEY` ab (die erlaubten Werte stehen in
  „Beispiel-Zugangsdaten werden abgelehnt“ unten) — nicht empfohlen.
  Die Prüfung erzwingt die Form (`sk-` plus mindestens 32 Zeichen) und
  weist bekannte Platzhalter ab; ob ein Schlüssel zufällig und geheim ist,
  kann sie nicht beurteilen: Ein Wert wie `sk-` plus 32-mal `a` besteht.

Pflicht-Variablen bleiben dieselben wie oben (`DATENSCHLEUSE_MASTER_KEY`,
`DATENSCHLEUSE_STATE_KEY`, solange `qi_risk_preset` gesetzt ist, und der
Anbieter-Schlüssel deiner `config.yaml`). Die Analyzer-URL setzt
`PRESIDIO_ANALYZER_API_BASE` (Standard `http://presidio-analyzer:3000`).

Hinweis für den Betreiber des Repos: Ein neu angelegtes GHCR-Paket ist
zunächst privat und muss nach dem ersten Release einmal auf „public"
gestellt werden.

---

## Sichere Standards und was sich beim Update ändert

Das lokale `docker-compose.yml` ist seit dem Image-Paket strenger. Wer von
einem älteren Stand kommt:

| Was | Jetzt | Zurück zum alten Verhalten |
|---|---|---|
| Port 4000 | nur `127.0.0.1` | `DATENSCHLEUSE_BIND=0.0.0.0` in der `.env` (dann gehört TLS davor) |
| Port 5001 (Analyzer, nur Benchmark) | nur `127.0.0.1` | — |
| Proxy-Nutzer | `DATENSCHLEUSE_UID`/`_GID`, Standard `1000:1000` | muss der Eigentümer von `rules/custom-rules.yml` sein, sonst sind die eigenen Regeln aus (siehe unten) |
| Debug-Log | aus (`--detailed_debug` und `set_verbose` entfernt) | siehe „Fehlersuche" |
| Presidio-Anonymizer | nicht mehr im Standard-Stack (der Guardrail ruft ihn nie auf) | `docker compose --profile anonymizer up -d` |
| API-Doku-Seiten | aus | — |
| Admin-UI | bleibt an (`DISABLE_ADMIN_UI=False`), das Image allein hat es aus | `DATENSCHLEUSE_DISABLE_ADMIN_UI=True` schaltet es auch hier ab; LiteLLM erkennt nur `True`/`False`, jeder andere Wert (auch `1`, `yes`) lässt das UI an |
| Analyzer | schreibgeschützt, Start des Proxys erst, wenn der Analyzer gesund ist | — |
| Block-Antwort | trägt die feste Kennung, Status unverändert 500 | `DATENSCHLEUSE_BLOCK_RESPONSE=strict` für HTTP 422 (siehe README) |
| Master-Key | `sk-` plus mindestens 32 Zeichen, kein bekannter Platzhalter | kein Weg zurück: ein öffentlich bekannter Key ist keine Anmeldung |
| Admin-UI-Passwort | `UI_PASSWORD` mindestens 16 Zeichen, kein leerer oder bekannter Beispielwert (sonst startet der Proxy nicht, sobald die Datenbank konfiguriert ist) | neues Passwort setzen (siehe unten); kein Weg zurück |
| Datenbank-Passwort | `DATENSCHLEUSE_DB_PASSWORD` ist Pflicht ohne Default (vorher im Repo-Compose `datenschleuse`); bekannte Beispielwerte werden abgelehnt | Passwort setzen, bei bestehender Datenbank zusätzlich in Postgres ändern (siehe unten) |
| Schalter `DATENSCHLEUSE_REQUIRE_MASTER_KEY` | unter dem Proxy auch ohne gesetzte Variable an (vorher: aus, wenn die Variable fehlte) | nur ausdrücklich abschalten: `false`, `0`, `no` oder `off` |

**Master-Key: Platzhalter werden abgelehnt.** Die `.env.example` lieferte früher
den Wert `sk-datenschleuse-lokal` mit. Wer sie unverändert nach `.env` kopiert
hat, dessen Datenschleuse startet nach dem Update nicht mehr (das Log nennt den
Grund, nie den Wert); dasselbe gilt für andere bekannte Platzhalter und für
Keys mit weniger als 32 Zeichen nach `sk-`. Neuen Key erzeugen, in die `.env`
eintragen und **neu bauen und starten**. `docker compose up -d` allein baut ein
vorhandenes Image nicht neu; die Compose-Dateien dieses Repos setzen den
Schalter zwar selbst, ein Neubau holt aber auch den übrigen Code des neuen
Stands ins Image. Je nach Installationsweg:

```bash
echo "sk-$(openssl rand -hex 32)"     # Ausgabe als DATENSCHLEUSE_MASTER_KEY in die .env

# Weg B / lokal (docker-compose.yml im Repo-Root), nach git pull:
docker compose up -d --build

# Weg B (deploy/coolify/docker-compose.yaml ohne Coolify), nach git pull:
docker compose -f deploy/coolify/docker-compose.yaml up -d --build

# Coolify: neuen Wert unter „Environment Variables“ eintragen und „Deploy“
# (Redeploy) auslösen; Coolify baut aus dem Compose-File neu.

# Weg C (fertige Images): neue Image-Version (Tag und Digest) eintragen, dann
docker compose pull && docker compose up -d
```

Nicht mit Docker ausgeführt (kein Docker-Daemon in der Entwicklungsumgebung):
das Verhalten von `up -d` ohne `--build` und der Coolify-Redeploy sind aus den
Compose-Dateien und der Compose-Dokumentation abgeleitet, nicht gemessen. Die
Compose-Dateien sind per Test geprüft (der Schalter steht in jedem
`environment:` des Proxys), geparst und mit `docker compose config` gelesen.

Danach den neuen Key in allen Tools eintragen, die die Datenschleuse
ansprechen (der alte war öffentlich bekannt).

**Nutzer-ID und eigene Regeln.** Die CLI legt `rules/custom-rules.yml` mit den
Rechten `0600` an, lesbar nur für ihren Eigentümer. Läuft der Proxy unter
einer anderen UID, kann er die Datei nicht lesen: die eigenen Regeln sind dann
aus (das Log meldet „nicht lesbar"), Presidio maskiert weiter. Prüfen und
setzen:

```bash
stat -c '%u:%g' rules/custom-rules.yml    # Eigentümer
echo "DATENSCHLEUSE_UID=$(id -u)" >> .env
echo "DATENSCHLEUSE_GID=$(id -g)" >> .env
```

**Bestehendes Volume mit dem QI-Zustand.** Ältere Stände liefen als root; das
Volume `datenschleuse-qi-state` gehört dann root, und der Proxy startet als
Nicht-Root nicht (die verschlüsselte SQLite-Datei ist nicht beschreibbar).
Der Inhalt ist nur der TTL-begrenzte Sitzungszustand der Quasi-Identifier
(Standard 24 h); ihn zu verwerfen setzt nur diese Akkumulation zurück:

```bash
docker compose stop datenschleuse
docker compose rm -f datenschleuse
docker volume rm datenschleuse_datenschleuse-qi-state   # Projektname ggf. anders: docker volume ls
docker compose up -d --build
```

Nicht verifiziert (kein Docker-Test in dieser Umgebung): der Start des
Repo-Compose mit Postgres und Admin-UI als Nicht-Root. Den ersten echten
Lauf zeigt der Smoke-Test des Release-Workflows — der prüft allerdings den
Proxy **ohne** Datenbank. Startet der Proxy mit Datenbank als Nicht-Root
nicht, ist `DATENSCHLEUSE_UID=0` ein Notausgang (läuft dann wieder als root):
nur vorübergehend, bis der Fehler behoben ist, und bitte als Fehler melden.
Dauerhaft als root zu laufen hebt die Sperren dieses Abschnitts auf.

### Beispiel-Zugangsdaten werden abgelehnt

Die `.env.example` liefert keine nutzbaren Geheimnisse mehr: Master-Key,
Admin-UI-Passwort und Datenbank-Passwort sind leer, der State-Key ein
Platzhalter, den der Proxy nicht annimmt. Der Proxy prüft beim Start (im
Guardrail, auf jedem ausgelieferten Startweg):

| Wert | Bedingung für den Start |
|---|---|
| `DATENSCHLEUSE_MASTER_KEY` | `sk-` plus mindestens 32 Zeichen, kein bekannter Platzhalter |
| `UI_PASSWORD` | mindestens 16 Zeichen, nicht leer, kein bekannter Beispielwert; fehlt es, muss das Admin-UI abgeschaltet sein (dann gilt der Master-Key als Passwort) |
| Passwort in `DATABASE_URL` (`DATENSCHLEUSE_DB_PASSWORD`) | kein bekannter Beispielwert; die Stärke prüft der Proxy nicht, die Datenbank kann extern sein |

Die Passwörter werden geprüft, sobald `DATABASE_URL` gesetzt ist, auch bei
`DISABLE_ADMIN_UI=True`: In LiteLLM 1.97.0 ignoriert `POST /login` diesen
Schalter und meldet jeden als Admin an, der `UI_USERNAME`/`UI_PASSWORD` kennt;
ein gesetzter, aber leerer `UI_PASSWORD` bleibt leer. (Gemessen ohne Docker mit
dem echten Proxy: leeres Passwort, `DISABLE_ADMIN_UI=True` → die Anmeldung
kommt bis zum Datenbankschritt, ein falsches Passwort wird mit 401 abgelehnt.)
Meldungen nennen nur den Namen der Variable, nie den Wert.

**Der Schalter** `DATENSCHLEUSE_REQUIRE_MASTER_KEY` steuert alle drei Prüfungen:

- Abgeschaltet wird sie nur mit einem dieser Werte (Groß-/Kleinschreibung und
  Leerzeichen am Rand egal): `false`, `0`, `no`, `off`. Nicht empfohlen.
- Jeder andere Wert mit Inhalt (auch ein Tippfehler wie `flase`) lässt die
  Prüfung an.
- Fehlt die Variable oder ist sie leer, ist die Prüfung unter dem Proxy an;
  nur ohne den Proxy-Server (Unit-Tests, Bibliotheksnutzung) bleibt sie aus.
- Die Compose-Dateien reichen `${DATENSCHLEUSE_REQUIRE_MASTER_KEY:-true}`
  durch. Eine in der Shell exportierte Variable hat Vorrang vor der `.env`
  (mit `docker compose config` geprüft, 2026-11-21); ein leerer Wert in der
  `.env` wird zu `true`.

**Wenn du ein Beispiel-Passwort benutzt hast** (die `.env` stammt aus einer
älteren `.env.example`): Der Proxy startet nach dem Update nicht mehr, das Log
nennt die Variable. Neue Werte erzeugen und eintragen:

```bash
openssl rand -hex 32     # neues UI_PASSWORD in die .env
openssl rand -hex 32     # neues DATENSCHLEUSE_DB_PASSWORD in die .env
```

Das Datenbank-Passwort legt Postgres nur beim **ersten** Start an. Eine
bestehende Datenbank behält ihr altes Passwort, auch wenn du die `.env`
änderst; `DATABASE_URL` passt dann nicht mehr zur Datenbank. Wer das Passwort
nie gesetzt hatte (früher Standard im Repo-Compose: `datenschleuse`) oder die
Beispielzeile der alten `.env.example` benutzt hat, ändert es **in der laufenden
Datenbank**, solange der alte Stack noch läuft, und trägt danach denselben
neuen Wert in die `.env` ein:

```bash
# 1. neuen Wert erzeugen und merken (er kommt gleich in die .env)
openssl rand -hex 32
# 2. in der laufenden Datenbank setzen (psql fragt zweimal nach dem Passwort).
#    Der Vorsatz DATENSCHLEUSE_DB_PASSWORD=x ist nur nötig, wenn Compose die
#    Variable zum Einlesen verlangt; exec ändert den laufenden Container nicht.
DATENSCHLEUSE_DB_PASSWORD=x docker compose exec datenschleuse-db \
  sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
#    in psql:   \password          (dann \q)
# 3. denselben Wert als DATENSCHLEUSE_DB_PASSWORD in die .env, dann:
docker compose up -d --build
```

Einfacher, wenn die Spend-Logs (nur Zeit, Modell, Kosten, nie Nachrichteninhalt)
verzichtbar sind: Stack stoppen, das Volume `datenschleuse-db-data` löschen
(`docker volume ls` zeigt den Namen mit Projektpräfix), neue Werte in die `.env`,
`docker compose up -d --build`. Postgres legt die Datenbank dann mit dem neuen
Passwort neu an.

Nicht mit Docker ausgeführt (kein Docker-Daemon in der Entwicklungsumgebung):
der Start von Postgres mit dem neuen `:?`-Guard, die `psql`-Schritte oben, das
Verhalten von `up -d` bei bestehender Datenbank und der Coolify-Redeploy.
Gemessen ist: `docker compose config` bricht bei fehlendem oder leerem
`UI_PASSWORD` und `DATENSCHLEUSE_DB_PASSWORD` mit Meldung ab; der echte Proxy
(LiteLLM 1.97.0, ohne Docker) lehnt die Fälle der Tabelle ab.

### Fehlersuche: ausführliche Logs

Ausführliche Logs sind ein bewusster, vorübergehender Schritt: Sie können
Teile von Anfragen enthalten. Für die Dauer der Fehlersuche in einer
`docker-compose.override.yml` (ist in `.gitignore`):

```yaml
services:
  datenschleuse:
    command: ["--config", "/app/config.yaml", "--port", "4000", "--detailed_debug"]
```

Danach die Datei wieder löschen und neu starten.

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

## Bilder: Policy und Compose-Profil `images`

- **Compose-/Coolify-Standard ist `block`:** Bild-Anhaenge werden abgelehnt
  (fail-closed). Das gilt fuer `docker compose up` (Compose setzt die Variable
  explizit) und fuer Coolify. Der **Code-Default** des Guardrails (ohne gesetzte
  Policy) haengt dagegen von `PRESIDIO_IMAGE_REDACTOR_API_BASE` ab: ist die URL
  gesetzt, waehlt er `redact`, sonst `block`.
- **`redact` (Bilder schwaerzen)** braucht den optionalen Dienst
  `presidio-image-redactor`. Er liegt hinter dem Compose-Profil `images` und
  startet nur so:

  ```bash
  # .env: DATENSCHLEUSE_IMAGE_POLICY=redact
  docker compose --profile images up -d
  ```

- **Was der Client sieht:** nur "Bild-Anhaenge sind blockiert. Bitte den
  Betreiber kontaktieren." Die Aktivierungsanleitung (Profil `images` plus
  `DATENSCHLEUSE_IMAGE_POLICY=redact`, nur Docker-Compose-Self-Hosting) steht
  im Server-Log des Proxys (`docker compose logs datenschleuse`) und in diesem
  Abschnitt. Das Log enthaelt keinen Bild- oder Client-Inhalt.
- **`pass`** laesst Bilder ungeprueft durch — eine bewusste Datenschutzluecke,
  nur setzen, wenn du das willst.
- **Coolify:** Bilder sind dort standardmaessig blockiert. `redact` ist auf
  Coolify nicht vorgesehen: `deploy/coolify/docker-compose.yaml` enthaelt weder
  den Redactor-Dienst noch die Variable `DATENSCHLEUSE_IMAGE_POLICY`
  (deshalb steht sie auch nicht in `coolify-template.json`).
- **Upgrade fuer Bestandsinstallationen:** Wer den Stack vor dieser Aenderung
  gestartet hat, hat evtl. noch einen laufenden alten Redactor-Container
  (`datenschleuse-image-redactor`). Er wird durch ein neues `docker compose up`
  nicht entfernt. Gezielt abraeumen mit
  `docker compose --profile images rm -sf presidio-image-redactor` bzw.
  `docker rm -f datenschleuse-image-redactor`.
  **Nicht `docker compose down` verwenden:** `down` stoppt den GANZEN Stack,
  nicht nur den Redactor.
  *Nicht verifiziert (kein Docker-Test)* — der Containername stammt aus
  `docker-compose.yml`, die Befehle wurden nicht ausgefuehrt.

---

## Nicht-PII-Wortliste und Recognizer-Config (DATENSCHLE-82)

Der Guardrail laedt beim Start `de-stopwords.yml` und prueft sie gegen die
`deny_list`-Terme aus `recognizers-config.yml` (Betreiber-Vorrang). Beides
muss im Container ankommen, sonst startet der Dienst bewusst nicht
(`StopwordConfigError`, fail-closed):

- Das Modul `de_stopwords.py` kommt per `COPY` ins Image
  (`litellm/Dockerfile`).
- `docker-compose.yml`: beide YAML-Dateien werden aus `./presidio/` nach
  `/app/config/` gemountet, `DATENSCHLEUSE_STOPWORDS_PATH` und
  `DATENSCHLEUSE_RECOGNIZERS_PATH` zeigen darauf.
- Coolify: Verzeichnis-Mount `../../presidio` nach `/mnt/presidio-src`, die
  beiden ENVs zeigen auf Dateien darin (kein Einzeldatei-Mount, s.o.).

**Invariante: Guardrail und Analyzer muessen DIESELBE
`recognizers-config.yml` lesen.** Die Vorrangspruefung liest die Datei im
Guardrail-Container, der Analyzer laedt seine eigene. Beide Container mounten
deshalb dieselbe Host-Datei (in Compose und in Coolify). Wer die Datei fuer
einen der beiden Dienste an eine andere Stelle legt, verliert den Vorrang
unbemerkt. `test/test_deploy_layout.py` prueft die Gleichheit der Host-Quellen
und simuliert das Container-Layout aus den Dateien.

Ehrlich zur Reichweite: Das ist eine Simulation aus den Compose- und
Dockerfile-Dateien. Ein echter Image-Build und Container-Start wurde fuer
diese Aenderung **nicht** ausgefuehrt, und die Coolify-Live-Verifikation
(siehe unten) stammt aus der Zeit davor.

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
