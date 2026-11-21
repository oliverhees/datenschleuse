# ADR-0006: Veröffentlichte Images, sichere Standards und feste Block-Kennung

- Status: vorgeschlagen
- Datum: 2026-11-21
- Work Item: [DATENSCHLE-105]

## Kontext

Die Datenschleuse wurde bisher nur aus dem Repo gebaut. Wer sie als Dienst in
ein eigenes Projekt einbindet, musste die Dockerfiles nachbauen, um sie ohne
Root, mit schreibgeschütztem Dateisystem und ohne Netz-Abrufe beim Start zu
betreiben. Drei Befunde aus dem Nachbau:

1. Das Proxy-Image installierte mit `ensurepip` + `pip install` aus
   Versionsbereichen — und installierte dabei nichts, weil das gepinnte
   LiteLLM-Basis-Image alle vier Pakete schon enthält.
2. Das Analyzer-Image lud das Sprachmodell per `spacy download` (Version zur
   Bauzeit aufgelöst) als UID 1001 in ein Home-Verzeichnis; mit `HOME=/tmp`
   wäre es nicht mehr gefunden und von Presidio beim Start nachgeladen worden.
   Der E-Mail-Recognizer lädt bei der ersten E-Mail-Adresse die
   Public-Suffix-Liste aus dem Netz; gunicorn 25.1 legt einen Steuer-Socket im
   Arbeitsordner an.
3. Ein Image, das ohne `DATENSCHLEUSE_MASTER_KEY` gestartet wird, nahm jede
   Anfrage an (LiteLLM 1.97.0 warnt nur und behandelt dann jeden Aufrufer als
   internen Nutzer; das Image lauscht auf `0.0.0.0`). Die Compose-Dateien
   verhindern das mit `${...:?}`, `docker run` des Images nicht (Sicherheits-
   Audit H1).
4. Eine blockierte Anfrage war für Clients nur am deutschen Freitext von
   anderen Proxy-Fehlern zu unterscheiden (beide HTTP 500, `type "None"`).

## Entscheidung

Beide Images werden aus dem Repo-Root gebaut, laufen ohne Mounts, ohne Root
und mit schreibgeschütztem Dateisystem, laden beim Start nichts und werden per
`.github/workflows/release.yml` für amd64/arm64 mit Herkunftsnachweis und SBOM
veröffentlicht; jeder Block trägt eine feste Kennung, deren Standardmodus
Status, Typ und Meldung unverändert lässt.

Der Proxy verweigert den Start ohne brauchbaren Master-Key
(`DATENSCHLEUSE_REQUIRE_MASTER_KEY=true` im Image). Die Prüfung sitzt im
Konstruktor des Guardrails und liest den Schlüssel, den LiteLLM auflöst
(Fallback: die Variable). Verlangt wird `sk-` plus mindestens 32 Zeichen, und
bekannte Platzhalter werden abgelehnt (Sicherheits-Audit Runde 2, M3): Die
`.env.example` lieferte `sk-datenschleuse-lokal` mit, ein öffentlich bekannter
Wert, der die erste Formprüfung (16 Zeichen) bestand. Jetzt ist der Wert in
der `.env.example` leer, `KNOWN_PLACEHOLDER_MASTER_KEYS` im Code enthält jeden
Wert, den das Repo je ausgeliefert hat, und die Meldung nennt den Wert nie.
Die Mindestlänge 32 passt zu `openssl rand -hex 32` (64 Zeichen) und zum
Coolify-Generator `random_hex_32` des Templates (ob 32 oder 64 Zeichen, ist
nicht geprüft; beides besteht). Folge für Bestandsinstallationen mit dem alten
Platzhalter: sie starten nach dem Update nicht mehr; Anleitung in
`docs/DEPLOY.md`. Die Prüfung erkennt nur bekannte Werte, keine Zufälligkeit:
ein eigener, schwacher Wert mit 32 Zeichen besteht.

## Alternativen

- **Start-Prüfung in einem Entrypoint-Skript.** Verworfen: das Skript müsste den
  Entrypoint des Basis-Images aufrufen, dessen Pfad ohne Docker nicht
  überprüfbar ist, und `--entrypoint` am `docker run` umgeht es. Der
  Konstruktor läuft bei jedem Start des Proxys mit dieser Konfiguration.
- **Prüfung ohne Schalter, immer aktiv.** Verworfen: Unit-Tests und
  Bibliotheksnutzung bräuchten dann einen Schlüssel. Der Schalter ist im Code
  aus und im Image an; ein Tippfehler im Wert schaltet die Sperre nicht ab
  (nur `false`, `0`, `no`, `off`, leer).

- **Block mit eigenem HTTP-Status als Standard (z. B. 422).** Verworfen als
  Standard: bestehende Clients erkennen Blocks heute an Status 500 plus
  `type "None"` plus Meldungstext; ein neuer Status hätte sie stumm in eine
  andere Fehlerklasse geschoben. Als Opt-in (`strict`) vorhanden.
- **Kennung in `error.code`.** Nicht möglich: LiteLLM schreibt dort immer den
  HTTP-Status. Gewählt: `error.provider_specific_fields.datenschleuse` (von
  LiteLLM unverändert durchgereicht) plus Antwort-Header.
- **Kennung als Präfix der Meldung.** Verworfen: ändert den Text, den Clients
  anzeigen oder loggen.
- **Lockfile mit Hashes für das Proxy-Image.** Unnötig, solange nichts
  installiert wird; die exakten Versionen werden stattdessen beim Bau geprüft
  (`litellm/runtime-pins.txt`). Für Test- und CI-Umgebung bleibt ein Lockfile
  offen (supply-chain.md §4).
- **Admin-UI im Repo-Compose abschalten.** Verworfen: die README dokumentiert
  `/ui` für dieses Setup. Abgeschaltet ist es nur im Image-Standard.
- **Proxy im Repo-Compose unter der Image-UID 65532.** Verworfen als Standard:
  die CLI schreibt die Regeldatei mit `0600` für den Host-Nutzer; der Proxy
  könnte sie nicht lesen und die eigenen Regeln wären aus. Gewählt:
  `DATENSCHLEUSE_UID`/`_GID`, Standard 1000.

## Konsequenzen

- Leichter: Einbindung als fertiger Dienst per Digest; Erkennung in einem Netz
  ohne Internet; Clients erkennen Blocks maschinell.
- Schwerer: Ein neuer Block-Grund ist eine Vertragsänderung
  (`BLOCK_REASONS`, security-baseline.md, Test). Ein Digest-Update des
  LiteLLM-Basis-Images muss `runtime-pins.txt` mitziehen, sonst bricht der Bau.
- Update-Bruch für Bestandsinstallationen: als root angelegtes QI-Volume und
  eine Regeldatei, die nicht der UID 1000 gehört (docs/DEPLOY.md, „Sichere
  Standards").
- Nicht verifiziert ohne Docker: echter Bau, Start mit Postgres als Nicht-Root.
  Der erste Release-Lauf (Smoke-Test, ohne Datenbank) ist die erste echte
  Probe.
