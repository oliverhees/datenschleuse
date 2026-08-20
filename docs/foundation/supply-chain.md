# Supply-Chain-Härtung

> Bindend per Gesetz 5 (Security & Secrets) und Gesetz 12 (Grundbuch).
> Ergänzt `security-baseline.md` um die konkrete Umsetzung.
> Eingeführt mit DATENSCHLE-59.

Die Datenschleuse ist ein Sicherheitsprodukt. Wer sie betreibt, vertraut uns
personenbezogene Daten an. Also muss nachträglich feststellbar sein, **welche
Software** wir ausgeliefert haben — und zwar bis auf das Byte.

Dieses Dokument regelt drei Dinge:

1. wie Container-Images gepinnt werden und wie ein Update abläuft,
2. wie GitHub-Actions gepinnt werden und wie ein Update abläuft,
3. (Abschnitt 3, siehe unten) wie der CVE-Scan blockiert und wie mit Funden
   umgegangen wird, die wir nicht beheben können.

---

## 1. Container-Images: Tag **und** Digest

### Regel

Jede Image-Referenz im Repo trägt einen **Versions-Tag UND einen Digest**:

```
ghcr.io/berriai/litellm:v1.97.0@sha256:468c25f3...
```

- Der **Digest** ist die Garantie. Er ist der Hash des Manifests; er kann sich
  nicht ändern, ohne ein anderes Image zu werden. Docker zieht bei dieser
  Schreibweise ausschließlich nach Digest — der Tag wird beim Auflösen ignoriert.
- Der **Tag** ist die Lesehilfe. Er sagt einem Menschen (und dem nächsten Agent),
  *was* da eigentlich drin steckt. Ein nackter Digest ohne Tag ist reproduzierbar,
  aber unlesbar; niemand sieht ihm an, ob er drei Tage oder drei Jahre alt ist.

**Verboten sind** `:latest`, `:main-latest` und jeder andere rollende Tag ohne
Digest. Begründung am konkreten Fall: `ghcr.io/berriai/litellm:main-latest` trug
am 2026-08-19 das Label `org.opencontainers.image.revision=007bd43c` — ein
BerriAI-Commit von **demselben Tag, 03:31 UTC**. Der Tag rollt also mit jedem
Merge auf `main`. Zwei `docker compose up` am selben Nachmittag konnten
unterschiedliche Software starten, und im Nachhinein war nicht mehr feststellbar,
welche.

### Aktueller Stand (2026-08-19)

| Datei | Service | Referenz |
|-------|---------|----------|
| `litellm/Dockerfile` | LiteLLM-Basis | `ghcr.io/berriai/litellm:v1.97.0@sha256:468c25f35f3e5ec4e414974f00deab93337b1b4d9953cabcfd3722e59415f834` |
| `presidio/Dockerfile.analyzer` | Analyzer-Basis | `mcr.microsoft.com/presidio-analyzer:2.2.362@sha256:286e3fa7f3a7426e775e8564fe1870f1ba8f999d3ab8bbb8cc46a44355d9d6e9` |
| `docker-compose.yml` | Postgres | `postgres:16.15-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685` |
| `docker-compose.yml` | Anonymizer | `mcr.microsoft.com/presidio-anonymizer:2.2.362@sha256:a10a12a2a613d13cf29d3ad3641e3258444dd8c90403dd644a0a114c472c2483` |
| `docker-compose.yml` | Image-Redactor | `mcr.microsoft.com/presidio-image-redactor:0.0.58@sha256:e49fd47bfc38d834f0856063b9f00cfb3c19866e8d61b061849baf6275139612` |
| `deploy/coolify/docker-compose.yaml` | Postgres | `postgres:16.15-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685` |
| `deploy/coolify/docker-compose.yaml` | Anonymizer | `mcr.microsoft.com/presidio-anonymizer:2.2.362@sha256:a10a12a2a613d13cf29d3ad3641e3258444dd8c90403dd644a0a114c472c2483` |

Beachten: Der Image-Redactor hat eine **eigene Versionsreihe (0.0.x)**, nicht die
2.2.x der übrigen Presidio-Dienste. Wer blind „alle Presidio-Images auf dieselbe
Version" setzt, baut einen Fehler ein.

### Update-Verfahren (Digest-Update)

Pinning ohne Update-Verfahren ist kein Sicherheitsgewinn, sondern eine Zeitbombe:
Die Software friert ein, beim ersten ernsten CVE umgeht jemand das Pinning, und
danach ist es wertlos. Deshalb ist der Update-Weg hier festgeschrieben.

**Wer:** derjenige Teammate, der das Update-Work-Item zugewiesen bekommt. Ein
Digest-Update ist **immer ein eigenes Work Item** — nie eine Beifügung zu einem
fachlichen PR. Sonst vermischen sich „das Feature ist kaputt" und „das neue
Basis-Image ist kaputt" in einem Diff.

**Auslöser** (einer genügt):

- Der wöchentliche Image-CVE-Scan meldet einen blockierenden Fund (Abschnitt 3).
- Upstream veröffentlicht ein Security-Release.
- Routine: spätestens **quartalsweise** prüfen, auch ohne Fund. Ein Pin, den ein
  Jahr niemand angefasst hat, ist kein Pin mehr, sondern ein Fossil.

**Wie:**

```bash
# 1. Welchen Tag wollen wir? Immer ein veroeffentlichtes Release,
#    NIE ein -dev/-rc/-latest.
gh api "repos/BerriAI/litellm/releases?per_page=20" \
  --jq '.[] | select(.prerelease==false) | .tag_name'

# 2. Digest aufloesen -- niemals abschreiben, immer aufloesen lassen.
docker buildx imagetools inspect ghcr.io/berriai/litellm:<NEUER-TAG>
#    -> "Digest: sha256:..."

# 3. Tag UND Digest in die Datei eintragen (beides, nicht nur eins).

# 4. Lokal bauen und gegenpruefen, dass der Custom-Code im neuen Basis-Image
#    ueberhaupt noch importierbar ist:
docker build -t datenschleuse-litellm:verify ./litellm
docker run --rm --entrypoint python datenschleuse-litellm:verify -c \
  "import importlib.metadata as md, datenschleuse_guardrail, qi_state, \
   qi_generalization, sensitivity_classifier; print(md.version('litellm'))"

# 5. Testsuite gruen (Gesetz 2), dann PR. Der Image-CVE-Scan laeuft auf diesem
#    PR automatisch mit, weil die gepinnten Dateien im Diff sind.
```

**Was ins Work Item gehört** (Gesetz 1): alter Digest, neuer Digest, Grund für
das Update, und der Output von Schritt 4. Damit ist später beantwortbar, warum
genau dieser Stand ausgeliefert wurde.

### Was NICHT gepinnt ist — und warum

- `runs-on: ubuntu-latest` in der CI. Das ist kein Image, das wir ausliefern,
  sondern die Wegwerf-VM von GitHub. Ein Pin auf `ubuntu-24.04` würde nur den
  Zeitpunkt verschieben, an dem GitHub das Label abkündigt.
*(`deploy/coolify/docker-compose.yaml` war bis zum Security-Audit von
DATENSCHLE-59 ungepinnt — siehe „Der blinde Fleck" in Abschnitt 3.)*

---

## 2. GitHub-Actions: SHA statt Tag

### Regel

Jede `uses:`-Zeile in `.github/workflows/` zeigt auf einen **Commit-SHA**, mit
dem Versions-Tag als Kommentar dahinter:

```yaml
- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
```

Warum: Ein Action-Tag wie `@v4` ist ein bewegliches Git-Ref im *fremden* Repo.
Wer es verschiebt, führt beliebigen Code in unserer CI aus — mit unserem
`GITHUB_TOKEN` und Zugriff auf den Checkout. Das ist der klassische
Action-Hijack (tj-actions/changed-files, März 2025) und kein theoretisches Risiko.

Der Kommentar `# v4.4.0` ist **nur Lesehilfe**. Verbindlich ist der SHA. Deshalb
gilt: Der Kommentar wird beim Update mitgezogen, und ein Reviewer, der ihm nicht
traut, löst ihn selbst auf (Befehl unten).

### Aktueller Stand (2026-08-19)

| Action | SHA | Tag |
|--------|-----|-----|
| `actions/checkout` | `11d5960a326750d5838078e36cf38b85af677262` | v4.4.0 |
| `actions/setup-python` | `a26af69be951a213d495a4c3e4e4022e16d87065` | v5.6.0 |
| `gitleaks/gitleaks-action` | `ff98106e4c7b2bc287b24eaf42907196329070c7` | v2.3.9 |
| `aquasecurity/trivy-action` | `ed142fd0673e97e23eac54620cfb913e5ce36c25` | v0.36.0 |

**Gelernt an der eigenen Regel** (DATENSCHLE-59, Security-Audit): `trivy-action`
stand zuerst auf `a9c7b0f06e461e9d4b4d1711f154ee024b8d7ab8`. Das ist **nicht der
Commit**, sondern das *annotierte Tag-Objekt* von `v0.36.0` — genau der Fall, vor
dem das Update-Verfahren unten warnt. Die Regel wurde in demselben PR aufgestellt
und in demselben PR verletzt. Vier Stellen (`ci.yml` 2x, `image-scan.yml` 2x)
zeigen jetzt auf den dereferenzierten Commit `ed142fd0`.

**Warum das mehr ist als ein Schönheitsfehler — und was NICHT das Argument ist.**

Zuerst die Klarstellung, weil das Gegenteil naheliegt und falsch ist: Ein
annotiertes Tag-Objekt ist **nicht** unsicherer im Sinne der Integrität. Git ist
content-addressed; Commits, Trees, Blobs *und* Tag-Objekte sind unveränderlich.
`git tag -f` erzeugt ein **neues** Objekt mit **neuer** ID — verschiebbar ist der
Ref-*Name* `refs/tags/v0.36.0`, niemals die ID `a9c7b0f0`. Der alte Pin war
weder kaputt noch manipulierbar, und er lief grün (Run `32253275837`).

Die echten Gründe sind andere:

- **Erreichbarkeit statt Integrität.** Wird das Tag upstream verschoben oder
  gelöscht, verwaist das Tag-Objekt und kann perspektivisch weg-garbage-
  collectet werden — der Pin bricht dann. Ein Commit, der auf dem Standard-Branch
  liegt (`ed142fd0` ist Vorfahre von `master`, geprüft), ist deutlich schwerer zu
  verwaisen. Das ist ein **Verfügbarkeits**-Argument, keine Zusicherung, dass
  nichts verschwinden *kann*.
- **Werkzeuge erkennen es nicht.** `gh api repos/aquasecurity/trivy-action/commits/a9c7b0f0…`
  antwortet mit **HTTP 422** — für die Commit-API existiert diese ID nicht.
  Pin-Auditoren (zizmor, ratchet) und Dependabot arbeiten auf Commits. Der
  praktisch teuerste Effekt: Dependabot würde so einen Pin **stillschweigend nie**
  aktualisieren. Die Veralterung wird unsichtbar — und ein Pin, den nie jemand
  hochzieht, ist genau das Fossil, vor dem Abschnitt 1 warnt.
- **Undokumentiertes Verhalten.** Dass GitHub Actions ein Tag-Objekt auf den
  Commit peelt, ist *beobachtet*, nicht zugesichert. Wer `a9c7b0f0` einträgt,
  verlässt sich auf Verhalten, das niemand garantiert hat.

Merkregel fürs nächste Mal: `git rev-parse <tag>^{commit}` liefert den Commit;
`git rev-parse <tag>` liefert bei annotierten Tags das Tag-Objekt. Der Unterschied
ist genau dieser Fehler.

Bewusst **nicht** mit-aktualisiert: `actions/checkout` steht upstream bei v7,
`actions/setup-python` bei v7. Pinning ist eine Supply-Chain-Maßnahme;
ein Major-Upgrade ist eine funktionale Änderung und braucht ein eigenes Work
Item mit eigenem grünen CI-Lauf. Beides in einem PR zu vermischen macht bei
einem roten Lauf die Ursache unauffindbar.

### Update-Verfahren

```bash
# SHA zu einem Tag aufloesen -- nie aus einem README abschreiben:
gh api repos/actions/checkout/git/matching-refs/tags/v4.4.0 \
  --jq '.[] | "\(.ref) \(.object.type) \(.object.sha)"'
```

Ist `object.type` gleich `tag` statt `commit`, handelt es sich um ein annotiertes
Tag — dann ist der gesuchte Commit-SHA `.object.sha` **des dereferenzierten
Objekts**, nicht der des Tag-Objekts. Im Zweifel gegenprüfen mit
`gh api repos/<owner>/<repo>/commits/<sha> --jq .sha`.

### Durchsetzung: `test/test_action_pins.py`

Diese Regel hatte bis zum Security-Audit **keinen Prüfmechanismus** — und wurde
prompt in genau dem PR gebrochen, der sie aufstellte (Audit-Fund MEDIUM-1). Eine
Regel ohne Durchsetzung ist eine Empfehlung. Der Test läuft in der normalen Suite
und arbeitet auf zwei Ebenen:

- **Offline (immer).** Form: 40 Hex-Zeichen, `# vX.Y.Z`-Kommentar vorhanden,
  keine beweglichen Refs. Das allein hätte MEDIUM-1 **nicht** gefunden — ein
  Tag-Objekt hat ebenfalls 40 Hex-Zeichen. Es fängt den viel häufigeren Fall
  `@v4` / `@main`.
- **Online (opt-in, `DS_CHECK_ACTION_PINS_ONLINE=1`).** Fragt GitHub, ob der SHA
  wirklich ein *Commit* ist. `repos/<owner>/<repo>/commits/<tag-objekt-id>`
  antwortet mit **HTTP 422** — daran ist der Fall eindeutig erkennbar. Das ist
  die Prüfung, die MEDIUM-1 gefunden hätte; gegen den Stand `947bd36`
  nachgestellt, schlägt sie dort fehl.

Opt-in ist die Online-Ebene, damit die normale Suite offline und deterministisch
bleibt. **Vor jedem Merge einer Workflow-Änderung** gehört sie trotzdem gelaufen:

```bash
DS_CHECK_ACTION_PINS_ONLINE=1 PYTHONPATH=litellm \
  python3 -m unittest discover -s test -p "test_action_pins.py"
```

Beim Pinnen von `github/codeql-action` (Audit-Fund MEDIUM-4) ist derselbe Fall
sofort wieder aufgetreten: Auch dessen `v4.37.7` ist ein annotiertes Tag. Zweimal
in einer Änderung ist kein Schlamperei-Problem, sondern ein fehlender Check.

Ein Detail, das der Test selbst zutage gefördert hat: Bei Unterverzeichnis-Actions
(`github/codeql-action/upload-sarif@…`) sind nur die **ersten zwei** Pfadsegmente
das Repository; der Rest ist ein Pfad darin. Wer das nicht trennt, bekommt einen
404 und hält einen korrekten Pin für falsch.

---

## 3. CVE-Scan

`gitleaks` findet Secrets. Es fand bis DATENSCHLE-59 **nichts**, was bekannte
Schwachstellen in Abhängigkeiten oder Images angeht. Diese Lücke schließt Trivy.

### Warum Trivy und nicht Grype

Beide sind gute Scanner. Ausschlaggebend war:

- **Ein Werkzeug für beides.** Trivy scannt Container-Images *und*
  Dateisysteme/Abhängigkeiten mit demselben Binary und derselben Schwellen-
  Syntax. Grype bräuchte für die Image-Seite zusätzlich Syft für die SBOM —
  zwei Werkzeuge, zwei Konfigurationen, zwei Stellen, an denen Schwellen
  auseinanderlaufen.
- **Ausnahmen mit Verfallsdatum.** Trivys `.trivyignore.yaml` kennt
  `expired_at`. Eine Ausnahme, die von selbst abläuft, ist der Unterschied
  zwischen „vertagt" und „unter den Teppich gekehrt".
- **Transitiv gepinnte Action.** `aquasecurity/trivy-action` pinnt seinerseits
  `aquasecurity/setup-trivy` und `actions/cache` auf SHAs. Unser SHA-Pin auf
  die äußere Action nagelt damit die ganze Kette fest — geprüft am
  gepinnten Stand `ed142fd0` (v0.36.0). Gilt für den *Code* der Kette; die
  Trivy-Schwachstellen-DB wird zur Scan-Zeit unter rollendem Tag geladen, und
  das ist bei einem CVE-Scanner auch so gewollt.

Keine neue Laufzeit-Abhängigkeit: Trivy läuft nur in der CI, nichts davon
landet im ausgelieferten Image.

### Die Schwellen — und warum sie so und nicht schärfer sind

Das eigentliche Risiko bei einem CVE-Scanner ist nicht, dass er zu wenig
findet. Es ist, dass er **zu oft blockiert**. Ein Gate, das bei jedem neu
veröffentlichten CVE in einem Basis-Image rot wird, hält irgendwann jeden PR
auf. Was dann passiert, ist vorhersehbar: Jemand schaltet ihn ab oder
gewöhnt sich an, rot zu ignorieren. Beides ist schlechter als kein Scanner,
weil es zusätzlich noch ein falsches Sicherheitsgefühl erzeugt.

Leitgedanke deshalb: **Blockiert wird nur, was der Autor des PRs auch
tatsächlich beheben kann.**

| Was | Wo | Sperrt den Merge | Nur Bericht |
|-----|----|------------------|-------------|
| Python-Abhängigkeiten | `security`-Job in `ci.yml`, bei jedem PR | CRITICAL + HIGH, **nur mit verfügbarem Fix** | alles ohne Fix, MEDIUM, LOW, UNKNOWN |
| Container-Images | `image-scan.yml`, wöchentlich + bei Pin-Änderung | **nichts** (siehe „Der Presidio-Altbestand") | alles |

**Was „sperrt den Merge" voraussetzt.** Ein roter Check färbt für sich genommen
nur ein Häkchen rot — verhindern kann er nichts. Die Sperre entsteht erst, wenn
der Job-Name als *required status check* in einem aktiven Ruleset steht.

Stand **2026-08-20, selbst geprüft** (`gh api repos/oliverhees/datenschleuse/rulesets`):
Ruleset `main-protection` (ID 21091840) ist **aktiv**, verlangt einen Pull Request
und vier erforderliche Checks: `test`, `syntax-check`, `security`, `gates`.
Zusätzlich sind `deletion` und `non_fast_forward` auf `main` gesperrt. Die Spalte
oben beschreibt damit den tatsächlichen Zustand.

Zwei Dinge, die dabei zusammenhängen und leicht auseinanderlaufen:

- Das Dependency-Gate sperrt, **weil** es im Job `security` sitzt und dieser
  Name auf der Required-Liste steht. Würde jemand den Scan in einen neu
  angelegten Job verschieben, wäre die Sperre lautlos weg — der neue Job wäre
  nicht required. Deshalb wächst die Abdeckung im vorhandenen Job, statt neue
  anzulegen (siehe „Wo die Scans hängen").
- `image-scan` steht **korrekt nicht** auf der Liste. Der Workflow hat einen
  `paths`-Filter; als required Check würde er bei PRs ohne passende Pfade nie
  ein Ergebnis melden und jeden Merge blockieren. Bestätigt: die vier
  erforderlichen Checks enthalten `image-scan` nicht.

*Historie, weil die Begründung des PRs daran hing:* Bis zum 2026-08-20 15:02
gab es **kein** Ruleset (`rulesets` → `[]`, `branches/main/protection` → 404
„Branch not protected"). Das Risiko-Argument dieses PRs — „blockiert wird beim
Dependency-Gate" — verlagerte damals auf ein Gate, das es nicht gab. Der
Security-Audit hat das aufgedeckt; Oliver hat das Ruleset daraufhin aktiviert
(DATENSCHLE-61). Der Satz stimmt also erst, seit er geprüft wurde — nicht,
seit er geschrieben wurde.

Begründung im Einzelnen:

- **`ignore-unfixed` überall.** Ein CVE ohne Upstream-Fix ist im PR nicht
  behebbar. Darauf zu blockieren heißt, den Autor für etwas zu bestrafen, das
  er nicht ändern kann — der klassische Weg, ein Gate unglaubwürdig zu machen.
  Diese Funde verschwinden aber nicht: Sie stehen im Bericht-Schritt (siehe
  unten).
- **Abhängigkeiten blockieren, Images nicht.** Unsere Abhängigkeiten haben
  wir selbst gewählt, und die Behebung ist meist eine Zeile: Version
  hochziehen. Ein CVE im Basis-Image dagegen kommt von außen, trifft jeden
  gleichzeitig laufenden PR — und ist, wie sich beim ersten echten Lauf
  zeigte, oft gar nicht von uns behebbar. Siehe nächster Abschnitt.
- **Jeder Scan läuft zweimal.** Erst ein Bericht-Schritt mit `exit-code: 0`
  und weiter Schwelle (bis LOW herunter, inklusive der Funde ohne Fix), dann
  das eigentliche Gate. So steht *alles* im Job-Log — niemand kann später
  sagen, wir hätten es nicht gesehen —, aber nur die handhabbare Teilmenge
  stoppt den Merge. Sichtbarkeit und Blockade sind bewusst getrennt.

### Der Presidio-Altbestand — Entscheidungsvorlage für Oliver

Der erste echte Lauf des Image-Scans hat die ursprünglich geplante Schwelle
„CRITICAL mit Fix blockiert" sofort widerlegt. Die Zahlen stammen aus
Run `32253275837` (head `947bd36`, 2026-08-19) und sind einzeln aus den
Job-Logs abgelesen, nicht geschätzt:

| Image | CRITICAL gesamt | davon **mit Fix** | HIGH | MEDIUM | Befunde gesamt |
|-------|-----------------|-------------------|------|--------|----------------|
| `litellm:v1.97.0` | 0 | 0 | 0 | 2 | 2 |
| `postgres:16.15-alpine` | 1 | 1 | 21 | 21 | 43 |
| `presidio-analyzer:2.2.362` | 9 | 5 | 66 | 151 | 226 (+20 Python) |
| `presidio-anonymizer:2.2.362` | 9 | 5 | 68 | 151 | 228 (+18 Python) |
| `presidio-image-redactor:0.0.58` | **42** | **21** | 705 | 3100 | **3847** (+38 Python) |
| **Summe** | **61** | **32** | 860 | 3425 | 4346 |

Nachprüfbar mit:

```bash
gh api repos/oliverhees/datenschleuse/actions/jobs/96069004036/logs \
  | grep -E "Total: [0-9]+ \("
```

**Zwei Dinge, die eine frühere Fassung dieser Tabelle falsch darstellte** und
die für eine Entscheidungsvorlage genau die falschen zwei sind:

1. Die Spalte hieß „CRITICAL (mit Fix)" und trug für Analyzer/Anonymizer je `9`
   ein. `9` ist die **Gesamtzahl**; mit Fix sind es je `5`. Deshalb stehen
   „gesamt" und „mit Fix" jetzt getrennt.
2. Die Zeile des Image-Redactors war **leer** („vorhanden | —"). Das schlechteste
   Image des Stacks war das einzige ohne Zahlen. Eine Vorlage, die die
   schlechteste Zahl auslässt, ist keine Vorlage.

#### Die These „wir können sie nicht senken" trägt nicht — gemessen

Die frühere Begründung lautete: Presidio ist Debian-basiert, `2.2.362` ist der
neueste Stand von Microsoft, „in Debian gefixt" heiße nicht „von uns behebbar".

Der erste Halbsatz stimmt, die Schlussfolgerung nicht. Die behebbaren CRITICALs
sind gewöhnliche Debian-Pakete mit vorhandener Zielversion:

```
libgnutls30t64  CVE-2026-33845, CVE-2026-42010  3.8.9-3+deb13u2 → 3.8.9-3+deb13u4
libssl3t64      CVE-2026-31789                  3.5.4-1~deb13u2 → 3.5.5-1~deb13u2
openssl         CVE-2026-31789                  3.5.4-1~deb13u2 → 3.5.5-1~deb13u2
```

Wir bauen den Analyzer **selbst** — `presidio/Dockerfile.analyzer` setzt mit
`FROM` auf und legt eine eigene Schicht darauf. Ein `apt-get upgrade` in genau
dieser Schicht behebt sie. Wir brauchen Microsoft dafür nicht.

**Gemessen am 2026-08-20** (lokal, Trivy 0.70.0, Basis-Image vs. Basis + eigene
`apt upgrade`-Schicht). Die Absolutzahlen liegen über denen des CI-Laufs vom
Vortag, weil die Schwachstellen-DB einen Tag jünger ist — verglichen wird
deshalb *vorher gegen nachher mit derselben DB*, nicht gegen die Tabelle oben:

| Image | CRITICAL mit Fix | CRITICAL gesamt | HIGH | Befunde (OS) |
|-------|------------------|-----------------|------|--------------|
| Analyzer vorher | 5 | 9 | 93 | 253 |
| Analyzer **nachher** | **0** | 4 | 22 | 96 |
| Anonymizer vorher | 5 | 9 | 95 | 255 |
| Anonymizer **nachher** | **0** | 4 | 22 | 96 |
| Image-Redactor vorher | 21 | 42 | 743 | 3835 |
| Image-Redactor **nachher** | **0** | 21 | 218 | 933 |

Das Ergebnis ist in allen drei Fällen dasselbe: **alle behebbaren CRITICALs
verschwinden**, die Gesamtbefunde fallen um 62 % bis 76 %. Übrig bleibt genau
das, wofür es upstream keinen Fix gibt — also genau das, was `ignore-unfixed`
ohnehin ausblendet.

Gegengeprüft, dass die Schicht nichts kaputt macht:

```
$ docker run --rm --entrypoint python <upgraded> -c "import presidio_analyzer, spacy, ssl; ..."
presidio ok / spacy 3.8.11 / OpenSSL 3.5.6 7 Apr 2026
```

#### Der Preis dieser Option — ehrlich benannt

`apt-get upgrade` holt sich, was am **Build-Tag** aktuell ist. Dieselbe
Dockerfile an zwei Tagen gebaut ergibt zwei verschiedene Images. Das steht in
einer gewissen Spannung zum Digest-Pinning aus Abschnitt 1 — wir nageln den
*Input* fest und lassen dann eine Schicht floaten.

Aufgelöst wird die Spannung dadurch, wo Reproduzierbarkeit für Betreiber
tatsächlich hängt: am Digest des **Ergebnis**-Images, nicht am Rezept. Der Input
ist über `FROM …@sha256:` festgenagelt, das Ergebnis wird in der CI gescannt.
Drift wird damit gemessen statt geglaubt. Echte Bit-Reproduzierbarkeit bräuchte
`snapshot.debian.org` als Paketquelle — eigene Infrastruktur-Entscheidung,
eigenes Work Item.

#### Was inzwischen umgesetzt ist (DATENSCHLE-83)

Die Umsetzung liegt **nicht** in diesem PR, sondern in DATENSCHLE-83 — dort
gehört sie fachlich hin, und zwei Branches dieselbe Datei bauen zu lassen wäre
ein Merge-Konflikt mit Ansage (Gesetz 8). Umgesetzt sind dort:

- `apt-get upgrade` in `presidio/Dockerfile.analyzer`, mit `USER root` nur für
  diese eine Schicht und anschließendem Zurückschalten auf UID 1001.
- Der Image-Redactor liegt hinter dem Compose-Profil `images` und startet bei
  `docker compose up` **nicht** mehr mit; die Bildpolitik steht per Default auf
  `block`. Damit ist das mit Abstand schlechteste Image (42 CRITICAL, 3847
  Befunde) aus dem Standard-Stack heraus.

**Was das für den ausgelieferten Standard-Stack bedeutet:**

| | behebbare CRITICALs |
|---|---|
| vorher (alle fünf Images) | **32** |
| nach DATENSCHLE-83 (Redactor optional, Analyzer upgraded) | **6** |
| zusätzlich mit `apt`-Schicht für den Anonymizer | **1** |

Die verbleibende `1` ist `postgres:16.15-alpine` (Alpine, kein `apt`; dort wäre
der Weg ein Digest-Update, sobald Upstream nachzieht).

#### Zu entscheiden hat das Oliver, nicht ein Agent

Gesetz 5 — Ausnahmen bei High/Critical genehmigt nur er, dokumentiert am Work
Item. Die vollständige Vorlage mit allen vier Optionen und ihren Konsequenzen
steht in **`docs/adr/0001-image-cve-gate.md`** (Status: vorgeschlagen).

Kurzfassung der Optionen:

1. **Akzeptieren und dokumentieren.** Kostet nichts, ändert am
   Auslieferungszustand nichts.
2. **Presidio komplett selbst bauen** (Wolfi o. ä.). Bringt die CRITICALs auf
   null, wir übernehmen dauerhaft Microsofts Wartungsarbeit.
3. **Warten und beobachten.** Der Wochenlauf meldet, sobald Microsoft nachzieht.
4. **`apt upgrade` in unserer eigenen Schicht** — der billige Zwischenweg, den
   die frühere Fassung dieses Dokuments gar nicht erst anbot. Gemessen: alle
   behebbaren CRITICALs weg, Aufwand eine RUN-Zeile, Preis ist die oben
   benannte Build-Zeit-Abhängigkeit.

Sobald das entschieden ist, wird `image-scan.yml` Schritt 2 wieder auf
`exit-code: "1"` gestellt. Der Schalter steht dort kommentiert. Nach Option 4
wäre diese Schwelle für den Standard-Stack erfüllbar — genau das war der
Einwand, an dem sie ursprünglich scheiterte.

### Wo die Scans hängen — und warum getrennt

- **`security`-Job in `ci.yml`** (bestehender Job, Name unverändert). Der Name
  steht als required Status-Check im Ruleset `main-protection` — seit dem
  2026-08-20 **aktiv**, vorher nur ein nicht angewandtes Template
  (DATENSCHLE-61). Hätten wir einen neuen Job `vuln-scan` angelegt, hätte
  `.github/ruleset-main-protection.json`
  mitgepflegt werden müssen — siehe die Pflege-Regel in `docs/BRANCH-PROTECTION.md`.
  Stattdessen wächst die Abdeckung des vorhandenen Checks.
- **`image-scan.yml`** (eigener Workflow): wöchentlich montags, per
  `workflow_dispatch`, und bei jedem PR, der eine der gepinnten Dateien
  anfasst (`paths`-Filter). Ein Image pro Matrix-Job, damit sich fünf
  Multi-Gigabyte-Images nicht die Platte eines Runners teilen müssen.

  **Dieser Workflow darf NIE auf die Required-Liste.** Er hat einen
  `paths`-Filter; ein paths-gefilterter Job meldet bei nicht passenden PRs
  überhaupt kein Ergebnis, und GitHub wartet dann dauerhaft auf einen Check,
  der nie kommt — kein PR mehr mergebar. Genau davor warnt
  `docs/BRANCH-PROTECTION.md`. Als eigener Workflow ist er davon getrennt.

### Der Scan-Input bei den Abhängigkeiten

`litellm/requirements-guardrail.txt` und `test/requirements.txt` enthalten
Bereiche (`httpx>=0.27,<1.0`), keine exakten Pins. Ein Scanner kann daraus
nicht ableiten, was installiert würde — er meldet dann nichts und wiegt uns in
Sicherheit. Der `security`-Job löst deshalb erst auf (`pip install` +
`pip freeze`) und scannt das Ergebnis. Die aufgelöste Liste steht im Job-Log.

Das ist ein Behelf, kein Lockfile. Siehe Abschnitt 4.

### Wohin die Funde gehen — und wer wann draufschaut

Bis zum Security-Audit von DATENSCHLE-59 schrieben beide Workflows **nur eine
Tabelle ins Job-Log**. Kein SARIF, kein Artefakt, keine Benachrichtigung. Der
wöchentliche Lauf endete mit fünf grünen Haken, während darunter tausende Funde
lagen. Ein grüner Haken über 3847 Befunden ist kein neutrales Signal, sondern ein
**aktiv irreführendes**. Dazu löscht GitHub Job-Logs nach 90 Tagen: Wer in einem
halben Jahr belegen will, was wir heute ausgeliefert haben, findet nichts mehr —
womit der Zweck aus der Einleitung („nachträglich feststellbar, welche Software
wir ausgeliefert haben") verfehlt wäre.

Beide Workflows laden ihre Ergebnisse deshalb als **SARIF ins Code-Scanning**.
Das Repo ist public, Code-Scanning ist damit kostenlos; die Funde landen
dedupliziert und mit Verlauf pro CVE im Security-Tab. Zwei Details, die nicht
Kosmetik sind:

- **`category` pro Matrix-Job.** Ohne sie überschreiben sich die fünf Image-Jobs
  gegenseitig, und im Security-Tab bliebe genau ein Image übrig.
- **Upload VOR dem Gate** (in `ci.yml`). Der Gate-Schritt beendet den Job mit
  `exit-code: 1`; alles danach läuft nicht mehr. Stünde der Upload dahinter,
  würde ausgerechnet der *blockierende* Fund nie aufgezeichnet — dokumentiert
  wären nur die harmlosen Läufe.
- **Fork-PRs übersprungen.** Forks bekommen kein `security-events: write`. Ohne
  die Bedingung scheiterte jeder Fork-PR am Upload statt an seiner Qualität.

**Wer schaut wann drauf** — ohne diese Zeile ist auch das beste Dashboard nur
ein Archiv:

| Wann | Wer | Was |
|------|-----|-----|
| Montags nach dem Wochenlauf | der Teammate mit dem Wartungs-Work-Item | Security-Tab öffnen: Sind **neue** CRITICALs dazugekommen? Nur die Veränderung zählt, nicht der Absolutstand. |
| Bei jedem Fund mit verfügbarem Fix | derselbe | Digest-Update nach Abschnitt 1 anstoßen — eigenes Work Item. |
| Quartalsweise | Oliver | Gesamtstand gegen die Entscheidung aus `docs/adr/0001-image-cve-gate.md` prüfen: Gilt die Begründung noch? |

Ohne festen Termin verfällt jede Berichtspflicht zu Hintergrundrauschen. Der
Wochenlauf ist der Termin.

### Ausnahmen

`.trivyignore.yaml` im Repo-Root. Die Regeln stehen als Kommentar in der Datei
selbst und sind bindend: `id` + `statement` + `expired_at` (max. 90 Tage),
Begründung sagt *warum es uns nicht trifft*, Verweis auf das Work Item,
High/Critical-Ausnahmen genehmigt nur Oliver (Gesetz 5).

Der Normalfall bei einem blockierenden Fund ist **nicht** ein Eintrag hier,
sondern: Dependency hochziehen oder Digest aktualisieren (Abschnitt 1).

### Drift-Schutz

Die Digests stehen an zwei Orten: dort, wo das Image *benutzt* wird
(Dockerfiles, Compose) und dort, wo es *gescannt* wird (Matrix in
`image-scan.yml`). Doppelte Wahrheit verrottet, wenn sie niemand prüft — und
eine vergessene Matrix-Zeile heißt: Der wöchentliche Scan prüft ein Image, das
wir gar nicht mehr ausliefern, und meldet beruhigend grün.

`test/check_image_pins.py` läuft im `security`-Job und schlägt fehl, wenn
(a) eine Image-Referenz keinen Digest hat oder (b) die beiden Mengen
auseinanderlaufen. Reine Stdlib, keine neue Abhängigkeit.

### Der blinde Fleck — und warum der Prüfumfang jetzt ermittelt wird

Der Drift-Schutz trug bis zum Security-Audit von DATENSCHLE-59 eine **fest
verdrahtete Dreierliste** von Dateien. `deploy/coolify/docker-compose.yaml`
stand nicht darin. Diese Datei enthielt `postgres:16-alpine` und
`mcr.microsoft.com/presidio-anonymizer:latest` — zwei rollende Tags. Der Check
meldete trotzdem:

```
$ python3 test/check_image_pins.py
OK: 5 gepinnte Images, alle mit Digest, alle in der Scan-Matrix abgedeckt.
EXIT=0
```

Eine **globale Entwarnung für eine Datei, die er nie geöffnet hatte** — genau
das Versagen, vor dem sein eigener Docstring warnt („a scanner reporting green
about the wrong thing, which is worse than no scanner at all"). Und es traf
ausgerechnet den Coolify-Deploy: den Weg, auf dem die gehostete Instanz läuft,
also den Pfad, auf dem verkauft wird.

Das eigentliche Problem war nicht die vergessene Zeile, sondern die Bauart:
**Eine feste Liste kann keine Datei abdecken, die es noch nicht gibt.** Die zwei
Digests nachzutragen hätte den heutigen Fund behoben und das Loch für die
nächste Compose-Datei offen gelassen.

Deshalb ermittelt der Check seinen Prüfumfang jetzt selbst: jede **getrackte**
`Dockerfile*`- und `docker-compose*.y*ml`-Datei im Repo, ermittelt über
`git ls-files`. Zwei Details, die dabei zählen:

- **`git ls-files` statt Dateisystem-Scan.** Das Repo trägt unter
  `.claude/worktrees/` Dutzende vollständiger Checkouts. Ein `rglob` würde sie
  alle mitnehmen. Getrackte Dateien sind genau die Dateien, die wir ausliefern.
- **`REQUIRED_IN_SCOPE` als Untergrenze.** Findet die Erkennung eine der bekannt
  relevanten Dateien *nicht* mehr, bricht der Check ab. Ohne diese Sperre wäre
  ein kaputtes Suchmuster wieder still grün — derselbe Fehler eine Ebene höher.

Abgesichert ist das durch `test/test_image_pins.py` (läuft in der normalen
Suite): Der Test `test_coolify_compose_is_in_scope` war rot, bevor die Erkennung
existierte, und hält den verkauften Deploy-Pfad dauerhaft im Prüfumfang. Der
Check selbst hatte vorher **keinen einzigen Test** und wurde von der Suite gar
nicht eingesammelt (fehlendes `test_`-Präfix — Audit-Fund LOW-1).

---

## 4. Offene Punkte

- ~~**`deploy/coolify/docker-compose.yaml`** enthält zwei ungepinnte
  Referenzen.~~ **Erledigt** im Security-Audit-Nachlauf von DATENSCHLE-59.
  Beide Referenzen tragen jetzt Tag + Digest und stehen in der Tabelle in
  Abschnitt 1; der Prüfumfang des Drift-Schutzes wird ermittelt statt
  aufgezählt (Abschnitt 3, „Der blinde Fleck").

  Zur Begründung, die hier vorher stand („wird parallel von einer anderen Lane
  bearbeitet"): Sie ließ sich nicht belegen. Die Datei liegt seit `2d4e8f6`
  unverändert auf `main`, und kein offener PR fasst sie an. Eine Verlagerung auf
  eine Lane, die es nicht gibt, ist keine Verlagerung — sie ist ein offenes Loch
  mit einer Fußnote. Der LiteLLM- und der Analyzer-Dienst dieser Datei bauen aus
  `../../litellm` bzw. `../../presidio` und erben die Pins ohnehin.
- **Kein Lockfile für die Python-Abhängigkeiten.** `litellm/requirements-guardrail.txt`
  und `test/requirements.txt` verwenden Bereiche (`httpx>=0.27,<1.0`), keine
  exakten Pins. Gesetz 5 verlangt ein Lockfile. Ohne eins ist eine Installation
  von heute nicht dieselbe wie eine von morgen — dasselbe Problem wie bei
  `:latest`, nur eine Ebene tiefer. Eigenes Work Item nötig; die Datei ist
  ebenfalls außerhalb des Reviers von DATENSCHLE-59.
