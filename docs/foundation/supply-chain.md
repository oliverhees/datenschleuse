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
- `deploy/coolify/docker-compose.yaml` — **offen**, siehe Abschnitt 4.

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

| Was | Wo | Blockiert | Nur Bericht |
|-----|----|-----------|-------------|
| Python-Abhängigkeiten | `security`-Job in `ci.yml`, bei jedem PR | CRITICAL + HIGH, **nur mit verfügbarem Fix** | alles ohne Fix, MEDIUM, LOW, UNKNOWN |
| Container-Images | `image-scan.yml`, wöchentlich + bei Pin-Änderung | **nichts** (siehe „Der Presidio-Altbestand") | alles |

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

### Der Presidio-Altbestand — offene Entscheidung für Oliver

Der erste echte Lauf des Image-Scans (Run `32252889633`, 2026-08-19) hat die
ursprünglich geplante Schwelle „CRITICAL mit Fix blockiert" sofort widerlegt:

| Image | CRITICAL (mit Fix) | Gesamt (CRITICAL/HIGH/MEDIUM) |
|-------|--------------------|-------------------------------|
| `litellm:v1.97.0` | 0 | 0 |
| `postgres:16.15-alpine` | 1 (CVE-2025-68121, Go-stdlib `crypto/tls`) | 43 |
| `presidio-analyzer:2.2.362` | 9 (openssl, gnutls, perl) | 226 |
| `presidio-anonymizer:2.2.362` | 9 (dieselben) | 228 |
| `presidio-image-redactor:0.0.58` | vorhanden | — |

Das Entscheidende ist nicht die Zahl, sondern dass **wir sie nicht senken
können**: Die Presidio-Images sind Debian-basiert, und `2.2.362` *ist* der
neueste von Microsoft veröffentlichte Stand. „In Debian gefixt" heißt nicht
„von uns behebbar" — den Fix muss Microsoft in einen Rebuild gießen. Es gibt
keinen Digest, auf den wir hochziehen könnten.

Ein blockierender Check, den niemand erfüllen *kann*, ist exakt der
Mechanismus, durch den Scanner abgeschaltet werden. Deshalb meldet
`image-scan.yml` und blockiert nicht. Die Merge-Sperre sitzt dort, wo sie
handhabbar ist: beim Dependency-Gate.

Bemerkenswert im Kontrast: `litellm:v1.97.0` ist sauber. Das Image basiert auf
Chainguard/Wolfi, wo minimale Angriffsfläche das Produktversprechen ist.

**Zu entscheiden hat das Oliver, nicht ein Agent** (Gesetz 5 — Ausnahmen bei
High/Critical genehmigt nur er). Die Optionen, ehrlich benannt:

1. **Akzeptieren und dokumentieren.** Die Dienste hängen im internen
   `datenschleuse-net` und sind nicht öffentlich erreichbar; die
   OpenSSL-Lücke ist laut Beschreibung auf 32-Bit-Systemen relevant, wir
   fahren 64 Bit. Kostet nichts, ändert aber am Auslieferungszustand nichts.
2. **Analyzer/Anonymizer selbst bauen.** Presidio ist Open Source; ein
   eigener Build auf gepatchter Basis (oder Wolfi) bringt die CRITICALs auf
   null, kostet aber dauerhaft Wartung — wir übernehmen damit Microsofts Job.
3. **Warten und beobachten.** Der wöchentliche Lauf meldet, sobald Microsoft
   nachzieht; dann greift das normale Digest-Update (§1).

Sobald der Altbestand entschieden ist, wird `image-scan.yml` Schritt 2 wieder
auf `exit-code: "1"` gestellt. Der Schalter steht dort kommentiert.

### Wo die Scans hängen — und warum getrennt

- **`security`-Job in `ci.yml`** (bestehender Job, Name unverändert). Der Name
  steht als required Status-Check im Ruleset-Template (DATENSCHLE-61). Hätten
  wir einen neuen Job `vuln-scan` angelegt, hätte `.github/ruleset-main-protection.json`
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

---

## 4. Offene Punkte

- **`deploy/coolify/docker-compose.yaml`** enthält zwei ungepinnte Referenzen
  (`postgres:16-alpine`, `mcr.microsoft.com/presidio-anonymizer:latest`). Die
  Datei liegt außerhalb des Reviers von DATENSCHLE-59 und wird parallel von einer
  anderen Lane bearbeitet — deshalb hier bewusst nicht angefasst, sondern
  gemeldet. Die Digests aus Abschnitt 1 sind direkt übernehmbar. Der
  LiteLLM- und der Analyzer-Dienst dieser Datei bauen aus `../../litellm` bzw.
  `../../presidio` und erben die Pins dieses PRs bereits.
- **Kein Lockfile für die Python-Abhängigkeiten.** `litellm/requirements-guardrail.txt`
  und `test/requirements.txt` verwenden Bereiche (`httpx>=0.27,<1.0`), keine
  exakten Pins. Gesetz 5 verlangt ein Lockfile. Ohne eins ist eine Installation
  von heute nicht dieselbe wie eine von morgen — dasselbe Problem wie bei
  `:latest`, nur eine Ebene tiefer. Eigenes Work Item nötig; die Datei ist
  ebenfalls außerhalb des Reviers von DATENSCHLE-59.
