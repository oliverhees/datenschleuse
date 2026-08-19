# Branch-Protection aktivieren (main-protection Ruleset)

Gesetz 4 der Verfassung sagt: niemals direkt auf `main`, immer PR. Bis heute
wird das **nur durch einen lokalen Git-Hook** durchgesetzt. Ein lokaler Hook
greift nicht, wenn jemand ausserhalb einer Claude-Session pusht, den Hook
umgeht oder auf einem anderen Rechner arbeitet. Serverseitig war `main`
ungeschuetzt.

Dieses Dokument ist der Laufzettel, um das zu aendern: ein Befehl zum
Aktivieren, einer zum Pruefen, einer zum Zurueckdrehen.

> **Status: NICHT aktiviert.** Die Aktivierung ist eine Governance-Entscheidung
> und trifft ausschliesslich Oliver. Die Vorlage ist vorbereitet und gegen die
> echten CI-Job-Namen verifiziert — mehr nicht.

---

## Ist-Zustand (Stand DATENSCHLE-61)

```console
$ gh api repos/oliverhees/datenschleuse/rulesets
[]

$ gh api repos/oliverhees/datenschleuse/rules/branches/main
[]

$ gh api repos/oliverhees/datenschleuse/branches/main/protection
{"message":"Branch not protected", ... "status":"404"}
```

Kein Ruleset, keine klassische Branch-Protection, kein required Status-Check.
Konkret heisst das: ein direkter Push auf `main` geht durch, und der komplette
Laufzettel (`gates`, `test`, `syntax-check`, `security`) darf rot sein, ohne
einen Merge zu verhindern.

---

## Was die Vorlage durchsetzt

Datei: [`.github/ruleset-main-protection.json`](../.github/ruleset-main-protection.json)

| Regel | Wirkung |
|-------|---------|
| `deletion` | `main` kann nicht geloescht werden |
| `non_fast_forward` | kein Force-Push auf `main` (Gesetz 4) |
| `pull_request` | kein direkter Push — jede Aenderung braucht einen PR |
| `required_status_checks` | `test`, `syntax-check`, `security`, `gates` muessen gruen sein |

`strict_required_status_checks_policy: true` verlangt zusaetzlich, dass der
Branch vor dem Merge auf dem Stand von `main` ist.

### Warum die Context-Namen exakt stimmen muessen

Ein required Status-Check wird ueber seinen **Namen** gematcht. Steht in der
Vorlage ein Name, den kein Job jemals meldet, wartet GitHub dauerhaft auf einen
Check, der nie kommt — **kein PR ist dann mehr mergebar**. Genau das waere
passiert, wenn die Vorlage noch den alten Namen `lint` enthalten haette; der Job
heisst seit DATENSCHLE-49 `syntax-check`.

Die Namen wurden gegen die tatsaechlich von GitHub gemeldeten Check-Runs des
letzten PRs geprueft (nicht gegen die YAML-Datei allein):

```console
$ gh api repos/oliverhees/datenschleuse/commits/<PR-HEAD-SHA>/check-runs \
    --jq '.check_runs[] | "\(.name) | \(.conclusion) | \(.app.slug) | \(.app.id)"'
security      | success | github-actions | 15368
gates         | success | github-actions | 15368
syntax-check  | success | github-actions | 15368
test          | success | github-actions | 15368
```

`integration_id: 15368` in der Vorlage pinnt jeden Check auf die GitHub-Actions-
App. Ohne diese ID wuerde ein beliebiger anderer App-Status mit dem passenden
Namen den Check erfuellen.

### Pflege-Regel

**Wer einen Job in `.github/workflows/ci.yml` umbenennt, aendert im selben PR
`.github/ruleset-main-protection.json` — und nach dem Merge das aktive Ruleset.**
Sonst blockiert der alte Name jeden weiteren Merge. Diese Reihenfolge ist bewusst
unbequem: erst Ruleset auf beide Namen erweitern, dann umbenennen, dann alten
Namen entfernen.

---

## 1. Aktivieren

```bash
gh api -X POST repos/oliverhees/datenschleuse/rulesets \
  --input .github/ruleset-main-protection.json
```

Ausfuehren aus dem Repo-Root. Der Befehl gibt das angelegte Ruleset inklusive
`id` zurueck — diese `id` wird fuer Pruefung und Rollback gebraucht.

Voraussetzung: `gh auth status` zeigt einen Token mit `repo`-Scope fuer
`oliverhees`. Das Repo ist public und User-eigen; Rulesets sind in dieser
Konstellation ohne kostenpflichtigen Plan verfuegbar.

## 2. Pruefen

```bash
# Existiert das Ruleset und ist es aktiv?
gh api repos/oliverhees/datenschleuse/rulesets \
  --jq '.[] | {id, name, enforcement}'

# Was gilt effektiv fuer main? (vor Aktivierung: [])
gh api repos/oliverhees/datenschleuse/rules/branches/main \
  --jq '[.[].type]'

# Welche Checks sind wirklich required?
gh api repos/oliverhees/datenschleuse/rulesets/<ID> \
  --jq '.rules[] | select(.type=="required_status_checks")
        | .parameters.required_status_checks'
```

Erwartet nach der Aktivierung: `["deletion","non_fast_forward","pull_request","required_status_checks"]`
und die vier Contexts `test`, `syntax-check`, `security`, `gates`.

Funktionale Gegenprobe (soll **fehlschlagen**):

```bash
git push origin main   # erwartet: rejected — protected branch
```

## 3. Zurueckdrehen

Weich — Ruleset bleibt erhalten, greift aber nicht mehr:

```bash
gh api -X PUT repos/oliverhees/datenschleuse/rulesets/<ID> \
  -f enforcement=disabled
```

Hart — Ruleset komplett entfernen:

```bash
gh api -X DELETE repos/oliverhees/datenschleuse/rulesets/<ID>
```

Danach zur Kontrolle nochmal `gh api repos/oliverhees/datenschleuse/rules/branches/main`
— muss wieder `[]` liefern.

### Wenn CI ausfaellt und nichts mehr mergebar ist

Das ist der Grund, warum kein Dauer-Bypass eingerichtet ist: Faellt ein
Check-Provider aus (z. B. die gitleaks-Action im `security`-Job), ist der
richtige Weg, das Ruleset kurz auf `disabled` zu setzen, zu mergen und wieder zu
aktivieren. Das steht in der Ruleset-Historie und ist damit nachvollziehbar —
ein stehender Bypass waere es nicht.

---

## Offene Entscheidungen (Oliver)

Die Vorlage enthaelt drei Punkte, die bewusst so gesetzt sind und bestaetigt
werden sollten. Sie sind hier dokumentiert, damit sie nicht stillschweigend
mitlaufen.

### E1 — `required_approving_review_count: 0`

**Vorschlag: auf 0 belassen.**

GitHub laesst niemanden den eigenen PR approven. Oliver ist der einzige Mensch
im Repo, Agents koennen nicht approven. Bei `1` waere jeder PR, den Oliver
selbst aufmacht, dauerhaft nicht mergebar — eine Blockade ohne Sicherheitsgewinn.
Die Qualitaetssicherung leistet hier nicht ein Klick, sondern der Laufzettel:
`gates` erzwingt SHA-gepinnte Security- und QA-Verdicts, `test` erzwingt Gesetz 2.

Ehrlich dazu: `dismiss_stale_reviews_on_push: true` ist bei 0 erforderlichen
Approvals wirkungslos und steht nur da, damit die Einstellung stimmt, falls die
Zahl je erhoeht wird. `required_review_thread_resolution: true` wirkt dagegen
unabhaengig davon — offene Review-Threads blockieren den Merge auch bei 0.

### E2 — Bypass fuer Oliver?

**Vorschlag: kein Bypass (`bypass_actors: []`).**

Anders als bei der klassischen Branch-Protection sind Repo-Admins bei Rulesets
**nicht** automatisch ausgenommen. Ein leeres `bypass_actors` heisst also
wirklich: die Regel gilt ausnahmslos, auch fuer Oliver. Das ist der Punkt der
Uebung — eine Regel, die der Haupt-Committer jederzeit umgehen kann, schuetzt
genau gegen nichts.

Der Notausgang ist nicht der Bypass, sondern der Rollback-Befehl oben: sichtbar,
protokolliert, in Sekunden erledigt. Falls Oliver das anders sieht, waere die
Alternative ein Bypass mit `bypass_mode: "pull_request"` (greift nur in PRs,
nicht beim Direkt-Push) statt `"always"`.

### E3 — Welche Checks sind required?

**Vorschlag: alle vier — `test`, `syntax-check`, `security`, `gates`.**

- `gates` — ohne diesen Check ist der ganze Laufzettel (Security-/QA-/UX-Verdicts,
  SHA-Pinning gegen veraltete Audits) unverbindlich. Das ist der wichtigste der vier.
- `test` — Gesetz 2, kein Code ohne gruene Tests.
- `security` — Gesetz 5, gitleaks-Secrets-Scan.
- `syntax-check` — billig, schnell, faengt kaputte Python-Dateien.

Alle vier laufen bei jedem PR gegen `main`: der Workflow hat keine `paths`-Filter
und keine Job-`if`-Bedingungen, es kann also kein Job stillschweigend
uebersprungen werden und den Merge blockieren. Alle vier waren auf den PRs #5 und
#6 gruen — sie sind erprobt, nicht theoretisch.

Zu bedenken: `gates` und `security` haengen an externen Faktoren (Verdict-Dateien
bzw. der gitleaks-Action). Faellt eines davon aus, blockiert es zu Recht — der
Umgang damit steht unter "Wenn CI ausfaellt".
