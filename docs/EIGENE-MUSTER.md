# Eigene Begriffe und Muster hinterlegen

Die automatische Erkennung findet vieles — aber nie alles. Was sie
prinzipbedingt **nicht** finden kann, ist alles, was bei euch anders heißt als
überall sonst:

- Kundennamen (`Nordwind Logistik`)
- Projektnamen (`Adlerflug`)
- interne Kürzel und Projektnummern (`PRJ-4711`, `KD-ABC`)
- Produktbezeichnungen
- Mandantennamen

Dafür gibt es eigene Regeln. Sie sind **deterministisch** (kein Modell rät
mit), **sofort wirksam** (kein Rebuild, kein Neustart) und **einzeln testbar**.

> **Kein Training.** Hier wird nichts trainiert und nichts gelernt — hier wird
> konfiguriert. Es werden ausschließlich die von euch eingegebenen Muster
> gespeichert, **niemals Trefferdaten** aus echten Anfragen. Siehe
> [ADR-0001](adr/0001-eigene-muster-deny-list.md).

## In zwei Minuten zum ersten eigenen Begriff

Einmalig die Vorlage kopieren — mit `install -m 600`, nicht mit `cp`:

```bash
install -m 600 rules/custom-rules.example.yml rules/custom-rules.yml
```

`cp` würde die Rechte eurer Umask übernehmen (meist `0664`) — die Datei wäre
dann für jeden Benutzer der Maschine lesbar, obwohl echte Kundennamen darin
stehen. `datenschleuse-rules list` warnt euch, falls das passiert ist.

Begriff hinterlegen — das `--example` ist Pflicht und ist zugleich der
Testfall der Regel:

```bash
./tools/datenschleuse-rules add kunde-nordwind \
    --entity Kundenname \
    --term "Nordwind Logistik" \
    --example "Angebot fuer Nordwind Logistik rausgeschickt"
```

```
✓ Regel 'kunde-nordwind' gespeichert und SOFORT aktiv.
  Platzhalter: <CUSTOM_KUNDENNAME_N>
  Testfall gruen: 1 Beispiel(e)
  Kein Neustart noetig — die Datenschleuse liest die Datei beim naechsten Request neu ein.
```

Ausprobieren:

```bash
./tools/datenschleuse-rules test "Bitte fasse den Vertrag mit Nordwind Logistik zusammen."
```

```
Treffer: 1
  'Nordwind Logistik'                      → <CUSTOM_KUNDENNAME>  via kunde-nordwind

So verlaesst der Text die Datenschleuse:
  Bitte fasse den Vertrag mit <CUSTOM_KUNDENNAME_0> zusammen.
```

Fertig. Der nächste Request durch die Datenschleuse maskiert den Begriff
bereits — es ist **kein** `docker compose restart` nötig.

Der Weg zurück funktioniert wie bei jeder anderen Entität: Das Modell sieht
`<CUSTOM_KUNDENNAME_0>`, die Antwort wird auf dem Rückweg wieder zu
`Nordwind Logistik`. Auch beim Streaming.

## Muster statt einzelner Begriffe

Für alles mit System — Projektnummern, Mandantenkürzel, Aktenzeichen:

```bash
./tools/datenschleuse-rules add projektnummer \
    --entity Projektnummer \
    --regex '\bPRJ-[0-9]{4}\b' \
    --example "Bitte pruefe Ticket PRJ-1234." \
    --counter-example "Die Rechnung RE-1234 ist offen."
```

`--counter-example` ist optional, aber die beste Investition beim Muster-Bauen:
Es ist ein Text, in dem die Regel **nicht** greifen darf. Ein zu gieriges
Muster fliegt so sofort auf — vor dem Livegang, nicht danach.

## Kein ungetestetes Muster geht live

Jede Regel trägt ihren eigenen Testfall. Beim Speichern **und** bei jedem
Laden wird sie dagegen verifiziert. Fällt sie durch, wird sie gar nicht erst
gespeichert:

```bash
./tools/datenschleuse-rules add tippfehler \
    --entity Kundenname --term "Suedwind AG" \
    --example "Hier kommt der Begriff gar nicht vor"
```

```
Nicht gespeichert — der eigene Testfall ist rot -- das Muster greift im hinterlegten Beispiel nicht. Muster oder Beispiel korrigieren.
Kein ungetestetes Muster geht live (ISC-24). Die Regeldatei ist unveraendert.
```

Das ist Absicht: Ein Muster, das nicht greift, ist gefährlicher als gar
keines — es wiegt in falscher Sicherheit.

## Was ist gerade aktiv?

```bash
./tools/datenschleuse-rules list
```

Zeigt drei Blöcke: die **aktiven** eigenen Regeln, die **nicht aktiven** mit
Begründung, und die eingebaute Erkennung zum Vergleich.

Wer die Datei von Hand editiert, kann Regeln kaputt machen. Sie verschwinden
dann nicht still, sondern werden rot ausgewiesen:

```
NICHT AKTIV — Testfall rot oder Regel ungueltig (2)
  Diese Muster schuetzen NICHT. Bitte korrigieren.
  ✗ handverpfuscht               Regel 'handverpfuscht': Muster laesst sich nicht uebersetzen: unterminated character set at position 5
  ✗ tippfehler                   Regel 'tippfehler': der eigene Testfall ist rot -- das Muster greift im hinterlegten Beispiel nicht. Muster oder Beispiel korrigieren.
```

**Wichtig:** Alle anderen Regeln arbeiten dabei ungestört weiter. Ein
kaputtes Muster kostet genau die eine Entität, die es abdecken sollte — nie
die ganze Pipeline.

## Regel entfernen oder abschalten

```bash
./tools/datenschleuse-rules remove kunde-nordwind
```

Nur vorübergehend abschalten, ohne sie zu verlieren? In der YAML `enabled: false`
setzen.

## Alle Befehle

| Befehl | Zweck |
|---|---|
| `list` | zeigt aktive, nicht aktive und eingebaute Erkennung (`--json` für Maschinen) |
| `add NAME --entity E (--term T \| --regex R) --example X` | neue Regel, wird vor dem Speichern getestet |
| `test "TEXT"` | prüft einen Text gegen die eigenen Regeln, zeigt die Maskierung |
| `remove NAME` | Regel entfernen |

Globale Option `--rules PFAD` überschreibt die Regeldatei.

## Feldreferenz

| Feld | Pflicht | Bedeutung |
|---|---|---|
| `name` | ja | eindeutiger Kurzname (Kleinbuchstaben, Ziffern, `-`, `_`) |
| `entity` | ja | Kategorie → Platzhalter `<CUSTOM_KATEGORIE_N>`. **Geht an den Anbieter** — Kategorie benennen, nie den Kunden |
| `type` | ja | `term` (wörtlicher Begriff) oder `regex` |
| `value` | ja | der Begriff bzw. das Muster |
| `examples` | **ja** | mindestens ein Text, in dem die Regel greifen MUSS |
| `counter_examples` | nein | Texte, in denen sie NICHT greifen darf |
| `score` | nein | Konfidenz 0–1 (Default: 0.9 Begriff / 0.85 Muster) |
| `case_sensitive` | nein | Default `false` |
| `enabled` | nein | auf `false` setzen zum Abschalten |

### Der Kategoriename geht an den Anbieter — der Wert nicht

Das ist die eine Sache, die man hier falsch machen kann. Der Wert wird
maskiert, der **Kategoriename steht im Platzhalter** und reist damit wörtlich
zum LLM-Anbieter:

```
--entity Kundenname  --term "Nordwind Logistik"
→ Modell sieht:  <CUSTOM_KUNDENNAME_0>          ✅ verrät nichts

--entity "Nordwind Logistik"  --term "Nordwind Logistik"
→ Modell sähe:   <CUSTOM_NORDWIND_LOGISTIK_0>   ❌ Name ist trotzdem draußen
```

Die zweite Variante hebt den eigenen Schutz auf — der Wert ist maskiert, der
Name geht raus. Deshalb wird sie **abgelehnt**:

```
Nicht gespeichert — entity und value teilen sich ein Wort -- der Kategoriename
waere damit selbst ein Teil des Geheimnisses. [...] Bitte die KATEGORIE
benennen (z.B. 'Kundenname', 'Projektname'), nicht den Kunden.
```

**Faustregel:** `--entity` benennt die *Sorte* von Daten (Kundenname,
Projektnummer, Mandant), niemals den konkreten Kunden. Kategorienamen sind
deshalb auf 40 Zeichen und 3 Wörter begrenzt — ein Kategoriename ist ein Wort,
kein Satz.

### Was ihr über Begriffe wissen solltet

- Begriffe sind **wörtlich**, kein Regex: Der Punkt in `a.b` ist ein Punkt.
- Es gelten **Wortgrenzen**: `Adler` maskiert nicht die halbe `Adlerflug`.
  Wer beides will, legt beide Begriffe an (oder nutzt ein Muster).
- Default ist **Groß-/Kleinschreibung egal**. Bei Begriffen, die auch normale
  Wörter sind, lohnt `case_sensitive: true`.

## Sicherheit und Datenschutz

- **Dateirechte werden geprüft.** `list` warnt, wenn die Regeldatei für andere Benutzer lesbar ist (`chmod 600` behebt es). Die CLI selbst schreibt immer `0600`.
- **`rules/custom-rules.yml` gehört nicht ins Repository.** Sie steht in der
  `.gitignore` und ist wie ein Secret zu behandeln — sie enthält genau die
  Namen, die ihr schützen wollt. Die Datei wird mit Rechten `0600` geschrieben.
- **Keine Trefferdaten.** Gespeichert werden nur die Muster selbst. Was eine
  Regel in echten Anfragen trifft, wird nirgendwo mitgeschrieben.
- **Keine Werte in Logs.** Fehlermeldungen nennen nur Regelnamen und
  Fehlerkategorie, nie den Regelwert.
- **Kategorienamen werden geprüft.** Ein `--entity`, das ein Wort mit dem Wert teilt, wird abgelehnt — sonst reiste der Name im Platzhalter zum Anbieter, während der Wert maskiert ist.
- **Zeitbudget mit fail-closed.** Die Regelprüfung hat pro Anfrage ein festes
  Zeitbudget. Reicht es nicht — etwa weil ein Muster mit exponentiellem
  Backtracking rechnet —, wird die Anfrage **blockiert**, nicht halb maskiert
  ausgeliefert. Ein unvollständiges Ergebnis sieht von außen genau aus wie ein
  vollständiges; deshalb darf es keins geben. Wer diese Meldung sieht, hat ein
  zu teures Muster: `datenschleuse-rules list` zeigt die Kandidaten.

## Grenzen, die ihr kennen solltet

- **Bilder.** Eure eigenen Regeln wirken auf Text, nicht auf Bildinhalte —
  der Image-Redactor ist ein eigener Dienst mit eigener Erkennung. Verlasst
  euch für eigene Begriffe also nicht auf Bilder. Wer das nicht in Kauf nehmen
  will, setzt `DATENSCHLEUSE_IMAGE_POLICY=block`; dann kommen Bilder gar nicht
  erst durch.
- **Schreibweisen.** Eine Regel trifft, was dasteht. `Nordwind Logistik`
  fängt nicht `Nordwind-Logistik` oder `Nordwind GmbH`. Für Varianten entweder
  mehrere Begriffe anlegen oder ein Muster schreiben — und mit
  `--counter-example` absichern.
- **Muster mit variablem Whitespace (`\s*`, `\s+`).** Ein Muster, das eine
  beliebig große Lücke zwischen seinen Teilen erlaubt, kann auch dann noch
  passen, wenn an dieser Stelle bereits ein Platzhalter eingesetzt wurde —
  es greift dann über den Platzhalter hinweg. `Nord\s*wind` etwa passt nicht
  nur auf `Nordwind` und `Nord wind`, sondern auch auf eine Stelle, an der
  zwischen `Nord` und `wind` ein anderer Begriff ersetzt wurde. Die Anfrage
  wird dann blockiert, obwohl nichts durchgerutscht ist. Das ist ein
  sichtbarer, aber harmloser Fehlalarm — kein Leck, und wir nehmen ihn
  bewusst in Kauf: eine blockierte Anfrage, die ihr seht, ist billiger als
  eine durchgelassene, die ihr nicht seht. Die Blockmeldung nennt diesen Fall
  ausdrücklich mit. Was ihr tun könnt: variable Whitespace-Muster sparsam
  einsetzen, jedes mit `--counter-example` absichern und vor dem Ausrollen
  `datenschleuse-rules test` über einen echten Beispieltext laufen lassen.
  Deny-Listen — der Standardtyp — sind davon nicht betroffen.
- **Erkennungsrate ist nie 100 %.** Eigene Regeln verschieben die Grenze
  deutlich, sie verschwinden lassen sie nicht.
