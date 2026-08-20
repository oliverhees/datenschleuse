# ADR-0004: Nur exaktes `str` passiert Register, Allowlists und Textfelder

- Status: akzeptiert
- Datum: 2026-08-20
- Work Item: [DATENSCHLE-65]

## Kontext

`x in frozenset` prüft über `__hash__`/`__eq__`. Benutzt — formatiert, geloggt,
weiterverarbeitet — wird danach aber die **Instanz**. Eine `str`-Subklasse mit
überschriebenem `__hash__`/`__eq__` tarnt sich damit als bekannter Schlüssel und
schleust ihren eigenen Inhalt durch jede Registerprüfung.

Gefunden wurde das dreimal in Folge (DATENSCHLE-57, -64, -65). Der erste Fixversuch
reparierte zwei Stellen lokal; ein AST-Sweep über alle `In`/`NotIn`-Vergleiche fand
danach **19** solcher Vergleiche allein in `datenschleuse_guardrail.py`.

Der externe Review deckte zwei Verschärfungen auf:

- Der Maskierungspfad vertraut nicht nur auf den **Typ**, sondern auf `str`-**Semantik**:
  `_analyze` steigt bei `not text.strip()` aus. Eine Subklasse, die bei `strip()` lügt,
  ließ den Analyzer den Text für leer halten — er ging **unmaskiert an das Zielmodell**.
- `type(x).__name__` ist frei wählbar und damit ebenfalls Client-Inhalt. Die Meldungen
  gaben den Typnamen aus, gerade *weil* der Wert nicht ausgegeben werden darf — die
  Ausweichroute war so offen wie der Hauptweg.

## Entscheidung

An jeder Grenze, an der ein Client-Wert gegen ein Register, eine Allowlist oder die
Erwartung "das ist Text" gehalten wird, gilt **Typidentität statt `isinstance`**:
`type(x) is str`. Subklassen fallen in den generischen, fail-closed blockenden Zweig.

Umgesetzt als drei Hilfsfunktionen statt als Muster zum Nachbauen:

| Funktion | Frage |
|---|---|
| `_ist_echter_str(x)` | Ist das wirklich ein `str` und keine Subklasse? |
| `_ist_registriert(x, register)` | Mitgliedschaft **und** Typidentität, als eine Frage |
| `_typname(x)` | Typname — aber nur aus unserem Vokabular (`SICHERE_TYPNAMEN`) |

**Vorbedingung für `_ist_registriert` (bindend):** Die Hilfe ist nur dort richtig, wo
ein `False` **blockt**. Wo ein `False` etwas überspringt, dreht sie die Wirkung ins
Fail-open. Der Aufruftyp-Gate in `async_pre_call_hook` ist genau so ein Fall und
bleibt deshalb bewusst ausgenommen.

## Alternativen

- **Einzelfixes pro Fundstelle.** Verworfen: der Prüfer hatte fünf Stellen, es waren
  19. Eine Abarbeitungsliste hätte zwölf Löcher offengelassen — darunter zwei Klassen,
  die niemand auf dem Schirm hatte (Allowlist-Schlüssel, die als Feldname mitsamt PII
  ans Modell gehen; und die `benannt`/`fremd`-Partition).
- **Jede `str`-Methode gegen Lügen absichern.** Verworfen: aussichtslos. `__len__`,
  `__getitem__`, `replace`, `find`, `strip` — jede kann lügen. Die Identitätsfrage
  wird einmal an den Chokepoints gestellt.
- **Zusage streichen statt einlösen.** Verworfen: die Kommentare versprachen bereits
  "der ausgegebene Name ist unsere Konstante". Eine falsche Zusage zu löschen ist
  billiger, aber sie wahr zu machen ist das, was ein Sicherheitswerkzeug schuldet.

## Konsequenzen

**Leichter:** Wer ein neues Register einführt, hat genau eine richtige Funktion zur
Auswahl. Die Verhaltens-Neutralität folgt aus einer Eigenschaft der Hilfsfunktion,
nicht daraus, dass 19 Stellen einzeln richtig umgestellt wurden — `TestAequivalenz-
UeberAlleRegister` rechnet sie über alle per Introspektion gefundenen Register nach
und wächst automatisch mit dem zwanzigsten.

**Schwerer — BREAKING CHANGE für In-Process-Integrationen:**

> `str`-Subklassen werden ab jetzt geblockt. Das betrifft `str`-Enums
> (`class Role(str, Enum)`), pydantic-`constr`, `StrEnum` und vergleichbare
> Framework-Stringtypen. Vorher wurden sie von jeder Allowlist akzeptiert.
>
> **Über HTTP ändert sich nichts**: `json.loads` liefert ausschließlich exakte
> `str`. Betroffen sind nur Aufrufer, die den Guardrail in-process mit
> Enum- oder Framework-Stringtypen füttern.
>
> Die Richtung ist fail-closed — betroffene Requests werden geblockt, nicht
> stillschweigend durchgelassen. Wer solche Typen übergibt, normalisiert sie
> vor dem Aufruf mit `str(...)`.

**Diagnostik:** In Blockmeldungen erscheinen Typnamen außerhalb von
`SICHERE_TYPNAMEN` als `unbekannt`. Für alles, was über HTTP ankommen kann
(`str`/`int`/`float`/`bool`/`list`/`dict`/`NoneType`), bleibt die Diagnose
unverändert — ein Betreiber sieht weiterhin, dass in `type` ein `dict` stand.

**Für künftige Work Items:** Die Dateigrenze war die Lücke, nicht die einzelne Zeile.
Dieselbe Bugklasse außerhalb des Guardrails wird in DATENSCHLE-85 behandelt.
