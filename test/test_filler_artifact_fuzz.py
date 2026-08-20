"""Property-Fuzzing fuer den Artefaktfilter (_is_filler_artifact).

WARUM ES DIESE DATEI GIBT
-------------------------
Der Artefaktfilter im Verifikationsdurchlauf hat sich DREIMAL ein Leck
eingebaut (F10, S1, S1-R/HIGH-1/HIGH-2 -- die Liste steht ausfuehrlich am
Docstring von ``_is_filler_artifact``). Beim letzten Mal gingen vollstaendige
Kreditkartennummern durch. Die staerkste Aussage, die wir ueber die aktuelle
Fassung hatten, stammte aus einem Wegwerf-Skript im Security-Audit: rund
200.000 Zufallsfaelle, kein einziger verworfener Treffer mit Klartext im Kern.
Dieses Skript existierte nirgends im Repo -- die Aussage war also nicht
reproduzierbar, weder fuer Aussenstehende noch fuer uns beim naechsten
Refactoring. Diese Datei macht sie dauerhaft nachpruefbar.

DIE GEPRUEFTE EIGENSCHAFT
-------------------------
Ein Treffer darf NUR dann verworfen werden, wenn er AUSSCHLIESSLICH aus
Fuellmaterial besteht, das WIR selbst eingesetzt haben. Formal wird die
vollstaendige Charakterisierung geprueft -- beide Richtungen:

  verworfen  <=>  (Span geklemmt auf den Text ist nicht leer)
                  UND (Span enthaelt kein einziges Nicht-Whitespace-Zeichen)
                  UND (Span schneidet mindestens einen Fuellerbereich)

Die sicherheitskritische Richtung ist "=>" von rechts nach links gelesen:
Sobald auch nur EIN Zeichen Klartext im Kern liegt, muss der Treffer bestehen
bleiben und zum Block fuehren. Genau daran ist der Filter dreimal gescheitert.

DER GENERATOR IST DIE EIGENTLICHE ARBEIT
----------------------------------------
Ein Fuzzer, der harmlose Zufallsstrings erzeugt, beweist nichts: er trifft die
Grenzfaelle nie. Der Generator hier baut den Probe-String mit dem ECHTEN
``_build_probe`` und leitet die Span-Grenzen anschliessend aus den TATSAECH-
LICHEN Fuellerpositionen ab (``_kandidaten_grenzen``). Damit liegen die
erzeugten Spans systematisch genau dort, wo die bisherigen Lecks sassen:
exakt auf einer Fuellergrenze, ein Zeichen davor, ein Zeichen dahinter, ueber
einen Fueller hinweg, ueber mehrere Fueller hinweg. Zusaetzlich deckt
``KATALOG`` die benannten Grenzfaelle als lesbare, deterministische
Regressionsfaelle ab (Platzhalter am Textanfang/-ende, Klartext ohne Trenner
direkt neben Fuellmaterial, leere und einzeichige Kerne, Umlaute und
Mehrbyte-Zeichen an den Grenzen).

Ebenfalls variiert wird der ``entity_type`` -- inklusive ``CUSTOM_*``. Der
Filter entscheidet nach HERKUNFT (Fuellerposition), nie nach Typ; wuerde nur
``PERSON`` erzeugt, liefe ein Rueckbau auf den Praefix-Filter (Leck F10)
unbemerkt durch. Im Katalog wird jeder Fall gegen ALLE Typen gefahren und muss
dasselbe Ergebnis liefern.

FALLZAHL, SEED, GROSSER LAUF
----------------------------
Standardlauf: 4.000 Faelle (``_STANDARD_FAELLE``), Seed 20260820
(``_STANDARD_SEED``), Laufzeit rund 0,4 s auf einem Entwicklerrechner. Die
Suite hat ueber 300 Tests und wird oft ausgefuehrt -- der Standardlauf muss
deshalb billig bleiben.

Grosser Auditlauf (100.000+ Faelle) ueber Umgebungsvariablen:

    DATENSCHLEUSE_FUZZ_FAELLE=200000 PYTHONPATH=litellm \
        python3 -m unittest discover -s test

    # anderer Seed, um die Aussage vom konkreten Seed zu loesen:
    DATENSCHLEUSE_FUZZ_FAELLE=200000 DATENSCHLEUSE_FUZZ_SEED=1 \
        PYTHONPATH=litellm python3 -m unittest discover -s test

Der Seed ist fest verdrahtet, weil Reproduzierbarkeit hier wichtiger ist als
Eleganz: schlaegt der Test in CI fehl, muss derselbe Fall lokal exakt wieder
entstehen. ``hypothesis`` waere das passendere Werkzeug, ist aber KEINE
Projekt-Abhaengigkeit (weder ``litellm/requirements-guardrail.txt`` noch
``test/requirements.txt`` fuehren es) -- und eine neue Abhaengigkeit braucht
nach Gesetz 5 eine eigene Begruendung und Pruefung. Fuer diesen Zweck traegt
``random`` mit festem Seed die Aussage genauso: der Generator ist ohnehin
handgeschrieben auf die bekannten Grenzfaelle hin, nicht generisch.

GEGENPROBE
----------
Dass dieser Test die bekannten Lecks auch wirklich FAENGT, ist nachgewiesen:
mit der kaputten Filtervariante (verwirft, sobald ein Treffer Fuellmaterial
nur BERUEHRT, statt zu verlangen, dass er ausschliesslich daraus besteht --
das ist Leck S1) wird er rot, ebenso mit dem ``CUSTOM_``-Praefixfilter (F10).
Ein Test, der die bekannten Lecks nicht faengt, ist wertlos, egal wie viele
Faelle er durchlaeuft.
"""

import os
import random
import sys
import unittest

# litellm/-Ordner (mit datenschleuse_guardrail.py) auf den Importpfad legen.
_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402


_STANDARD_FAELLE = 4000
_STANDARD_SEED = 20260820


def _fallzahl() -> int:
    """Fallzahl des Fuzzlaufs -- ueber Umgebungsvariable skalierbar."""
    roh = os.environ.get("DATENSCHLEUSE_FUZZ_FAELLE")
    if not roh:
        return _STANDARD_FAELLE
    try:
        wert = int(roh)
    except ValueError:
        return _STANDARD_FAELLE
    return max(1, wert)


def _seed() -> int:
    roh = os.environ.get("DATENSCHLEUSE_FUZZ_SEED")
    if not roh:
        return _STANDARD_SEED
    try:
        return int(roh)
    except ValueError:
        return _STANDARD_SEED


# ---------------------------------------------------------------------------
# Bausteine des Generators
# ---------------------------------------------------------------------------
# Klartext-Bausteine. Bewusst gemischt: ASCII, Umlaute, Eszett, Mehrbyte
# (CJK, Emoji), Ziffern, Satz- und Trennzeichen, Whitespace-Varianten sowie
# leere und einzeichige Stuecke. Die Mehrbyte-Zeichen stehen absichtlich auch
# ALLEIN, damit sie direkt an einer Fuellergrenze landen koennen.
_KLARTEXT = (
    "", "a", "X", "7", "-", ".", "_",
    "Anna", "Mueller", "Nord", "wind", "Rathaus",
    "Mueller-Luedenscheidt", "4111111111111111", "4111 1111 1111 1111",
    "Muenchen", "Strasse 5", "GmbH",
    # Umlaute / Eszett / diakritische Zeichen
    "ae", "Ae", "ss", "Muenchen", "Grosse", "Weissenboeck", "Zoe", "Andre",
    "ä", "ö", "ü", "ß", "Müller", "Straße",
    "Große", "ÄÖÜ",
    # Mehrbyte / ausserhalb der BMP
    "中文", "日本", "\U0001F600", "\U0001F469‍\U0001F4BB",
    "Ж", "א", "الع",
    # kombinierende Zeichen direkt an der Grenze
    "é", "ä",
    # Whitespace-Varianten: sehen wie unser Fueller aus, sind aber KLARTEXT
    # aus dem Originaltext -- der Filter darf sie nur verwerfen, wenn sie
    # zusaetzlich einen echten Fuellerbereich schneiden.
    " ", "  ", "\t", "\n", " ", " \t ",
)

# Platzhalter, wie die Maskierung sie erzeugt. Enthaelt bewusst ein Paar mit
# gemeinsamem Praefix (PERSON_1 / PERSON_10), weil _build_probe dafuer die
# laengsten Schluessel zuerst sortiert -- ein Fehler dort verschoebe alle
# Fuellerpositionen und damit die Grundlage des Filters.
_PLATZHALTER = (
    "<PERSON_0>", "<PERSON_1>", "<PERSON_10>",
    "<LOCATION_0>", "<CREDIT_CARD_0>", "<IBAN_CODE_2>",
    "<CUSTOM_KUNDE_3>", "<CUSTOM_PROJEKT_0>",
)


# Entity-Typen. Bewusst MIT ``CUSTOM_``-Praefix: der erste Leck-Versuch (F10)
# filterte nach genau diesem Praefix und nahm damit das Sicherheitsnetz fuer
# eigene Entitaeten komplett heraus. Wuerde der Fuzzer nur ``PERSON``
# erzeugen, liefe ein Rueckbau auf den Praefix-Filter unbemerkt durch.
_ENTITY_TYPEN = (
    "PERSON", "CREDIT_CARD", "IBAN_CODE", "LOCATION", "EMAIL_ADDRESS",
    "CUSTOM_KUNDE", "CUSTOM_PROJEKT", "CUSTOM_DENY", "DE_STEUER_ID",
)


def _zufallsfall(rng):
    """Baut Text + reid_map und laesst den ECHTEN _build_probe darueber laufen.

    Wichtig: die Fuellerpositionen werden NICHT nachgebaut, sondern von der
    Produktionsfunktion geliefert. Sonst wuerde der Test seine eigene
    Vorstellung pruefen statt des Codes.
    """
    segmente = rng.randint(1, 5)
    teile = []
    genutzt = []

    # Platzhalter am Textanfang ist ein eigener Grenzfall (Fueller bei 0).
    if rng.random() < 0.35:
        p = rng.choice(_PLATZHALTER)
        teile.append(p)
        genutzt.append(p)

    for _ in range(segmente):
        teile.append(rng.choice(_KLARTEXT))
        if rng.random() < 0.8:
            p = rng.choice(_PLATZHALTER)
            teile.append(p)
            genutzt.append(p)
            # Direkt angrenzender zweiter Platzhalter: erzeugt die
            # Leerzeichenkette, auf die ein Whitespace-Muster greift.
            if rng.random() < 0.3:
                p2 = rng.choice(_PLATZHALTER)
                teile.append(p2)
                genutzt.append(p2)

    # Platzhalter am Textende (Fueller direkt am Rand).
    if rng.random() < 0.35:
        p = rng.choice(_PLATZHALTER)
        teile.append(p)
        genutzt.append(p)
    else:
        teile.append(rng.choice(_KLARTEXT))

    text = "".join(teile)
    # Die reid_map bildet Platzhalter -> Klartext ab. Der Wert ist fuer
    # _build_probe egal, nur die Schluessel zaehlen.
    reid_map = {p: "geheim" for p in genutzt}
    if rng.random() < 0.1:
        # Auch der Fall "Map enthaelt Schluessel, die im Text gar nicht
        # vorkommen" muss den Filter nicht aus der Bahn werfen.
        reid_map[rng.choice(_PLATZHALTER)] = "geheim"

    probe, filler_spans = dg._build_probe(text, reid_map)
    return text, reid_map, probe, filler_spans


def _kandidaten_grenzen(rng, probe, filler_spans):
    """Span-Grenzen, die systematisch AUF den Fuellergrenzen liegen.

    Das ist der Kern des Generators. Rein zufaellige Offsets treffen die
    Grenzfaelle praktisch nie -- die Lecks sassen aber genau dort: exakt auf
    der Grenze, ein Zeichen davor, ein Zeichen dahinter, ueber den Fueller
    hinweg.
    """
    n = len(probe)
    kandidaten = {0, n}
    for fs, fe in filler_spans:
        for k in (fs - 2, fs - 1, fs, fs + 1, fe - 1, fe, fe + 1, fe + 2):
            if 0 <= k <= n:
                kandidaten.add(k)
    # Etwas Streuung, damit nicht nur die Grenzen selbst geprueft werden.
    for _ in range(3):
        if n:
            kandidaten.add(rng.randint(0, n))
    return sorted(kandidaten)


def _spans(rng, probe, filler_spans):
    """Erzeugt die zu pruefenden Treffer-Spans fuer einen Fall."""
    grenzen = _kandidaten_grenzen(rng, probe, filler_spans)
    spans = []
    for _ in range(6):
        a = rng.choice(grenzen)
        b = rng.choice(grenzen)
        spans.append((min(a, b), max(a, b)))
    # Ein Span, der ALLE Fueller ueberspannt (mehrere Platzhalter im selben
    # Treffer) -- der Fall, an dem Leck S1 die Kreditkarte verlor.
    if filler_spans:
        spans.append((filler_spans[0][0], filler_spans[-1][1]))
        spans.append((max(0, filler_spans[0][0] - 1),
                      min(len(probe), filler_spans[-1][1] + 1)))
    # Der ganze Text.
    spans.append((0, len(probe)))
    return spans


def _erwartet_verworfen(probe, start, end, filler_spans):
    """Die Referenz-Eigenschaft, unabhaengig vom Produktionscode formuliert.

    Bewusst NICHT aus _is_filler_artifact abgeleitet, sondern aus der
    Sicherheitsaussage: verworfen werden darf nur, was geklemmt nicht leer
    ist, kein Nicht-Whitespace-Zeichen enthaelt und einen Fuellerbereich
    schneidet.
    """
    s = max(0, start)
    e = min(len(probe), end)
    if s >= e:
        return False
    if probe[s:e].strip():
        return False
    return any(fs < e and s < fe for fs, fe in filler_spans)


# ---------------------------------------------------------------------------
# Benannte Grenzfaelle -- lesbare Regression neben dem Zufallslauf.
# Format: (name, text, reid_map, span_baustein, erwartung_verworfen)
# Der Span wird ueber eine Funktion aus (probe, filler_spans) bestimmt, damit
# die Faelle die echten Fuellerpositionen benutzen.
# ---------------------------------------------------------------------------
KATALOG = (
    (
        "Span exakt AUF dem Fueller -> reines Artefakt, darf weg",
        "Anna<PERSON_0>Mueller", {"<PERSON_0>": "X"},
        lambda p, f: (f[0][0], f[0][1]), True,
    ),
    (
        "Span endet an der Fuellergrenze, Klartext davor -> muss bleiben",
        "Anna<PERSON_0>Mueller", {"<PERSON_0>": "X"},
        lambda p, f: (f[0][0] - 1, f[0][1]), False,
    ),
    (
        "Span beginnt an der Fuellergrenze, Klartext dahinter -> muss bleiben",
        "Anna<PERSON_0>Mueller", {"<PERSON_0>": "X"},
        lambda p, f: (f[0][0], f[0][1] + 1), False,
    ),
    (
        "Span ueberspannt den Platzhalter komplett -> muss bleiben",
        "Anna<PERSON_0>Mueller", {"<PERSON_0>": "X"},
        lambda p, f: (0, len(p)), False,
    ),
    (
        "zwei angrenzende Platzhalter, nur Fueller im Span -> darf weg",
        "<PERSON_0><PERSON_1>", {"<PERSON_0>": "X", "<PERSON_1>": "Y"},
        lambda p, f: (f[0][0], f[-1][1]), True,
    ),
    (
        "mehrere Platzhalter, Klartext dazwischen -> muss bleiben",
        "<PERSON_0>X<PERSON_1>", {"<PERSON_0>": "A", "<PERSON_1>": "B"},
        lambda p, f: (f[0][0], f[-1][1]), False,
    ),
    (
        "Kreditkarte zwischen Platzhaltern (Leck HIGH-2) -> muss bleiben",
        "<PERSON_0>4111111111111111<PERSON_1>",
        {"<PERSON_0>": "A", "<PERSON_1>": "B"},
        lambda p, f: (f[0][0], f[-1][1]), False,
    ),
    (
        "Kreditkarte in Vierergruppen ueber Platzhalter (Leck HIGH-1)",
        "4111<PERSON_0>1111<PERSON_1>1111<PERSON_10>1111",
        {"<PERSON_0>": "A", "<PERSON_1>": "B", "<PERSON_10>": "C"},
        lambda p, f: (0, len(p)), False,
    ),
    (
        "Platzhalter am Textanfang, Span ab 0 mit Klartext -> muss bleiben",
        "<PERSON_0>Anna", {"<PERSON_0>": "X"},
        lambda p, f: (0, len(p)), False,
    ),
    (
        "Platzhalter am Textende, Span bis Ende mit Klartext -> muss bleiben",
        "Anna<PERSON_0>", {"<PERSON_0>": "X"},
        lambda p, f: (0, len(p)), False,
    ),
    (
        "einzeichiger Kern direkt neben dem Fueller -> muss bleiben",
        "a<PERSON_0>b", {"<PERSON_0>": "X"},
        lambda p, f: (f[0][0] - 1, f[0][0]), False,
    ),
    (
        "leerer Span (start == end) -> nie Artefakt",
        "Anna<PERSON_0>Mueller", {"<PERSON_0>": "X"},
        lambda p, f: (f[0][0], f[0][0]), False,
    ),
    (
        "Umlaut direkt an der Fuellergrenze -> muss bleiben",
        "Müller<PERSON_0>Straße", {"<PERSON_0>": "X"},
        lambda p, f: (f[0][0] - 1, f[0][1] + 1), False,
    ),
    (
        "Emoji (ausserhalb BMP) direkt an der Fuellergrenze -> muss bleiben",
        "\U0001F600<PERSON_0>\U0001F600", {"<PERSON_0>": "X"},
        lambda p, f: (f[0][0] - 1, f[0][1] + 1), False,
    ),
    (
        "CJK direkt an der Fuellergrenze -> muss bleiben",
        "中文<PERSON_0>日本", {"<PERSON_0>": "X"},
        lambda p, f: (f[0][0] - 1, f[0][1] + 1), False,
    ),
    (
        "echter Whitespace aus dem Text OHNE Fuellerschnitt -> nicht Artefakt",
        "Anna  Mueller<PERSON_0>", {"<PERSON_0>": "X"},
        lambda p, f: (4, 6), False,
    ),
    (
        "Whitespace aus dem Text MIT Fuellerschnitt -> darf weg",
        "Anna <PERSON_0> Mueller", {"<PERSON_0>": "X"},
        lambda p, f: (f[0][0] - 1, f[0][1] + 1), True,
    ),
)


class FillerArtefaktKatalogTest(unittest.TestCase):
    """Benannte Grenzfaelle -- deterministisch, ohne Zufall."""

    def test_katalog(self):
        for name, text, reid_map, span_fn, erwartet in KATALOG:
            with self.subTest(name=name):
                probe, filler = dg._build_probe(text, reid_map)
                self.assertTrue(filler, f"{name}: kein Fueller erzeugt -- "
                                        "der Fall prueft dann gar nichts")
                start, end = span_fn(probe, filler)

                # Jeder Fall laeuft mit ALLEN Entity-Typen und muss dasselbe
                # Ergebnis liefern. Der Filter entscheidet nach HERKUNFT
                # (Fuellerposition), nie nach Typ -- ein Rueckbau auf den
                # ``CUSTOM_``-Praefixfilter (Leck F10) faellt hier auf.
                for typ in _ENTITY_TYPEN:
                    entity = {"start": start, "end": end, "entity_type": typ}
                    ist = dg._is_filler_artifact(probe, entity, filler)
                    self.assertEqual(
                        ist, erwartet,
                        f"{name}\n  probe={probe!r} span=({start},{end}) "
                        f"kern={probe[max(0, start):max(0, end)]!r} typ={typ} "
                        f"filler={filler}\n  erwartet verworfen={erwartet}, "
                        f"ist={ist}",
                    )
                    # Zusaetzlich gegen die unabhaengig formulierte Eigenschaft.
                    self.assertEqual(
                        ist, _erwartet_verworfen(probe, start, end, filler),
                        f"{name} (typ={typ}): weicht von der "
                        "Referenz-Eigenschaft ab",
                    )


class FillerArtefaktFuzzTest(unittest.TestCase):
    """Der eigentliche Fuzzlauf ueber die volle Charakterisierung."""

    def test_kein_klartext_wird_je_verworfen(self):
        rng = random.Random(_seed())
        faelle = _fallzahl()
        geprueft = 0
        verworfen = 0
        mit_klartext_und_fuellerschnitt = 0

        for _ in range(faelle):
            text, reid_map, probe, filler = _zufallsfall(rng)
            for start, end in _spans(rng, probe, filler):
                typ = rng.choice(_ENTITY_TYPEN)
                entity = {"start": start, "end": end, "entity_type": typ}
                ist = dg._is_filler_artifact(probe, entity, filler)
                soll = _erwartet_verworfen(probe, start, end, filler)
                geprueft += 1
                if ist:
                    verworfen += 1

                s = max(0, start)
                e = min(len(probe), end)
                kern = probe[s:e] if s < e else ""

                # DIE sicherheitskritische Richtung: Klartext im Kern
                # bedeutet, der Treffer MUSS bestehen bleiben.
                if kern.strip():
                    if any(fs < e and s < fe for fs, fe in filler):
                        mit_klartext_und_fuellerschnitt += 1
                    self.assertFalse(
                        ist,
                        "LECK: Treffer mit Klartext im Kern wurde verworfen.\n"
                        f"  text={text!r}\n  reid_map={reid_map!r}\n"
                        f"  probe={probe!r}\n  span=({start},{end}) "
                        f"kern={kern!r} typ={typ}\n  filler={filler}\n"
                        f"  seed={_seed()}",
                    )

                # Und die vollstaendige Charakterisierung (beide Richtungen).
                self.assertEqual(
                    ist, soll,
                    "Filter weicht von der Referenz-Eigenschaft ab.\n"
                    f"  text={text!r}\n  probe={probe!r}\n"
                    f"  span=({start},{end}) kern={kern!r} typ={typ}\n"
                    f"  filler={filler}\n  erwartet={soll} ist={ist}\n"
                    f"  seed={_seed()}",
                )

        # Der Lauf muss die interessanten Faelle auch WIRKLICH getroffen
        # haben -- sonst ist er gruen, ohne etwas zu beweisen.
        self.assertGreater(geprueft, faelle,
                           "zu wenige Spans geprueft")
        self.assertGreater(
            verworfen, 0,
            "kein einziger Treffer wurde verworfen -- der Generator erzeugt "
            "die Artefaktfaelle nicht mehr, der Test beweist nichts",
        )
        self.assertGreater(
            mit_klartext_und_fuellerschnitt, faelle // 10,
            "zu wenige Faelle mit Klartext im Kern UND Fuellerschnitt -- "
            "genau diese Kombination ist der Leckfall (S1/HIGH-1/HIGH-2); "
            "ohne sie prueft der Fuzzer die kritische Grenze nicht",
        )

    def test_kaputte_spans_werden_nie_verworfen(self):
        """Verdrehte, negative und ueberlange Spans: im Zweifel blocken.

        Ein unlesbarer oder unsinniger Treffer ist etwas anderes als ein
        Whitespace-Treffer -- er darf nie als Artefakt durchgehen (S3).
        """
        rng = random.Random(_seed() + 1)
        for _ in range(500):
            _text, _map, probe, filler = _zufallsfall(rng)
            n = len(probe)
            kaputte = [
                {"start": 5, "end": 1},
                {"start": -10, "end": -1},
                {"start": n + 5, "end": n + 10},
                {"start": 0, "end": 0},
                {"start": "a", "end": 3},
                {"start": None, "end": 2},
                {"start": 1},
                {},
            ]
            for entity in kaputte:
                entity = dict(entity, entity_type="PERSON")
                self.assertFalse(
                    dg._is_filler_artifact(probe, entity, filler),
                    f"kaputter Span wurde als Artefakt verworfen: {entity!r} "
                    f"probe={probe!r}",
                )

    def test_ohne_fueller_wird_nichts_verworfen(self):
        """Ohne eigene Einfuegung kann kein Treffer unser Artefakt sein."""
        rng = random.Random(_seed() + 2)
        for _ in range(500):
            _text, _map, probe, _filler = _zufallsfall(rng)
            n = len(probe)
            if n == 0:
                continue
            a = rng.randint(0, n)
            b = rng.randint(0, n)
            entity = {"start": min(a, b), "end": max(a, b),
                      "entity_type": "PERSON"}
            self.assertFalse(
                dg._is_filler_artifact(probe, entity, []),
                f"ohne Fuellerbereiche darf nichts verworfen werden: "
                f"probe={probe!r} entity={entity!r}",
            )


if __name__ == "__main__":
    unittest.main()
