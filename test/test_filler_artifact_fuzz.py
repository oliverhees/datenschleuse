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

DAS TYP-UNIVERSUM WIRD ABGELEITET, NICHT GEPFLEGT
-------------------------------------------------
Ebenfalls variiert wird der ``entity_type`` -- inklusive ``CUSTOM_*``. Der
Filter entscheidet nach HERKUNFT (Fuellerposition), nie nach Typ; wuerde nur
``PERSON`` erzeugt, liefe ein Rueckbau auf den Praefix-Filter (Leck F10)
unbemerkt durch. Im Katalog wird jeder Fall gegen ALLE Typen gefahren und muss
dasselbe Ergebnis liefern.

Genau das war lange nur die halbe Miete (QA-Finding F1, DATENSCHLE-78): Hier
stand eine handgepflegte Liste aus neun Typen. Von den DREIZEHN eigenen
deutschen Recognizern in ``presidio/recognizers-config.yml`` war genau EINER
darin, Standardtypen wie PHONE_NUMBER, URL und IP_ADDRESS fehlten ganz. Ein
Filter mit

    if entity.get("entity_type") == "DE_GEBURTSDATUM": return True

lief dadurch durch Katalog UND Fuzzlauf gruen durch, obwohl er ein Klartext-
Geburtsdatum neben einem Platzhalter still verwirft -- exakt die Fehlerklasse,
gegen die der Absatz oben schuetzen will. Das Problem war erkannt, die Abhilfe
war zu schmal.

Deshalb wird ``_ENTITY_TYPEN`` heute aus den echten Quellen ABGELEITET
(Recognizer-Konfiguration, ``qi_generalization.QI_ENTITY_TYPES``,
``custom_rules.ENTITY_PREFIX``) und enthaelt kein einziges Typ-Literal mehr.
Ein neuer Recognizer landet automatisch im Fuzzlauf. Fehlt die Konfiguration
oder ist sie unlesbar, FAELLT DER TEST AUS -- er schrumpft nicht still auf
eine Handvoll Typen und meldet Sicherheit, die er nicht geprueft hat.

FALLZAHL, SEED, GROSSER LAUF
----------------------------
Standardlauf: 4.000 Faelle (``_STANDARD_FAELLE``), Seed 20260820
(``_STANDARD_SEED``), Laufzeit rund 0,5 s auf einem Entwicklerrechner. Die
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

GEMESSENE ABDECKUNG DES STANDARDLAUFS
-------------------------------------
Nachgemessen am 2026-08-20 gegen den Code in dieser Datei (4.000 Faelle,
Seed 20260820):

    gepruefte Spans ................................. 35.836
    davon verworfen (reines Artefakt) ...............  3.204
    davon Klartext im Kern UND Fuellerschnitt ....... 24.449  (68,2 %)

Die letzte Zeile ist die wichtige: das ist genau die Kombination, an der
S1/HIGH-1/HIGH-2 die Kreditkarte verloren haben. Ein Lauf, der sie selten
trifft, ist gruen, ohne etwas zu beweisen -- deshalb hat der Test eine
Untergrenze darauf, und zwar relativ zu den geprueften Spans (40 %), nicht
gegen eine feste Zahl.

Die Zahlen stehen zusaetzlich in ``_ABDECKUNG_STANDARDLAUF`` und werden vom
Fuzztest GEPRUEFT. Sie koennen also nicht mehr unbemerkt veralten -- das war
QA-Finding F2, wo dokumentierte und gemessene Werte auseinanderliefen. Seit
die Typwahl an einem eigenen Zufallsstrom haengt (``_fuzz_faelle``), aendern
neue Recognizer diese Zahlen nicht mehr; nur eine Aenderung am GENERATOR tut
das, und dann meldet der Test die neuen Werte.

GEGENPROBE
----------
Dass dieser Test die bekannten Lecks auch wirklich FAENGT, ist nachgewiesen.
Rot werden alle vier bekannten Leckformen:

  1. S1        -- verwirft, sobald ein Treffer Fuellmaterial nur BERUEHRT,
                  statt zu verlangen, dass er ausschliesslich daraus besteht.
  2. F10       -- Filter auf das Typ-Praefix ``CUSTOM_``.
  3. HIGH-1/2  -- Segmentpruefung mit Duplikat-Entfernung und verklebtem Kern.
  4. Typ-Leck  -- verwirft still bei genau einem ``entity_type``. Diese Form
                  lief frueher GRUEN durch (QA-Finding F1) und wird heute von
                  ``TypUniversumTest`` fuer JEDEN Typ des Universums gefangen.

Ein Test, der die bekannten Lecks nicht faengt, ist wertlos, egal wie viele
Faelle er durchlaeuft.
"""

import os
import random
import sys
import tempfile
import unittest

import yaml

# litellm/-Ordner (mit datenschleuse_guardrail.py) auf den Importpfad legen.
_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import custom_rules as cr  # noqa: E402
import datenschleuse_guardrail as dg  # noqa: E402
import qi_generalization as qig  # noqa: E402


_STANDARD_FAELLE = 4000
_STANDARD_SEED = 20260820

# Gemessene Abdeckung des Standardlaufs (4.000 Faelle, Seed 20260820).
# Diese Zahlen stehen auch im Modul-Docstring -- und werden vom Fuzztest
# GEPRUEFT, statt von Hand abgeschrieben zu werden (QA-Finding F2: die
# dokumentierten Zahlen stimmten nicht mit den gemessenen ueberein).
#
# Sie sind stabil gegenueber neuen Recognizern: seit die Typwahl an einem
# eigenen Zufallsstrom haengt (siehe ``_fuzz_faelle``), aendert ein groesseres
# Typ-Universum die Struktur der erzeugten Faelle nicht mehr. Nachgepflegt
# werden muessen sie nur, wenn sich der GENERATOR aendert -- und dann meldet
# der Test es mit den neuen Werten.
_ABDECKUNG_STANDARDLAUF = {
    "geprueft": 35836,
    "verworfen": 3204,
    "mit_klartext_und_fuellerschnitt": 24449,
}


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
# Das Typ-Universum -- ABGELEITET, nicht von Hand gepflegt
# ---------------------------------------------------------------------------
# QA-Finding (DATENSCHLE-78): Hier stand eine handgepflegte Liste aus neun
# Typen. Von den DREIZEHN eigenen deutschen Recognizern in
# ``presidio/recognizers-config.yml`` war genau EINER darin (DE_STEUER_ID),
# Standardtypen wie PHONE_NUMBER, URL und IP_ADDRESS fehlten ganz. Ein Leck
# der Form
#
#     if entity.get("entity_type") == "DE_GEBURTSDATUM": return True
#
# lief damit durch Katalog UND Fuzzlauf gruen durch, obwohl es ein Klartext-
# Geburtsdatum neben einem Platzhalter still verwirft -- exakt die Fehler-
# klasse F10, gegen die dieser Test ausdruecklich schuetzen soll. Das Problem
# war erkannt (siehe Kommentar an _ENTITY_TYPEN), die Abhilfe war zu schmal.
#
# Eine statische Liste veraltet beim naechsten neuen Recognizer erneut. Also
# wird das Universum aus den ECHTEN Quellen abgeleitet:
#
#   1. ``presidio/recognizers-config.yml`` -- unsere eigenen Recognizer ueber
#      ``supported_entity``, plus die dort aktivierten Presidio-Standard-
#      Recognizer ueber ``_PREDEFINED_ENTITAETEN``.
#   2. ``qi_generalization.QI_ENTITY_TYPES`` -- live importiert statt kopiert.
#   3. ``custom_rules.ENTITY_PREFIX`` -- die Laufzeit-Typen aus der Regeldatei
#      lassen sich nicht enumerieren (der Nutzer benennt sie frei), deshalb
#      stellvertretende Beispiele mit dem ECHTEN Praefix.
#   4. ``_PRESIDIO_STANDARD_ZUSATZ`` -- Standardtypen, die im Umlauf sein
#      koennen, ohne dass ein Recognizer sie in unserer Konfiguration fuehrt.
#
# FEHLSCHLAGEN STATT SCHRUMPFEN: Fehlt die Konfiguration oder ist sie nicht
# lesbar, wirft ``_typen_aus_konfiguration`` -- und der Test FAELLT AUS. Ein
# Fuzzer, der bei fehlender Konfiguration still auf eine Handvoll Typen
# zusammenfaellt und gruen meldet, waere schlimmer als die statische Liste:
# er meldete Sicherheit, die er gar nicht geprueft hat.

_KONFIG_PFAD = os.path.normpath(
    os.path.join(_HERE, "..", "presidio", "recognizers-config.yml"))

# Presidio-Standard-Recognizer -> die Entitaetstypen, die sie liefern.
# Die Zuordnung ist explizit, damit ein NEU in der Konfiguration aktivierter
# Standard-Recognizer hier auffaellt: ``_typen_aus_konfiguration`` wirft bei
# einem unbekannten Namen, statt ihn still ohne Typen zu uebergehen.
_PREDEFINED_ENTITAETEN = {
    "EmailRecognizer": ("EMAIL_ADDRESS",),
    "PhoneRecognizer": ("PHONE_NUMBER",),
    "IbanRecognizer": ("IBAN_CODE",),
    "CreditCardRecognizer": ("CREDIT_CARD",),
    "IpRecognizer": ("IP_ADDRESS",),
    "UrlRecognizer": ("URL",),
    "CryptoRecognizer": ("CRYPTO",),
    "DateRecognizer": ("DATE_TIME",),
    # Das NER-Modell liefert mehrere Typen ueber denselben Recognizer.
    "SpacyRecognizer": ("PERSON", "LOCATION", "ORGANIZATION", "NRP",
                        "DATE_TIME"),
    "TransformersRecognizer": ("PERSON", "LOCATION", "ORGANIZATION", "NRP"),
}

# Presidio-Standardtypen, die auftauchen koennen, ohne dass unsere
# Konfiguration einen eigenen Recognizer dafuer fuehrt (Standard-Registry,
# andere Deployments, spaetere Aktivierung). Fuer den Fuzzer ist Grosszuegig-
# keit gratis: der Filter darf auf KEINEN Typ reagieren, also kostet ein Typ
# zu viel nichts -- ein Typ zu wenig kostet ein unentdecktes Leck. Diese
# Menge ist rein ADDITIV; sie darf die abgeleiteten Typen nie ersetzen.
_PRESIDIO_STANDARD_ZUSATZ = (
    "URL", "IP_ADDRESS", "PHONE_NUMBER", "DATE_TIME", "NRP",
    "ORGANIZATION", "MEDICAL_LICENSE", "US_SSN",
)

# Stellvertreter fuer die frei benannten Laufzeit-Typen aus der Regeldatei.
# Das Praefix kommt aus dem Produktionscode, nicht als Literal -- sonst
# liefe eine Umbenennung dort hier unbemerkt ins Leere.
_CUSTOM_BEISPIELE = tuple(
    cr.ENTITY_PREFIX + name
    for name in ("KUNDE", "PROJEKT", "DENY", "KUNDENNAME", "PERSON")
)


def _oeffne_konfiguration(pfad):
    """Indirektion fuer den Dateizugriff -- Tests erzwingen darueber Fehler."""
    return open(pfad, "r", encoding="utf-8")


def _typen_aus_konfiguration(pfad=None):
    """Entitaetstypen aus ``presidio/recognizers-config.yml`` ableiten.

    Wirft ``RuntimeError``, wenn die Konfiguration fehlt, nicht parsebar ist,
    einen unbekannten Standard-Recognizer fuehrt oder keine eigenen Typen
    liefert. Das ist Absicht -- siehe "FEHLSCHLAGEN STATT SCHRUMPFEN" oben.
    """
    pfad = pfad or _KONFIG_PFAD
    try:
        with _oeffne_konfiguration(pfad) as fh:
            daten = yaml.safe_load(fh)
    except OSError as exc:
        raise RuntimeError(
            f"Recognizer-Konfiguration nicht lesbar: {pfad} ({exc}). Das "
            "Typ-Universum des Fuzzers laesst sich damit nicht ableiten -- "
            "der Test faellt aus, statt still zu schrumpfen."
        ) from exc
    except yaml.YAMLError as exc:
        raise RuntimeError(
            f"Recognizer-Konfiguration nicht parsebar: {pfad} ({exc})."
        ) from exc

    if not isinstance(daten, dict):
        raise RuntimeError(
            f"Recognizer-Konfiguration ohne Mapping an der Wurzel: {pfad}")
    eintraege = daten.get("recognizers")
    if not isinstance(eintraege, list) or not eintraege:
        raise RuntimeError(
            f"Recognizer-Konfiguration ohne 'recognizers'-Liste: {pfad}")

    typen = set()
    eigene = set()
    for eintrag in eintraege:
        if not isinstance(eintrag, dict):
            raise RuntimeError(
                f"Recognizer-Eintrag ist kein Mapping: {eintrag!r} ({pfad})")
        entitaet = eintrag.get("supported_entity")
        if entitaet:
            typen.add(str(entitaet))
            eigene.add(str(entitaet))
            continue
        name = str(eintrag.get("name", ""))
        if eintrag.get("type") == "predefined" or name.endswith("Recognizer"):
            if name not in _PREDEFINED_ENTITAETEN:
                raise RuntimeError(
                    f"Unbekannter Presidio-Standard-Recognizer {name!r} in "
                    f"{pfad}. Trage seine Entitaetstypen in "
                    "_PREDEFINED_ENTITAETEN ein -- sonst fuzzt niemand "
                    "diesen Typ.")
            typen.update(_PREDEFINED_ENTITAETEN[name])
            continue
        raise RuntimeError(
            f"Recognizer {name!r} in {pfad} hat weder 'supported_entity' "
            "noch die Markierung 'predefined' -- sein Entitaetstyp ist nicht "
            "bestimmbar.")

    if not eigene:
        raise RuntimeError(
            f"Keine eigenen Entitaetstypen in {pfad} gefunden -- die "
            "Konfiguration ist leer oder hat ein anderes Format. Der Test "
            "faellt aus, statt ein geschrumpftes Universum zu pruefen.")
    return tuple(sorted(typen))


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


# Das Typ-Universum des Fuzzers -- vollstaendig abgeleitet (siehe oben).
# Bewusst MIT ``CUSTOM_``-Praefix: der erste Leck-Versuch (F10) filterte nach
# genau diesem Praefix und nahm damit das Sicherheitsnetz fuer eigene
# Entitaeten komplett heraus. Wuerde der Fuzzer nur ``PERSON`` erzeugen, liefe
# ein Rueckbau auf den Praefix-Filter unbemerkt durch.
#
# Es steht hier bewusst KEIN Typ-Literal mehr: jede Quelle ist live. Ein neuer
# Recognizer in presidio/recognizers-config.yml landet automatisch im Fuzzlauf,
# ohne dass jemand daran denken muss. Genau daran ist die Vorgaengerfassung
# gescheitert.
_ENTITY_TYPEN = tuple(sorted(
    set(_typen_aus_konfiguration())
    | set(_PRESIDIO_STANDARD_ZUSATZ)
    | set(qig.QI_ENTITY_TYPES)
    | set(_CUSTOM_BEISPIELE)
))


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


def _fuzz_faelle(faelle, seed):
    """Der komplette Fuzz-Strom als Generator: EINE Quelle fuer alle Nutzer.

    Liefert ``(text, reid_map, probe, filler, start, end, typ)``.

    ZWEI GETRENNTE ZUFALLSSTROEME -- Absicht: Der Typ wird aus einem eigenen
    ``Random`` gezogen. Sonst verschoebe jeder neue Recognizer in der
    Konfiguration (das Universum wird ja daraus abgeleitet) die Laenge von
    ``_ENTITY_TYPEN``, damit den Verbrauch von ``rng.choice`` und damit den
    GESAMTEN nachfolgenden Zufallsstrom. Die Abdeckungszahlen weiter unten
    wuerden bei jeder Recognizer-Aenderung wandern und muessten staendig
    nachgepflegt werden. So haengt die Struktur der Faelle nur am Generator,
    die Typwahl haengt nur am Typ-Universum -- beide unabhaengig reproduzierbar.
    """
    rng = random.Random(seed)
    rng_typ = random.Random(seed + 977)
    for _ in range(faelle):
        text, reid_map, probe, filler = _zufallsfall(rng)
        for start, end in _spans(rng, probe, filler):
            yield (text, reid_map, probe, filler, start, end,
                   rng_typ.choice(_ENTITY_TYPEN))


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
        faelle = _fallzahl()
        seed = _seed()
        geprueft = 0
        verworfen = 0
        mit_klartext_und_fuellerschnitt = 0

        for text, reid_map, probe, filler, start, end, typ in _fuzz_faelle(
                faelle, seed):
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
                    f"  seed={seed}",
                )

            # Und die vollstaendige Charakterisierung (beide Richtungen).
            self.assertEqual(
                ist, soll,
                "Filter weicht von der Referenz-Eigenschaft ab.\n"
                f"  text={text!r}\n  probe={probe!r}\n"
                f"  span=({start},{end}) kern={kern!r} typ={typ}\n"
                f"  filler={filler}\n  erwartet={soll} ist={ist}\n"
                f"  seed={seed}",
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

        # QA-Finding (DATENSCHLE-78, F3): Die Schwelle lag bei ``faelle // 10``
        # -- bei 4.000 Faellen also 400, gegen einen Ist-Wert um 24.000. Diese
        # 60-fache Marge faengt einen Totalausfall des Generators, aber keinen
        # Einbruch von 68% auf 15%. Die Schwelle ist deshalb RELATIV zu den
        # tatsaechlich geprueften Spans und liegt bei 40%: eng genug, um einen
        # echten Rueckgang zu sehen, weit genug, dass eine harmlose Aenderung
        # am Generator nicht grundlos rot wird (Ist-Wert ~69%, Marge ~1,7x).
        self.assertGreater(
            mit_klartext_und_fuellerschnitt, int(geprueft * 0.4),
            "zu wenige Faelle mit Klartext im Kern UND Fuellerschnitt "
            f"({mit_klartext_und_fuellerschnitt} von {geprueft} geprueften "
            "Spans) -- genau diese Kombination ist der Leckfall "
            "(S1/HIGH-1/HIGH-2); ohne sie prueft der Fuzzer die kritische "
            "Grenze nicht",
        )

        # QA-Finding (DATENSCHLE-78, F2): Dokumentierte und nachgemessene
        # Abdeckung liefen auseinander -- 35.836 / 24.449 dokumentiert gegen
        # 35.844 / 24.610 im Audit gemessen. Ursache war nicht ein Tippfehler,
        # sondern der geteilte Zufallsstrom: die Typwahl zog aus DEMSELBEN
        # ``Random`` wie der Generator, also verschob jede Aenderung am
        # Typ-Universum saemtliche nachfolgenden Faelle. Zwei Messungen
        # desselben Codes konnten so verschiedene Zahlen liefern.
        #
        # Seit ``_fuzz_faelle`` die Typwahl an einen eigenen Strom haengt, ist
        # die Struktur der Faelle vom Typ-Universum entkoppelt und die Zahlen
        # sind eindeutig. Statt sie erneut von Hand abzuschreiben, werden sie
        # hier GEPRUEFT -- sie koennen nicht mehr unbemerkt veralten.
        if faelle == _STANDARD_FAELLE and seed == _STANDARD_SEED:
            self.assertEqual(
                {"geprueft": geprueft,
                 "verworfen": verworfen,
                 "mit_klartext_und_fuellerschnitt":
                     mit_klartext_und_fuellerschnitt},
                _ABDECKUNG_STANDARDLAUF,
                "Die Abdeckung des Standardlaufs hat sich geaendert. Das ist "
                "kein Fehler an sich -- aber die Zahlen im Modul-Docstring "
                "und in _ABDECKUNG_STANDARDLAUF muessen dann mit den neu "
                "gemessenen Werten aktualisiert werden.",
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


class TypUniversumTest(unittest.TestCase):
    """Bildet das Typ-Universum des Fuzzers das echte System ab?

    QA-Finding (DATENSCHLE-78): Es tat es nicht. Neun handgepflegte Typen
    standen dreizehn eigenen deutschen Recognizern gegenueber -- genau EINER
    war abgedeckt. Ein Leck, das nach ``entity_type`` verwirft, lief damit
    gruen durch Katalog und Fuzzlauf. Diese Klasse haelt die Luecke zu, und
    zwar dauerhaft: sie prueft gegen die Konfiguration, nicht gegen eine
    zweite handgepflegte Liste.
    """

    def test_universum_deckt_alle_konfigurierten_typen(self):
        """Jeder Typ aus der Recognizer-Konfiguration muss gefuzzt werden."""
        konfiguriert = _typen_aus_konfiguration()
        fehlend = sorted(set(konfiguriert) - set(_ENTITY_TYPEN))
        self.assertEqual(
            fehlend, [],
            "Typen aus presidio/recognizers-config.yml fehlen im Fuzz-"
            f"Universum: {fehlend}\n"
            "Ein Leck, das genau auf einen dieser Typen keyt, findet diese "
            "Suite NICHT. Das Universum muss aus der Konfiguration abgeleitet "
            "werden, nicht von Hand gepflegt.",
        )

    def test_universum_deckt_presidio_standardtypen(self):
        """Auch die Presidio-Standardtypen gehoeren ins Universum."""
        fehlend = sorted(set(_PRESIDIO_STANDARD_ZUSATZ) - set(_ENTITY_TYPEN))
        self.assertEqual(
            fehlend, [],
            f"Presidio-Standardtypen fehlen im Fuzz-Universum: {fehlend}")

    def test_universum_deckt_qi_typen(self):
        """Die QI-Typen kommen live aus dem Produktionsmodul, nicht kopiert."""
        fehlend = sorted(set(qig.QI_ENTITY_TYPES) - set(_ENTITY_TYPEN))
        self.assertEqual(
            fehlend, [],
            f"QI-Typen fehlen im Fuzz-Universum: {fehlend}")

    def test_universum_enthaelt_laufzeit_custom_typen(self):
        """Die frei benannten Regel-Typen tragen das ECHTE Praefix."""
        mit_praefix = [t for t in _ENTITY_TYPEN
                       if t.startswith(cr.ENTITY_PREFIX)]
        self.assertGreaterEqual(
            len(mit_praefix), 3,
            f"zu wenige Typen mit dem Praefix {cr.ENTITY_PREFIX!r} -- ein "
            "Rueckbau auf den Praefixfilter (Leck F10) fiele hier nicht "
            "mehr auf",
        )

    def test_jeder_typ_im_universum_wird_wirklich_gefahren(self):
        """Ein typ-gekeytes Leck muss fuer JEDEN Typ des Universums auffallen.

        Das ist die vierte Leckvariante aus dem QA-Audit, als Test gegossen.
        Fuer jeden Typ wird ein Filter gebaut, der GENAU bei diesem Typ still
        verwirft. Der Katalogdurchlauf muss ihn finden. Faellt ein Typ hier
        durch, steht er zwar in der Liste, wird aber nirgends wirklich
        gefahren -- das Universum waere dann Dekoration statt Abdeckung.
        """
        echt = dg._is_filler_artifact
        ungefangen = []
        try:
            for typ in _ENTITY_TYPEN:
                def leck(probe, entity, filler_spans, _typ=typ):
                    if entity.get("entity_type") == _typ:
                        return True          # verwirft immer, typ-gekeyt
                    return echt(probe, entity, filler_spans)

                dg._is_filler_artifact = leck
                if not self._katalog_findet_abweichung():
                    ungefangen.append(typ)
        finally:
            dg._is_filler_artifact = echt

        self.assertEqual(
            ungefangen, [],
            "Ein Leck, das auf diese Typen keyt, bleibt unentdeckt: "
            f"{ungefangen}\n"
            "Diese Typen werden im Katalogdurchlauf nicht gefahren.",
        )

    def _katalog_findet_abweichung(self) -> bool:
        """Faehrt den Katalog wie ``test_katalog`` und meldet Abweichungen."""
        for _name, text, reid_map, span_fn, erwartet in KATALOG:
            probe, filler = dg._build_probe(text, reid_map)
            if not filler:
                continue
            start, end = span_fn(probe, filler)
            for typ in _ENTITY_TYPEN:
                entity = {"start": start, "end": end, "entity_type": typ}
                if dg._is_filler_artifact(probe, entity, filler) != erwartet:
                    return True
        return False

    def test_fehlende_konfiguration_faellt_aus_statt_zu_schrumpfen(self):
        """Ohne lesbare Konfiguration muss es KNALLEN, nicht leise gruen."""
        with self.assertRaises(RuntimeError):
            _typen_aus_konfiguration(
                os.path.join(_HERE, "gibt-es-nicht", "recognizers-config.yml"))

    def test_unbrauchbare_konfiguration_faellt_aus(self):
        """Leer, formfremd, kaputt oder ohne eigene Typen -> RuntimeError."""
        faelle = {
            "leere Recognizer-Liste": "recognizers: []\n",
            "leeres Mapping": "{}\n",
            "keine eigenen Typen": (
                "recognizers:\n"
                "  - name: EmailRecognizer\n"
                "    type: predefined\n"
            ),
            "unbekannter Standard-Recognizer": (
                "recognizers:\n"
                "  - name: VoellingNeuerRecognizer\n"
                "    type: predefined\n"
            ),
            "Recognizer ohne bestimmbaren Typ": (
                "recognizers:\n"
                "  - name: irgendwas\n"
            ),
            "kaputtes YAML": "recognizers: [\n  - name: x\n",
        }
        for name, inhalt in faelle.items():
            with self.subTest(fall=name):
                with tempfile.NamedTemporaryFile(
                        "w", suffix=".yml", delete=False,
                        encoding="utf-8") as fh:
                    fh.write(inhalt)
                    pfad = fh.name
                try:
                    with self.assertRaises(RuntimeError):
                        _typen_aus_konfiguration(pfad)
                finally:
                    os.unlink(pfad)


if __name__ == "__main__":
    unittest.main()
