"""Unit-Tests fuer die deutschen PatternRecognizer aus recognizers-config.yml.

Laeuft OHNE laufenden Presidio-Container: die Regex-Patterns werden direkt aus
der YAML-Config gelesen und mit dem `regex`-Modul kompiliert -- exakt dem Modul
und den globalen Flags (global_regex_flags), die auch der Presidio-Analyzer
nutzt (variable Lookbehinds / scoped Inline-Flags brauchen `regex`, nicht `re`).

Getestet wird die REINE Muster-Erkennung (matcht der Regex den Ground-Truth-
Teilstring? loest er auf den Negativ-Koedern NICHT aus?). Die Score-Kalibrierung
und das Zusammenspiel mit spaCy/Context deckt der Korpus-Benchmark ab
(test/corpus-benchmark.py gegen den laufenden Analyzer).

Ausfuehren (aus dem Repo-Root -- "test.test_recognizers_de" kollidiert mit dem
Python-Stdlib-Paket "test" und schlaegt dort fehl, siehe DATENSCHLE-62):
    python3 -m unittest discover -s ./test -p "test_recognizers_de.py" -v
    # oder aus dem test/-Ordner:
    python3 -m unittest test_recognizers_de -v
"""

import os
import unittest

import regex  # das Modul, das Presidio intern verwendet
import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))
_CONFIG_PATH = os.path.normpath(
    os.path.join(_HERE, "..", "presidio", "recognizers-config.yml")
)


def _load_config():
    with open(_CONFIG_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _patterns_for(config, supported_entity):
    """Alle Regex-Patterns des Recognizers mit gegebenem supported_entity."""
    for rec in config.get("recognizers", []):
        if isinstance(rec, dict) and rec.get("supported_entity") == supported_entity:
            return [p["regex"] for p in rec.get("patterns", [])]
    raise AssertionError(f"Kein Recognizer fuer {supported_entity!r} in {_CONFIG_PATH}")


class _RecognizerRegexMixin:
    """Gemeinsame Logik; kein TestCase, damit unittest die Basis nicht sammelt."""

    supported_entity = ""
    must_detect: list[tuple[str, str]] = []      # (text, erwarteter Teilstring)
    must_not_detect: list[str] = []

    @classmethod
    def setUpClass(cls):
        config = _load_config()
        flags = config.get("global_regex_flags", 0)
        cls._compiled = [
            regex.compile(pat, flags) for pat in _patterns_for(config, cls.supported_entity)
        ]

    def _find_all(self, text):
        hits = []
        for pat in self._compiled:
            hits.extend(m.group(0) for m in pat.finditer(text))
        return hits

    def test_must_detect(self):
        for text, expected in self.must_detect:
            with self.subTest(text=text):
                hits = self._find_all(text)
                self.assertTrue(
                    any(expected in h or h in expected for h in hits),
                    f"{self.supported_entity}: erwartete {expected!r} in {text!r}, "
                    f"gefunden: {hits!r}",
                )

    def test_must_not_detect(self):
        for text in self.must_not_detect:
            with self.subTest(text=text):
                hits = self._find_all(text)
                self.assertEqual(
                    hits, [], f"{self.supported_entity}: False Positive in {text!r}: {hits!r}"
                )


class TestDeAktenzeichen(_RecognizerRegexMixin, unittest.TestCase):
    supported_entity = "DE_AKTENZEICHEN"
    must_detect = [
        ("Das Verfahren läuft unter dem Aktenzeichen 3 O 123/45.", "3 O 123/45"),
        ("Bitte nennen Sie das Az. 5 K 678/23 im Betreff.", "5 K 678/23"),
        ("Der BGH entschied unter VI ZR 200/20 zugunsten der Klägerin.", "VI ZR 200/20"),
        ("Unser Geschäftszeichen lautet Gz. 12-3456.7-8/9.", "12-3456.7-8/9"),
    ]
    must_not_detect = [
        "Die Lieferung erfolgt in Kalenderwoche 12/25 wie geplant.",
        "Die Rechnungsnummer 2024/0815 ist bereits beglichen.",
        "Die Software läuft ab Version 2026.07.22 stabil.",
    ]


class TestDeFirma(_RecognizerRegexMixin, unittest.TestCase):
    supported_entity = "DE_FIRMA"
    must_detect = [
        ("Vertrag mit der Mustermann Technik GmbH in Köln.", "Mustermann Technik GmbH"),
        ("Rechnung an die Nordlicht Logistik GmbH & Co. KG.", "Nordlicht Logistik GmbH & Co. KG"),
        ("Beteiligung an der Solaris Energie AG bekanntgegeben.", "Solaris Energie AG"),
        ("Die Kreativ UG (haftungsbeschränkt) wurde gegründet.", "Kreativ UG (haftungsbeschränkt)"),
        ("Spende an die Hoffnung Weltweit gGmbH aus Bremen.", "Hoffnung Weltweit gGmbH"),
        ("Beraten durch die Weber & Söhne OHG aus Hamburg.", "Weber & Söhne OHG"),
    ]
    must_not_detect = [
        "Für eine GmbH gelten andere Haftungsregeln als für eine GbR.",
        "Wir haben die Agentur beauftragt und alles besprochen.",
        "Das Team traf sich am Bahnhof und ging dann essen.",
    ]


class TestDeGeburtsjahr(_RecognizerRegexMixin, unittest.TestCase):
    supported_entity = "DE_GEBURTSJAHR"
    must_detect = [
        ("Der Hinweisgeber gibt an, Jahrgang 1979 zu sein.", "1979"),
        ("Sie ist geboren 1990 und lebt in Köln.", "1990"),
    ]
    must_not_detect = [
        "Die Software läuft ab Version 2026 stabil.",
        "Der Vertrag endet im Jahr 2027.",
        # "geboren am 1990" faellt bewusst NICHT hierher -- das "am" bricht den
        # Match (siehe DE_GEBURTSDATUM fuer volle Daten mit "am").
    ]


class TestDeGeburtsdatum(_RecognizerRegexMixin, unittest.TestCase):
    """Live-Befund 2026-07-30: "geboren am 14.03.1985" wurde bislang von
    KEINEM Recognizer erfasst -- DE_GEBURTSJAHR verlangt die Jahreszahl direkt
    hinterm Kontext-Wort, "am" dazwischen bricht den Match. Ein volles
    Geburtsdatum ist zudem der staerkere der drei Sweeney-Quasi-Identifier
    (PLZ+Geburtsdatum+Geschlecht) -- wichtiger als die blosse Jahreszahl."""

    supported_entity = "DE_GEBURTSDATUM"
    must_detect = [
        ("Herr Bergmann, geboren am 14.03.1985, wohnhaft in München.", "14.03.1985"),
        ("Frau Wagner, geboren 22.11.1990, wohnt in Berlin.", "22.11.1990"),
        ("Geburtsdatum: 01.01.99 laut Akte.", "01.01.99"),
        ("Laut Personalbogen geb. 5.6.2001 in Hamburg.", "5.6.2001"),
    ]
    must_not_detect = [
        "Die Lieferung erfolgt am 14.03.2026 wie geplant.",
        "Die Rechnung Nr. 14.03.1985 wurde bereits beglichen.",
        "Der Termin ist auf den 01.01.2027 verschoben worden.",
    ]


class TestDeStrasse(_RecognizerRegexMixin, unittest.TestCase):
    """Live-Befund 2026-08-03: "Bahnhofstraße 22" blieb im maskierten Text
    unveraendert stehen -- PLZ und Ort wurden erkannt, die Strasse selbst von
    KEINEM Recognizer. Zwei Muster (siehe recognizers-config.yml): Kompositum
    ("Bahnhofstraße 22", hoher Score) und getrennte Schreibweise ("Neue
    Straße 5", "Am Ring 9", moderater Score -- braucht Kontext-Boost)."""

    supported_entity = "DE_STRASSE"
    must_detect = [
        ("Ich wohne in der Bahnhofstraße 22, 80331 München.", "Bahnhofstraße 22"),
        ("Bitte senden Sie es an den Musterweg 5a.", "Musterweg 5a"),
        ("Die Zentrale liegt am Kurfürstendamm 12-14 in Berlin.", "Kurfürstendamm 12-14"),
        ("Anschrift: Hauptstr. 3, 10115 Berlin.", "Hauptstr. 3"),
        ("Termin um 10 Uhr am Goetheplatz 1.", "Goetheplatz 1"),
        ("Neue Anschrift: Neue Straße 5, 12345 Musterstadt.", "Neue Straße 5"),
        ("Er wohnt jetzt Am Ring 9 in Köln.", "Am Ring 9"),
    ]
    must_not_detect = [
        "Die Wegstrecke war für alle Beteiligten viel zu lang.",
        "Für eine GmbH gelten strenge Regeln.",
        "Der Umweg über die Autobahn dauert ewig.",
        "Schritt 5 von 10 ist bereits erledigt.",
    ]


if __name__ == "__main__":
    unittest.main()
