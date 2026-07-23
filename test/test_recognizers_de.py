"""Unit-Tests fuer die deutschen PatternRecognizer aus recognizers-config.yml.

Laeuft OHNE laufenden Presidio-Container: die Regex-Patterns werden direkt aus
der YAML-Config gelesen und mit dem `regex`-Modul kompiliert -- exakt dem Modul
und den globalen Flags (global_regex_flags), die auch der Presidio-Analyzer
nutzt (variable Lookbehinds / scoped Inline-Flags brauchen `regex`, nicht `re`).

Getestet wird die REINE Muster-Erkennung (matcht der Regex den Ground-Truth-
Teilstring? loest er auf den Negativ-Koedern NICHT aus?). Die Score-Kalibrierung
und das Zusammenspiel mit spaCy/Context deckt der Korpus-Benchmark ab
(test/corpus-benchmark.py gegen den laufenden Analyzer).

Ausfuehren:
    python3 -m unittest test.test_recognizers_de -v
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


if __name__ == "__main__":
    unittest.main()
