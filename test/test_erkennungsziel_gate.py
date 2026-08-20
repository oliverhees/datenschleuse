"""Tests fuer das Erkennungsziel-Gate im Korpus-Benchmark.

Das Ziel aus `docs/foundation/erkennungsziel.md` ist erst dann ein Gate, wenn
es maschinell geprueft wird. Ohne Durchsetzung ist es ein Wunsch, den man beim
naechsten roten Lauf stillschweigend absenkt.

Geprueft wird die reine Auswertungs-Logik (`evaluate_targets`) gegen
konstruierte Ergebnisse -- ohne laufenden Analyzer, damit CI das Gate auch
dann pruefen kann, wenn kein Presidio erreichbar ist.

Die Schwellen stammen 1:1 aus dem Grundbuch. Sie sind nach ERKENNUNGS-
MECHANISMUS gestaffelt, nicht pauschal -- ein einzelner Wert fuer alle Typen
waere nicht verteidigungsfaehig, weil die Klassen fundamental verschieden gut
erkennbar sind (Belege in docs/foundation/erkennungsziel.md, Abschnitt 5):

    Recall gesamt                        >= 0.95
    Recall musterbasiert (Regex/Pruefsumme) >= 0.98
    Recall PERSON                        >= 0.90
    Recall LOCATION                      >= 0.85
    Recall ORGANIZATION                  >= 0.75
    Stoerquote                           <= 0.10
    Precision                            >= 0.90

Ausfuehren (aus dem Repo-Root):
    python3 -m unittest discover -s ./test -p "test_erkennungsziel_gate.py" -v
"""

import importlib.util
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_BENCHMARK_PATH = os.path.join(_HERE, "corpus-benchmark.py")


def _load_benchmark_module():
    """Laedt corpus-benchmark.py als Modul (Dateiname enthaelt einen Bindestrich)."""
    spec = importlib.util.spec_from_file_location("corpus_benchmark", _BENCHMARK_PATH)
    module = importlib.util.module_from_spec(spec)
    # Muss VOR exec_module in sys.modules stehen: `from __future__ import
    # annotations` macht die dataclass-Felder zu Strings, die dataclasses beim
    # Verarbeiten ueber sys.modules[cls.__module__] aufloest.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


cb = _load_benchmark_module()


def _result(*, tp, fn, fp, neg_cases, neg_with_fp, by_type=None):
    """Baut ein BenchmarkResult mit den fuer das Gate relevanten Feldern."""
    res = cb.BenchmarkResult()
    res.must_detect_overall = cb.Tally(tp=tp, fn=fn, fp=fp)
    res.negative_case_count = neg_cases
    res.negative_cases_with_fp = neg_with_fp
    for etype, (t_tp, t_fn) in (by_type or {}).items():
        res.must_detect_by_type[etype] = cb.Tally(tp=t_tp, fn=t_fn, fp=0)
    return res


class ZielSchwellen(unittest.TestCase):
    def test_schwellen_entsprechen_dem_grundbuch(self):
        self.assertEqual(cb.TARGET_RECALL_OVERALL, 0.95)
        self.assertEqual(cb.TARGET_STOERQUOTE_MAX, 0.10)
        self.assertEqual(cb.TARGET_PRECISION, 0.90)
        self.assertEqual(cb.TARGET_PER_TYPE_MIN_SUPPORT, 3)

    def test_ner_typen_haben_eigene_schwellen(self):
        """Gestaffelt nach dem, was das Modell nachweislich leisten kann."""
        self.assertEqual(cb.TARGET_RECALL_BY_TYPE["PERSON"], 0.90)
        self.assertEqual(cb.TARGET_RECALL_BY_TYPE["LOCATION"], 0.85)
        self.assertEqual(cb.TARGET_RECALL_BY_TYPE["ORGANIZATION"], 0.75)

    def test_musterbasierte_typen_haben_die_hoechste_schwelle(self):
        """Regex/Pruefsumme ist deterministisch -- hier gibt es keine Ausrede."""
        self.assertEqual(cb.TARGET_RECALL_PATTERN_BASED, 0.98)
        self.assertEqual(cb.target_for_type("IBAN_CODE"), 0.98)
        self.assertEqual(cb.target_for_type("DE_STEUER_ID"), 0.98)
        self.assertEqual(cb.target_for_type("PERSON"), 0.90)


class GateAuswertung(unittest.TestCase):
    def test_aktueller_projektstand_besteht(self):
        """Der gemessene Stand (Recall 100%, Precision 96.2%, Stoerquote 6.2%)."""
        res = _result(tp=51, fn=0, fp=2, neg_cases=32, neg_with_fp=2)
        verstoesse = cb.evaluate_targets(res)
        self.assertEqual(verstoesse, [], "Aktueller Stand sollte alle Gates erfuellen.")

    def test_recall_unter_ziel_faellt_auf(self):
        res = _result(tp=90, fn=10, fp=0, neg_cases=10, neg_with_fp=0)  # 90% Recall
        verstoesse = cb.evaluate_targets(res)
        self.assertTrue(any("Recall" in v for v in verstoesse), verstoesse)

    def test_stoerquote_ueber_ziel_faellt_auf(self):
        # Recall und Precision gut, aber jeder zweite PII-freie Text gestoert.
        res = _result(tp=100, fn=0, fp=5, neg_cases=10, neg_with_fp=5)
        verstoesse = cb.evaluate_targets(res)
        self.assertTrue(any("Stoerquote" in v for v in verstoesse), verstoesse)

    def test_precision_unter_ziel_faellt_auf(self):
        res = _result(tp=50, fn=0, fp=20, neg_cases=40, neg_with_fp=2)
        verstoesse = cb.evaluate_targets(res)
        self.assertTrue(any("Precision" in v for v in verstoesse), verstoesse)

    def test_schwacher_typ_faellt_auf_trotz_gutem_gesamtwert(self):
        """Der Kernzweck des Per-Typ-Gates: ein Typ mit 0% Recall darf sich
        nicht hinter einem guten Gesamtwert verstecken (Fall IP_ADDRESS)."""
        res = _result(
            tp=97,
            fn=3,
            fp=0,
            neg_cases=10,
            neg_with_fp=0,
            by_type={"PERSON": (94, 0), "IP_ADDRESS": (0, 3)},
        )
        verstoesse = cb.evaluate_targets(res)
        self.assertTrue(
            any("IP_ADDRESS" in v for v in verstoesse),
            "Typ mit 0%% Recall muss auffallen. Verstoesse: %r" % verstoesse,
        )

    def test_ner_typ_darf_niedriger_liegen_als_musterbasierter(self):
        """ORGANIZATION bei 80% besteht (Ziel 75%), IBAN bei 80% nicht (Ziel 98%)."""
        res = _result(
            tp=96, fn=4, fp=0, neg_cases=10, neg_with_fp=0,
            by_type={"ORGANIZATION": (8, 2), "IBAN_CODE": (8, 2)},
        )
        verstoesse = cb.evaluate_targets(res)
        self.assertFalse(
            any("ORGANIZATION" in v for v in verstoesse),
            "ORGANIZATION bei 80%% liegt ueber seinem Ziel von 75%%. %r" % verstoesse,
        )
        self.assertTrue(
            any("IBAN_CODE" in v for v in verstoesse),
            "IBAN_CODE bei 80%% verfehlt sein Ziel von 98%%. %r" % verstoesse,
        )

    def test_seltener_typ_loest_nicht_aus(self):
        """Unter Support 3 traegt eine Quote keine Aussage -- kein Fehlalarm."""
        res = _result(
            tp=99,
            fn=1,
            fp=0,
            neg_cases=10,
            neg_with_fp=0,
            by_type={"PERSON": (99, 0), "DE_SELTEN": (0, 1)},
        )
        verstoesse = cb.evaluate_targets(res)
        self.assertFalse(
            any("DE_SELTEN" in v for v in verstoesse),
            "Typ mit Support 1 darf das Gate nicht ausloesen. %r" % verstoesse,
        )

    def test_ohne_negativfaelle_keine_stoerquoten_verletzung(self):
        """Fehlende Negativ-Faelle duerfen nicht als 'bestanden' durchgehen."""
        res = _result(tp=50, fn=0, fp=0, neg_cases=0, neg_with_fp=0)
        verstoesse = cb.evaluate_targets(res)
        self.assertTrue(
            any("Negativ" in v for v in verstoesse),
            "Ein Korpus ohne Negativ-Faelle kann die Precision-Seite nicht "
            "belegen und muss das Gate verletzen, nicht bestehen. %r" % verstoesse,
        )


if __name__ == "__main__":
    unittest.main()
