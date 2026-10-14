"""Tests for the hardened test corpus v2 (DATENSCHLE-94).

Offline only: no analyzer needed. They pin three things that kept the corpus
from measuring anything real before:

1. SCHEMA / ANNOTATION RULES (A1-A6). The loader refuses v2 cases that break
   them (ambiguous offsets, titles inside PERSON spans, non-reserved e-mail
   domains, overlapping spans, ...). A rule that is only prose rots.
2. NO-SHRINK. Cases and the hold-out split cannot disappear silently: a
   manifest of case ids + split is compared with the corpus in both
   directions, and absolute floors guard the category minima.
3. SPLIT REPORTING. dev and hold-out are aggregated separately, so a tuning
   run can never hide behind a pooled number.

Run from the repo root:
    python3 -m pytest test/test_corpus_v2.py -q
"""

import importlib.util
import json
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = Path(_HERE).parent
_CORPUS = _ROOT / "test" / "corpus" / "de-pii-testkorpus.yaml"
_MANIFEST = _ROOT / "test" / "corpus" / "corpus-manifest.json"


def _load_cb():
    spec = importlib.util.spec_from_file_location(
        "corpus_benchmark", os.path.join(_HERE, "corpus-benchmark.py")
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


cb = _load_cb()


def _write(tmp: Path, body: str) -> Path:
    path = tmp / "corpus.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


class LoaderSchemaTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _load(self, body):
        return cb.load_corpus(_write(self.tmp, body))

    def test_v1_case_defaults_to_dev_split_and_v1_category(self):
        cases = self._load(
            """
            cases:
              - id: a-1
                text: "Herr Mueller kommt."
                entities:
                  - {type: PERSON, value: "Mueller", expected_recall: must_detect}
            """
        )
        self.assertEqual(cases[0].split, "dev")
        self.assertEqual(cases[0].category, "v1")
        self.assertFalse(cases[0].control)

    def test_unknown_split_is_refused(self):
        with self.assertRaises(cb.BenchmarkError):
            self._load(
                """
                cases:
                  - id: v2-a
                    category: negativ-satzanfang
                    split: validation
                    text: "Fasse den Text zusammen."
                    entities: []
                """
            )

    def test_v2_case_needs_category_and_v2_id_prefix(self):
        with self.assertRaises(cb.BenchmarkError):
            self._load(
                """
                cases:
                  - id: other-a
                    category: negativ-satzanfang
                    split: dev
                    text: "Fasse den Text zusammen."
                    entities: []
                """
            )

    def test_v2_value_must_occur_exactly_once(self):
        with self.assertRaises(cb.BenchmarkError) as ctx:
            self._load(
                """
                cases:
                  - id: v2-dup
                    category: nachname-wort
                    split: dev
                    text: "Herr Koch sagt, Koch sei zufrieden."
                    entities:
                      - {type: PERSON, value: "Koch", expected_recall: must_detect}
                """
            )
        self.assertIn("A1", str(ctx.exception))

    def test_v2_person_value_must_not_carry_a_title(self):
        for bad in ("Herr Koch", "Dr. Anna Koch", "Frau Koch", "Prof. Koch"):
            with self.subTest(bad=bad), self.assertRaises(cb.BenchmarkError):
                self._load(
                    f"""
                    cases:
                      - id: v2-title
                        category: nachname-wort
                        split: dev
                        text: "Heute hat {bad} angerufen."
                        entities:
                          - {{type: PERSON, value: "{bad}", expected_recall: must_detect}}
                    """
                )

    def test_v2_value_must_be_trimmed(self):
        with self.assertRaises(cb.BenchmarkError):
            self._load(
                """
                cases:
                  - id: v2-trim
                    category: nachname-wort
                    split: dev
                    text: "Heute hat Koch, der Leiter, angerufen."
                    entities:
                      - {type: PERSON, value: "Koch,", expected_recall: must_detect}
                """
            )

    def test_v2_email_must_use_a_reserved_domain(self):
        with self.assertRaises(cb.BenchmarkError) as ctx:
            self._load(
                """
                cases:
                  - id: v2-mail
                    category: kombi
                    split: dev
                    text: "Mail an anna.koch@firma-koeln.de bitte."
                    entities:
                      - {type: EMAIL_ADDRESS, value: "anna.koch@firma-koeln.de", expected_recall: must_detect}
                """
            )
        self.assertIn("A6", str(ctx.exception))
        cases = self._load(
            """
            cases:
              - id: v2-mail
                category: kombi
                split: dev
                text: "Mail an anna.koch@firma.example bitte."
                entities:
                  - {type: EMAIL_ADDRESS, value: "anna.koch@firma.example", expected_recall: must_detect}
            """
        )
        self.assertEqual(len(cases), 1)

    def test_v2_spans_must_not_overlap(self):
        with self.assertRaises(cb.BenchmarkError):
            self._load(
                """
                cases:
                  - id: v2-ovl
                    category: adresse-fliesstext
                    split: dev
                    text: "Sie wohnt in Freiburg im Breisgau."
                    entities:
                      - {type: LOCATION, value: "Freiburg im Breisgau", expected_recall: must_detect}
                      - {type: LOCATION, value: "Freiburg", expected_recall: must_detect}
                """
            )

    def test_negative_v2_case_cannot_carry_known_gap_or_control(self):
        with self.assertRaises(cb.BenchmarkError):
            self._load(
                """
                cases:
                  - id: v2-negctl
                    category: negativ-satzanfang
                    split: dev
                    control: true
                    text: "Fasse den Text zusammen."
                    entities: []
                """
            )

    def test_control_case_requires_baseline_detected_on_must_detect(self):
        with self.assertRaises(cb.BenchmarkError) as ctx:
            self._load(
                """
                cases:
                  - id: v2-ctl
                    category: positiv-kontrolle
                    split: dev
                    control: true
                    text: "Herr Dr. Peter Albrecht ruft an."
                    entities:
                      - {type: PERSON, value: "Peter Albrecht", expected_recall: must_detect}
                """
            )
        self.assertIn("baseline_detected", str(ctx.exception))
        cases = self._load(
            """
            cases:
              - id: v2-ctl
                category: positiv-kontrolle
                split: dev
                control: true
                text: "Herr Dr. Peter Albrecht ruft an."
                entities:
                  - {type: PERSON, value: "Peter Albrecht", expected_recall: must_detect, baseline_detected: true}
            """
        )
        self.assertTrue(cases[0].control)
        self.assertIs(cases[0].ground_truth[0].baseline_detected, True)

    def test_baseline_detected_must_be_boolean(self):
        with self.assertRaises(cb.BenchmarkError):
            self._load(
                """
                cases:
                  - id: v2-bd
                    category: positiv-kontrolle
                    split: dev
                    control: true
                    text: "Herr Dr. Peter Albrecht ruft an."
                    entities:
                      - {type: PERSON, value: "Peter Albrecht", expected_recall: must_detect, baseline_detected: "ja"}
                """
            )


class SplitAggregationTest(unittest.TestCase):
    def _case(self, cid, split, text, entities):
        gts = []
        for typ, value in entities:
            start = text.find(value)
            gts.append(
                cb.GroundTruthEntity(
                    case_id=cid, entity_type=typ, value=value,
                    expected_recall="must_detect", start=start,
                    end=start + len(value), occurrences=1,
                )
            )
        return cb.Case(case_id=cid, text=text, ground_truth=gts, split=split)

    def test_dev_and_holdout_are_aggregated_separately(self):
        dev_pos = self._case("v2-1", "dev", "Herr Koch kommt.", [("PERSON", "Koch")])
        ho_pos = self._case("v2-2", "holdout", "Frau Bauer kommt.", [("PERSON", "Bauer")])
        ho_neg = self._case("v2-3", "holdout", "Fasse den Text zusammen.", [])
        matches = [
            cb.match_case(dev_pos, [cb.PredictedEntity("PERSON", 5, 9, 0.85)], 0.5),
            cb.match_case(ho_pos, [], 0.5),  # miss in hold-out
            cb.match_case(ho_neg, [cb.PredictedEntity("PERSON", 0, 5, 0.85)], 0.5),
        ]
        by_split = cb.aggregate_by_split(matches, 0.5)
        self.assertEqual(set(by_split), {"dev", "holdout"})
        self.assertEqual(by_split["dev"].must_detect_overall.tp, 1)
        self.assertEqual(by_split["dev"].must_detect_overall.fn, 0)
        self.assertEqual(by_split["holdout"].must_detect_overall.tp, 0)
        self.assertEqual(by_split["holdout"].must_detect_overall.fn, 1)
        self.assertEqual(by_split["holdout"].negative_case_count, 1)
        self.assertEqual(by_split["holdout"].negative_cases_with_fp, 1)
        self.assertEqual(by_split["dev"].negative_case_count, 0)

    def test_pooled_result_is_unchanged_by_the_split(self):
        a = self._case("v2-1", "dev", "Herr Koch kommt.", [("PERSON", "Koch")])
        b = self._case("v2-2", "holdout", "Frau Bauer kommt.", [("PERSON", "Bauer")])
        matches = [cb.match_case(a, [], 0.5), cb.match_case(b, [], 0.5)]
        pooled = cb.aggregate(matches, 0.5)
        self.assertEqual(pooled.must_detect_overall.fn, 2)

    def test_control_deviations_report_only_changed_controls(self):
        text = "Herr Dr. Peter Albrecht ruft an."
        start = text.find("Peter Albrecht")
        gt_ok = cb.GroundTruthEntity("v2-c", "PERSON", "Peter Albrecht", "must_detect",
                                      start, start + 14, 1, baseline_detected=True)
        case = cb.Case("v2-c", text, [gt_ok], split="dev", category="positiv-kontrolle",
                       control=True)
        hit = cb.match_case(case, [cb.PredictedEntity("PERSON", start, start + 14, 0.9)], 0.5)
        miss = cb.match_case(case, [], 0.5)
        self.assertEqual(cb.control_deviations([hit]), [])
        dev = cb.control_deviations([miss])
        self.assertEqual(len(dev), 1)
        self.assertEqual(dev[0]["case_id"], "v2-c")
        self.assertTrue(dev[0]["baseline_detected"])
        self.assertFalse(dev[0]["detected_now"])


class ReportHelpersTest(unittest.TestCase):
    def _case(self, cid, cat, text, ents, split="dev"):
        gts = []
        for typ, value in ents:
            start = text.find(value)
            gts.append(cb.GroundTruthEntity(cid, typ, value, "must_detect", start,
                                            start + len(value), 1))
        return cb.Case(cid, text, gts, split=split, category=cat)

    def test_misses_list_names_every_missed_entity(self):
        hit = self._case("v2-a", "nachname-wort", "Herr Koch kommt.", [("PERSON", "Koch")])
        miss = self._case("v2-b", "nachname-wort", "Frau Bauer kommt.", [("PERSON", "Bauer")],
                          split="holdout")
        matches = [
            cb.match_case(hit, [cb.PredictedEntity("PERSON", 5, 9, 0.85)], 0.5),
            cb.match_case(miss, [], 0.5),
        ]
        misses = cb.must_detect_misses(matches)
        self.assertEqual(len(misses), 1)
        self.assertEqual(misses[0]["case_id"], "v2-b")
        self.assertEqual(misses[0]["value"], "Bauer")
        self.assertEqual(misses[0]["split"], "holdout")

    def test_category_summary_counts_tp_fn_and_negative_offenders(self):
        pos = self._case("v2-a", "nachname-wort", "Herr Koch kommt.", [("PERSON", "Koch")])
        neg_bad = self._case("v2-b", "negativ-satzanfang", "Fasse es zusammen.", [])
        neg_ok = self._case("v2-c", "negativ-satzanfang", "Erledige es.", [])
        matches = [
            cb.match_case(pos, [], 0.5),
            cb.match_case(neg_bad, [cb.PredictedEntity("PERSON", 0, 5, 0.85)], 0.5),
            cb.match_case(neg_ok, [], 0.5),
        ]
        summary = cb.category_summary(matches)
        self.assertEqual(summary["nachname-wort"]["fn"], 1)
        self.assertEqual(summary["nachname-wort"]["tp"], 0)
        self.assertEqual(summary["negativ-satzanfang"]["negative_cases"], 2)
        self.assertEqual(summary["negativ-satzanfang"]["negative_cases_with_fp"], 1)

    def test_json_report_carries_splits_misses_categories_and_controls(self):
        pos = self._case("v2-a", "nachname-wort", "Herr Koch kommt.", [("PERSON", "Koch")])
        result = cb.aggregate([cb.match_case(pos, [], 0.5)], 0.5)
        report = cb.build_json_report(
            result, corpus_path=Path("x.yaml"), presidio_url="http://x",
            overlap_min_ratio=0.5, case_count=1, timestamp="t",
        )
        for key in ("splits", "must_detect_misses", "by_category", "baseline_control", "corpus"):
            self.assertIn(key, report)
        self.assertEqual(report["splits"]["dev"]["must_detect"]["fn"], 1)
        self.assertEqual(report["corpus"]["by_split"]["dev"]["positive"], 1)

    def test_split_flag_filters_cases_before_the_run(self):
        args = cb.parse_args(["--split", "holdout"])
        self.assertEqual(args.split, "holdout")
        seen = []
        original = cb.analyze_text
        cb.analyze_text = lambda session, url, text, timeout, allow=None, flags=0: (
            seen.append(text) or []
        )
        try:
            _result, count = cb.run_benchmark(args)
        finally:
            cb.analyze_text = original
        holdout = [c for c in cb.load_corpus(_CORPUS) if c.split == "holdout"]
        self.assertEqual(count, len(holdout))
        self.assertEqual(sorted(seen), sorted(c.text for c in holdout))

    def test_write_manifest_needs_no_analyzer(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "c.yaml"
            corpus.write_text(
                'cases:\n  - id: a-1\n    text: "Herr Mueller kommt."\n    entities:\n'
                '      - {type: PERSON, value: "Mueller", expected_recall: must_detect}\n',
                encoding="utf-8",
            )
            target = cb.write_manifest(corpus)
            data = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(data["cases"], {"a-1": "dev"})


class ManifestTest(unittest.TestCase):
    def test_manifest_is_deterministic_and_complete(self):
        cases = cb.load_corpus(_CORPUS)
        m1 = cb.build_manifest(cases)
        m2 = cb.build_manifest(list(reversed(cases)))
        self.assertEqual(m1, m2)
        self.assertEqual(set(m1["cases"]), {c.case_id for c in cases})

    def test_checked_in_manifest_matches_corpus_both_ways(self):
        """A removed case fails; so does a new case nobody registered."""
        cases = cb.load_corpus(_CORPUS)
        checked_in = json.loads(_MANIFEST.read_text(encoding="utf-8"))
        have = cb.build_manifest(cases)["cases"]
        want = checked_in["cases"]
        self.assertEqual(
            sorted(set(want) - set(have)), [],
            "Cases vanished from the corpus. Removing a case must be a visible "
            "edit of corpus-manifest.json in the same commit.",
        )
        self.assertEqual(
            sorted(set(have) - set(want)), [],
            "New cases are not registered. Run: "
            "python3 test/corpus-benchmark.py --write-manifest",
        )
        moved = {k for k in want if want[k] != have[k]}
        self.assertEqual(sorted(moved), [], "Cases changed split (dev <-> holdout).")


class V1ContentPinTest(unittest.TestCase):
    """'v1 untouched' is a content claim, not a count claim (QA M2).

    The manifest pins a hash of text + entities for every v1 case. Editing a
    v1 case in place (same id, same count) turns this red.
    """

    def _mutated_cases(self, mutate):
        raw = yaml.safe_load(_CORPUS.read_text(encoding="utf-8"))
        for c in raw["cases"]:
            if c["id"] == "person-001-formal":
                mutate(c)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.yaml"
            path.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
            return cb.load_corpus(path)

    def _manifest(self):
        return json.loads(_MANIFEST.read_text(encoding="utf-8"))

    def test_checked_in_v1_cases_match_their_pinned_hash(self):
        cases = cb.load_corpus(_CORPUS)
        self.assertEqual(cb.v1_hash_mismatches(cases, self._manifest()), [])
        pinned = self._manifest()["v1_sha256"]
        self.assertEqual(len(pinned), 84)

    def test_mutating_v1_text_is_detected(self):
        def mutate(c):
            c["text"] = c["text"].replace("vielen Dank", "vielen herzlichen Dank")
        cases = self._mutated_cases(mutate)
        self.assertEqual(cb.v1_hash_mismatches(cases, self._manifest()), ["person-001-formal"])

    def test_mutating_v1_entity_is_detected(self):
        def mutate(c):
            c["entities"][0]["expected_recall"] = "known_gap"
        cases = self._mutated_cases(mutate)
        self.assertEqual(cb.v1_hash_mismatches(cases, self._manifest()), ["person-001-formal"])

    def test_removed_v1_case_is_detected(self):
        cases = [c for c in cb.load_corpus(_CORPUS) if c.case_id != "person-001-formal"]
        self.assertEqual(cb.v1_hash_mismatches(cases, self._manifest()), ["person-001-formal"])


class CorpusFloorsTest(unittest.TestCase):
    """Absolute floors from the DATENSCHLE-94 scope. Lowering one is a
    visible edit of this file, never a silent side effect of editing YAML."""

    @classmethod
    def setUpClass(cls):
        cls.raw = yaml.safe_load(_CORPUS.read_text(encoding="utf-8"))["cases"]
        cls.cases = cb.load_corpus(_CORPUS)
        cls.v2 = [c for c in cls.cases if c.category != "v1"]

    def _cat(self, *cats):
        return [c for c in self.v2 if c.category in cats]

    def test_total_case_floor(self):
        self.assertGreaterEqual(len(self.cases), 84 + 150 + 48)

    def test_v1_cases_are_untouched(self):
        v1 = [c for c in self.cases if c.category == "v1"]
        self.assertEqual(len(v1), 84)
        self.assertTrue(all(c.split == "dev" for c in v1))

    def test_at_least_150_new_positive_cases(self):
        pos = [c for c in self.v2 if not c.is_negative]
        self.assertGreaterEqual(len(pos), 150)

    def test_at_least_80_pii_free_negatives_overall(self):
        neg = [c for c in self.cases if c.is_negative]
        self.assertGreaterEqual(len(neg), 80)

    def test_holdout_floor(self):
        # Floors, not the exact current counts (QA L1): hold-out is 37 positive
        # / 30 negative / 67 total today. The floors keep a margin so that
        # swapping a case is possible, while a real shrink still fails.
        ho = [c for c in self.cases if c.split == "holdout"]
        self.assertGreaterEqual(len(ho), 60)
        self.assertGreaterEqual(len([c for c in ho if c.is_negative]), 26)
        self.assertGreaterEqual(len([c for c in ho if not c.is_negative]), 25)

    def test_holdout_is_never_v1(self):
        for c in self.cases:
            if c.split == "holdout":
                self.assertNotEqual(c.category, "v1")

    def test_category_floors(self):
        floors = {
            "nachname-wort": 20,
            "nachname-kopf": 12,
            "positiv-kontrolle": 15,
            "name-ohne-anrede": 12,
            "adresse-fliesstext": 15,
            "json-gemischt": 12,
            "quasi-identifier": 8,
            "titel-dateiname": 6,
            "negativ-satzanfang": 25,
            "negativ-schema": 8,
            "negativ-fliesstext": 10,
        }
        for cat, floor in floors.items():
            with self.subTest(cat=cat):
                self.assertGreaterEqual(len(self._cat(cat)), floor)

    def test_required_surnames_are_positives(self):
        values = {
            gt.value
            for c in self.v2
            for gt in c.ground_truth
            if gt.entity_type == "PERSON" and gt.expected_recall == "must_detect"
        }
        for needed in ("Menge", "Fuege", "Koch", "Bauer", "Erhart", "Lienhart"):
            with self.subTest(name=needed):
                self.assertIn(needed, values)

    def test_required_sentence_initial_words_are_negatives(self):
        text = " ".join(c.text for c in self._cat("negativ-satzanfang"))
        for needed in ("Fasse", "Uebersetze", "Übersetze", "Rueckruf", "Rückruf"):
            with self.subTest(word=needed):
                self.assertIn(needed, text)

    def test_negative_categories_are_really_negative(self):
        for c in self._cat("negativ-satzanfang", "negativ-schema", "negativ-fliesstext"):
            self.assertTrue(c.is_negative, c.case_id)

    def test_quasi_identifiers_are_reported_not_scored(self):
        combos = [
            gt
            for c in self._cat("quasi-identifier")
            for gt in c.ground_truth
            if gt.entity_type == "QUASI_IDENTIFIER_COMBO"
        ]
        self.assertGreaterEqual(len(combos), 8)
        self.assertTrue(all(g.expected_recall == "known_gap" for g in combos))

    def test_title_in_filename_cases_do_not_use_the_titel_id_prefix(self):
        """test_citation_doc_claims counts ids starting with 'titel-' (v1 gap)."""
        for c in self._cat("titel-dateiname"):
            self.assertFalse(c.case_id.startswith("titel-"), c.case_id)

    def test_mixed_german_json_key_cases_really_contain_json_keys(self):
        for c in self._cat("json-gemischt"):
            self.assertIn('"', c.text, c.case_id)
            self.assertIn(":", c.text, c.case_id)

    def test_multiline_cases_exist(self):
        multi = [c for c in self.v2 if "\n" in c.text]
        self.assertGreaterEqual(len(multi), 8)

    def test_controls_exist_and_carry_baseline_detected(self):
        controls = [c for c in self.v2 if c.control]
        self.assertGreaterEqual(len(controls), 15)
        for c in controls:
            for gt in c.ground_truth:
                if gt.expected_recall == "must_detect":
                    self.assertIsInstance(gt.baseline_detected, bool, c.case_id)


import re

# Name-bearing entity types (hold-out side AND dev side). Pure identifiers
# (IBAN, phone, dates, numbers, ...) are excluded: they carry no vocabulary.
_NAME_TYPES = ("PERSON", "LOCATION", "ORGANIZATION", "DE_FIRMA")
# On the dev side, the words of a QUASI_IDENTIFIER_COMBO span count too
# (v1 quasi-002 names 'Bamberg' only inside such a span).
_QUASI_TYPE = "QUASI_IDENTIFIER_COMBO"
# Legal forms are not vocabulary of a name.
_LEGAL_FORMS = frozenset(
    {"gmbh", "ag", "kg", "gbr", "ug", "mbh", "ohg", "kgaa", "se", "co", "ev", "e.v", "inc", "ltd", "llc"}
)

# Stem rule thresholds. Two tokens of length >= _STEM_MIN_LEN are variants of
# each other if one is a prefix of the other or they share a prefix of >=
# _SHARED_PREFIX characters (after folding umlauts: ae/oe/ue/ss). Catches
# Gebhardt/Gebhart, Sommer/Sommerfeld, Berg/Bergmann, Wittkopp/Witt.
_STEM_MIN_LEN = 4
_SHARED_PREFIX = 5

# Explicit, justified, test-checked exceptions: (hold-out token, dev token).
# An exception that no longer matches a real conflict fails the test, so the
# list cannot rot. Keep it small; prefer replacing the hold-out value.
_STEM_EXCEPTIONS: dict = {}


def _fold(tok):
    return (tok.casefold().replace("ä", "ae").replace("ö", "oe")
            .replace("ü", "ue").replace("ß", "ss"))


def _tokens_of(value, *, quasi=False):
    out = []
    for tok in re.split(r"[\s\-_/,&()]+", value):
        tok = tok.strip(".,;:()'\"")
        if not tok or any(ch.isdigit() for ch in tok):
            continue
        if quasi and not tok[0].isupper():
            continue  # inside a quasi span only capitalised words are names
        folded = _fold(tok)
        if folded in _LEGAL_FORMS:
            continue
        out.append(folded)
    return out


def _entity_tokens(cases, types=_NAME_TYPES, with_quasi=False):
    """folded token -> sorted case ids.

    Multi-word names are split on whitespace, hyphen and underscore, so
    'Freiburg im Breisgau' and 'Heinz-Dieter Brandt' contribute every part.
    Casefolded and umlaut-folded, so 'Koch' == 'koch' and 'Bürger' == 'Buerger'.
    """
    out = {}
    for c in cases:
        for gt in c.ground_truth:
            if gt.entity_type in types:
                toks = _tokens_of(gt.value)
            elif with_quasi and gt.entity_type == _QUASI_TYPE:
                toks = _tokens_of(gt.value, quasi=True)
            else:
                continue
            for tok in toks:
                out.setdefault(tok, set()).add(c.case_id)
    return {k: sorted(v) for k, v in out.items()}


def _variant(a, b):
    """True if tokens a and b are equal or stem variants (see thresholds)."""
    if a == b:
        return True
    if len(a) < _STEM_MIN_LEN or len(b) < _STEM_MIN_LEN:
        return False
    if a.startswith(b) or b.startswith(a):
        return True
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n >= _SHARED_PREFIX


def _holdout_conflicts(cases):
    """[(holdout token, dev token, holdout case ids, dev case ids), ...]"""
    dev = _entity_tokens([c for c in cases if c.split == "dev"], with_quasi=True)
    ho = _entity_tokens([c for c in cases if c.split == "holdout"])
    out = []
    for ht, hcases in sorted(ho.items()):
        for dt, dcases in sorted(dev.items()):
            if _variant(ht, dt):
                out.append((ht, dt, hcases, dcases))
    return out


class HoldoutDisjointTest(unittest.TestCase):
    """The hold-out is only a hold-out if it shares no name vocabulary with dev.

    Covers: every token of every PERSON / LOCATION / ORGANIZATION / DE_FIRMA
    entity in a hold-out case against every such entity in dev (v1 is dev)
    AND against the capitalised words inside dev QUASI_IDENTIFIER_COMBO spans
    (cross-type, so a surname vs a company name counts). Beyond exact equality
    a stem rule applies (tokens >= 4 chars: prefix of each other, or shared
    prefix >= 5 chars after umlaut folding). Not covered: pure identifiers
    (IBAN, phone, dates, numbers), legal-form tokens, and lower-case words;
    capitalised non-initial words in negative texts are shared with dev by
    design and are NOT checked.
    """

    def _case(self, cid, split, typ, value):
        gt = cb.GroundTruthEntity(cid, typ, value, "must_detect", 0, 1, 1)
        return cb.Case(cid, "t", [gt], split=split)

    def test_helper_splits_multiword_and_hyphenated_names(self):
        c = cb.Case("v2-x", "t", [
            cb.GroundTruthEntity("v2-x", "LOCATION", "Freiburg im Breisgau", "must_detect", 0, 1, 1),
            cb.GroundTruthEntity("v2-x", "PERSON", "Heinz-Dieter Brandt", "must_detect", 0, 1, 1),
            cb.GroundTruthEntity("v2-x", "DE_FIRMA", "Foo GmbH", "must_detect", 0, 1, 1),
            cb.GroundTruthEntity("v2-x", "IBAN_CODE", "DE02 1203", "must_detect", 0, 1, 1),
        ])
        toks = _entity_tokens([c])
        self.assertEqual(set(toks), {"freiburg", "im", "breisgau", "heinz", "dieter", "brandt", "foo"})

    def test_variant_rule(self):
        for a, b in (("gebhardt", "gebhart"), ("lindner", "lindner"), ("sommer", "sommerfeld"),
                     ("berg", "bergmann"), ("wittkopp", "witt"), ("buergerverein", "buergermeister"),
                     ("schwerin", "schweitzer")):
            with self.subTest(pair=(a, b)):
                self.assertTrue(_variant(a, b))
        for a, b in (("tag", "tagung"), ("anna", "annette"), ("ritter", "rotter"), ("jena", "gotha")):
            with self.subTest(pair=(a, b)):
                self.assertFalse(_variant(a, b))

    def test_blind_spots_are_closed(self):
        """Cross-type (PERSON vs DE_FIRMA), quasi-span words and stems are seen."""
        dev = [
            self._case("d1", "dev", "PERSON", "Torsten Lindner"),
            self._case("d2", "dev", "PERSON", "Leonie Gebhart"),
            cb.Case("d3", "t", [cb.GroundTruthEntity(
                "d3", "QUASI_IDENTIFIER_COMBO", "Leiterin der Qualitaet bei Zulieferern in Bamberg",
                "known_gap", 0, 1, 1)], split="dev"),
        ]
        ho = [
            self._case("h1", "holdout", "DE_FIRMA", "Lindner Elektrotechnik GmbH"),
            self._case("h2", "holdout", "LOCATION", "Bamberg"),
            self._case("h3", "holdout", "PERSON", "Gebhardt"),
            self._case("h4", "holdout", "PERSON", "Ritter"),
        ]
        found = {(h, d) for h, d, _a, _b in _holdout_conflicts(dev + ho)}
        self.assertEqual(found, {("lindner", "lindner"), ("bamberg", "bamberg"),
                                 ("gebhardt", "gebhart")})

    def test_holdout_does_not_share_name_vocabulary_with_dev(self):
        cases = cb.load_corpus(_CORPUS)
        found = {(h, d): (a, b) for h, d, a, b in _holdout_conflicts(cases)
                 if (h, d) not in _STEM_EXCEPTIONS}
        self.assertEqual(found, {}, "hold-out shares name vocabulary with dev: %r" % found)

    def test_exceptions_are_real_and_justified(self):
        cases = cb.load_corpus(_CORPUS)
        actual = {(h, d) for h, d, _a, _b in _holdout_conflicts(cases)}
        for pair, why in _STEM_EXCEPTIONS.items():
            self.assertIn(pair, actual, "stale exception %r" % (pair,))
            self.assertGreaterEqual(len(why), 30, "exception %r needs a justification" % (pair,))
        self.assertLessEqual(len(_STEM_EXCEPTIONS), 3)


class AnnotationRulesDocumentedTest(unittest.TestCase):
    def test_corpus_header_states_rules_a1_to_a6(self):
        header = _CORPUS.read_text(encoding="utf-8").split("\ncases:", 1)[0]
        for rule in ("A1", "A2", "A3", "A4", "A5", "A6"):
            with self.subTest(rule=rule):
                self.assertIn(rule, header)
        self.assertIn("hold-out", header.lower())

    def test_readme_documents_split_manifest_and_rules(self):
        readme = (_ROOT / "test" / "corpus" / "README.md").read_text(encoding="utf-8")
        for token in ("A1", "A6", "holdout", "corpus-manifest.json", "--split"):
            with self.subTest(token=token):
                self.assertIn(token, readme)


if __name__ == "__main__":
    unittest.main()
