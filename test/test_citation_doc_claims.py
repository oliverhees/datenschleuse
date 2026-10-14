"""Doc guards for the citations / verification claims (DATENSCHLE-65, round 2).

Each test pins one correction from the Security/QA audit so the overclaim
cannot return silently:

* Sec-L1  A document title in file-name form (``Arztbrief_Mustermann.pdf``)
          is NOT reliably recognised by the analyzer. The field goes through
          the masker (path), but recognition is a pragmatic heuristic (gap in
          recognition, not in the path). Docs and code comment must say so.
* Sec-I3  The verification pass runs only on ``tool_calls[].function.arguments``
          (not on text parts or citations). CONTEXT.md/README must not claim
          it applies "regardless of path".
* Sec-I5  ``cited_text`` is masked, not "passed through / not let through".
* Sec-L2  ADR-0005 covers exactly ``str``; container subclasses are a scope
          limit that must be stated.
* Corpus  The gap is held in the test corpus as ``known_gap`` so it cannot
          disappear silently (recall there is reported, not a target).

They read files only; no analyzer needed.
"""

import json
import pathlib
import re
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def _comment_block_with(text, needle):
    """The run of consecutive '#' comment lines that contains `needle`."""
    lines = text.splitlines()
    idx = next(i for i, ln in enumerate(lines) if needle in ln)
    lo = idx
    while lo > 0 and lines[lo - 1].lstrip().startswith("#"):
        lo -= 1
    hi = idx
    while hi + 1 < len(lines) and lines[hi + 1].lstrip().startswith("#"):
        hi += 1
    return "\n".join(lines[lo:hi + 1])


EXAMPLE = "Arztbrief_Mustermann.pdf"


class TitleFilenameLimitTest(unittest.TestCase):
    def test_security_baseline_states_the_limit(self):
        # The example's paragraph plus the one right after it (the limit).
        paras = re.split(r"\n\s*\n", _read("docs/foundation/security-baseline.md"))
        i = next(k for k, p in enumerate(paras) if EXAMPLE in p)
        flat = " ".join(" ".join(paras[i:i + 2]).split())
        self.assertIn("nicht zuverlässig", flat)
        self.assertIn("Erkennungslücke", flat)
        self.assertIn("Heuristik", flat)

    def test_guardrail_comment_states_the_limit(self):
        block = _comment_block_with(
            _read("litellm/datenschleuse_guardrail.py"), EXAMPLE)
        flat = " ".join(re.sub(r"^\s*#\s?", "", ln) for ln in block.splitlines())
        flat = " ".join(flat.split())
        self.assertIn("nicht zuverlaessig", flat)
        self.assertIn("Erkennungsluecke", flat)
        self.assertIn("Heuristik", flat)


    def test_limit_is_stated_as_measurement_not_as_rule(self):
        # Round 3 (Sec-I-1/QA-Info-1): "Unterstrich-/Punkt-getrennt" was too
        # sharp -- a space-separated title was among the misses and
        # "Max.Mustermann.pdf" WAS recognised. State what was measured
        # (titles with a file extension), not a separator rule.
        paras = re.split(r"\n\s*\n", _read("docs/foundation/security-baseline.md"))
        i = next(k for k, p in enumerate(paras) if EXAMPLE in p)
        flat = " ".join(" ".join(paras[i:i + 2]).split())
        self.assertNotIn("Unterstrich- oder Punkt-getrennt", flat)
        self.assertIn("Dateiendung", flat)
        self.assertIn("nicht vorhersagbar", flat)

    def test_guardrail_comment_states_measurement_not_rule(self):
        block = _comment_block_with(
            _read("litellm/datenschleuse_guardrail.py"), EXAMPLE)
        flat = " ".join(re.sub(r"^\s*#\s?", "", ln) for ln in block.splitlines())
        flat = " ".join(flat.split())
        self.assertNotIn("Unterstrich/Punkt-getrennt", flat)
        self.assertIn("Dateiendung", flat)
        self.assertIn("nicht vorhersagbar", flat)


class OperatorSectionTitleGapTest(unittest.TestCase):
    """Sec-L1 round 3: the operator list in README must name the title gap."""

    NUMBER_WORDS = {"Zwei": 2, "Drei": 3, "Vier": 4, "Fünf": 5, "Sechs": 6}

    def _section(self):
        text = _read("README.md")
        m = re.search(r"^(\w+) Dinge, die du als Betreiber kennen musst:\s*$",
                      text, re.M)
        self.assertIsNotNone(m, "operator list heading not found")
        rest = text[m.end():]
        end = re.search(r"^#{1,3} ", rest, re.M)
        return m.group(1), (rest[:end.start()] if end else rest)

    def test_title_gap_is_named_in_the_operator_section(self):
        _, body = self._section()
        flat = " ".join(body.split())
        self.assertIn("Dokumenttitel", flat)
        self.assertIn("nicht zuverlässig", flat)
        self.assertIn("Erkennungslücke", flat)

    def test_operator_section_links_the_baseline_limit(self):
        _, body = self._section()
        self.assertIn("docs/foundation/security-baseline.md", body)
        self.assertTrue((ROOT / "docs/foundation/security-baseline.md").is_file())
        self.assertIn("Grenze (Security-Audit Sec-L1)",
                      _read("docs/foundation/security-baseline.md"))

    def test_count_word_matches_number_of_bullets(self):
        word, body = self._section()
        bullets = re.findall(r"^- \*\*", body, re.M)
        self.assertIn(word, self.NUMBER_WORDS)
        self.assertEqual(self.NUMBER_WORDS[word], len(bullets))

    def test_no_readme_passage_suggests_title_protection(self):
        # "maskiert wie jeder andere Text" next to Dokumenttitel promises
        # protection the analyzer cannot guarantee for file-name-form titles.
        readme = " ".join(_read("README.md").split())
        for m in re.finditer(r"Dokumenttitel", readme):
            window = readme[max(0, m.start() - 200): m.end() + 400]
            self.assertTrue(
                "nicht zuverlässig" in window or "Erkennungslücke" in window
                or "Heuristik" in window,
                window)


class CorpusKeepsTheGapTest(unittest.TestCase):
    def _gap_cases(self):
        corpus = yaml.safe_load(_read("test/corpus/de-pii-testkorpus.yaml"))
        return [
            c for c in corpus["cases"]
            if c["id"].startswith("titel-")
            and c["entities"]
            and all(e["expected_recall"] == "known_gap" for e in c["entities"])
        ]

    def test_two_filename_title_cases_are_known_gap(self):
        cases = self._gap_cases()
        self.assertEqual(len(cases), 2)
        texts = " ".join(c["text"] for c in cases)
        self.assertIn(EXAMPLE, texts)
        self.assertIn("Arztbrief Max Mustermann.pdf", texts)

    def test_benchmark_results_report_the_gap(self):
        results = json.loads(_read("test/corpus/benchmark-results.json"))
        reported = {d["case_id"] for d in results["known_gap"]["detail"]}
        cases = self._gap_cases()
        self.assertEqual(len(cases), 2)  # no vacuous pass
        for case in cases:
            self.assertIn(case["id"], reported)


class VerificationScopeTest(unittest.TestCase):
    def test_context_row_names_the_arguments_scope(self):
        row = next(ln for ln in _read("CONTEXT.md").splitlines()
                   if ln.startswith("| **Verifikationsdurchlauf**"))
        self.assertIn("arguments", row)
        self.assertNotIn("unabhängig davon, welchen Pfad", row)

    def test_context_row_names_both_fields(self):
        row = next(ln for ln in _read("CONTEXT.md").splitlines()
                   if ln.startswith("| **Verifikationsdurchlauf**"))
        self.assertIn("function_call.arguments", row)
        self.assertNotIn("ausschließlich auf `tool_calls[].function.arguments`", row)

    def test_readme_names_both_fields_for_the_verification(self):
        readme = " ".join(_read("README.md").split())
        i = readme.index("Diese Nachprüfung gilt")
        self.assertIn("function_call.arguments", readme[i:i + 300])

    def test_baseline_verification_section_names_what_is_not_covered(self):
        text = _read("docs/foundation/security-baseline.md")
        i = text.index("**Verifikationsdurchlauf auf dem Ergebnis.**")
        j = text.index("\n- **", i + 5)
        flat = " ".join(text[i:j].split())
        self.assertTrue("Text-Parts" in flat or "Zitat" in flat, flat)
        self.assertIn("function_call.arguments", flat)

    def test_readme_does_not_claim_path_independence(self):
        readme = " ".join(_read("README.md").split())
        self.assertNotIn("unabhängig davon greift, welchen Weg", readme)


class MeasurementStateDatedTest(unittest.TestCase):
    def test_82_case_table_is_dated_before_ds65(self):
        flat = " ".join(_read("docs/foundation/erkennungsziel.md").split())
        i = flat.index("Messung nach Erweiterung des Korpus")
        window = flat[i:i + 1800]
        self.assertIn("DATENSCHLE-65", window)
        self.assertIn("84 Fälle", window)
        self.assertIn("known_gap", window)

    def test_claim_matches_benchmark_results(self):
        # The checked-in artifact is the v2 run (DATENSCHLE-94). The dated
        # claim is about the 84 v1 cases, which the artifact reports as the
        # category "v1" -- so the claim stays verifiable, not just quoted.
        r = json.loads(_read("test/corpus/benchmark-results.json"))
        v1 = r["by_category"]["v1"]
        self.assertEqual(v1["cases"], 84)
        self.assertEqual(v1["tp"], 54)
        self.assertEqual(v1["fn"], 0)
        v1_gap = [d for d in r["known_gap"]["detail"]
                  if not d["case_id"].startswith("v2-")]
        self.assertEqual(len(v1_gap), 4)


class TestDocstringTest(unittest.TestCase):
    def test_cited_text_is_described_as_masked(self):
        text = _read("test/test_content_part_citations.py")
        doc = text.split('"""', 2)[1]
        self.assertNotIn("nicht durchgelassen", doc)
        self.assertIn("maskiert", " ".join(doc.split()))


class AdrScopeTest(unittest.TestCase):
    def test_adr_0005_states_container_scope(self):
        text = " ".join(_read(
            "docs/adr/0005-exakter-str-typ-an-registergrenzen.md").split())
        self.assertIn("Container-Subklassen", text)
        self.assertIn("in-process", text)
        self.assertIn("Folge-Item", text)


if __name__ == "__main__":
    unittest.main()
