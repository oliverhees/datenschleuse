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


def _paragraph_with(text, needle):
    """The blank-line separated paragraph that contains `needle`."""
    for para in re.split(r"\n\s*\n", text):
        if needle in para:
            return para
    raise AssertionError(f"{needle!r} not found")


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
        para = _paragraph_with(_read("docs/foundation/security-baseline.md"), EXAMPLE)
        flat = " ".join(para.split())
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

    def test_readme_does_not_claim_path_independence(self):
        readme = " ".join(_read("README.md").split())
        self.assertNotIn("unabhängig davon greift, welchen Weg", readme)


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
