"""Doc guards for the stopword wiring claims (DATENSCHLE-82 / -88, QA F4).

1. The README measurement table must agree with the checked-in
   ``test/corpus/benchmark-results.json`` (a changed README number turns the
   test red; so does a changed artifact).
2. Repo documentation must not claim that the allow_list / stopword list is
   unwired, undelivered or not sent by the guardrail: the guardrail sends it.

LIMIT (documented): the phrase sweep is a regex heuristic over flattened text
within a context window around list/guardrail words. Paraphrases outside the
patterns are not detected. ISA.md (archive) and test files are excluded.
"""
import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS = ROOT / "test" / "corpus" / "benchmark-results.json"


def _de(value):
    """12.5 -> '12,5'; 100.0 -> '100'."""
    text = f"{value:.1f}".replace(".", ",")
    return text[:-2] if text.endswith(",0") else text


class TestReadmeTableMatchesResultsArtifact(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = json.loads(RESULTS.read_text(encoding="utf-8"))
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.rows = {}
        for line in cls.readme.splitlines():
            if line.startswith("| Recall") or line.startswith("| Precision") or line.startswith("| Störquote"):
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                cls.rows[cells[0].split()[0]] = cells

    def _last_cell(self, key):
        self.assertIn(key, self.rows, f"README table row {key!r} not found")
        return self.rows[key][-1]

    def test_artifact_is_the_run_with_the_list(self):
        self.assertEqual(self.results["stopwords_path"], "presidio/de-stopwords.yml")

    def test_recall_matches(self):
        want = _de(self.results["must_detect"]["overall"]["recall"] * 100)
        self.assertIn(f"{want} %", self._last_cell("Recall"))

    def test_precision_matches(self):
        want = _de(self.results["must_detect"]["overall"]["precision"] * 100)
        self.assertIn(f"{want} %", self._last_cell("Precision"))

    def test_stoerquote_matches(self):
        neg = self.results["negative_cases"]
        cell = self._last_cell("Störquote")
        self.assertIn(f"{_de(neg['stoerquote'] * 100)} %", cell)
        self.assertIn(f"{neg['cases_with_false_positive']} von {neg['count']}", cell)

    def test_pflicht_entities_count_matches(self):
        overall = self.results["must_detect"]["overall"]
        self.assertIn(f"{overall['tp']} von {overall['support']} Pflicht-Entitäten", self.readme)

    def test_case_count_matches(self):
        self.assertIn(f"({self.results['case_count']} Fälle", self.readme)


# ------------------------------------------------------------------ phrases
_NEGATIVE = re.compile(
    r"(?:noch\s+)?nicht\s+(?:verdrahtet|ausgeliefert|angeschlossen)"
    r"|sendet\s+(?:\S+\s+){0,6}?noch\s+nicht"
    r"|noch\s+nicht\s+(?:an\s+presidio\s+)?(?:mit)?gesendet"
    r"|nicht\s+an\s+presidio\s+(?:mit)?gesendet"
    r"|noch\s+nicht\s+umgesetzt"
    r"|spezifikation,\s+nicht\s+umgesetzt"
    r"|erreichbare[nr]?,?\s+nicht\s+(?:den\s+)?ausgelieferte",
    re.I,
)
_CONTEXT = re.compile(r"wortliste|allow_list|stopword|stoppwort|de-stopwords|guardrail", re.I)
_WINDOW = 160


def _flat(text):
    lines = [l.strip().lstrip("#").strip() for l in text.splitlines()]
    return " ".join(" ".join(lines).split())


def _violations(flat):
    out = []
    for m in _NEGATIVE.finditer(flat):
        ctx = flat[max(0, m.start() - _WINDOW): m.end() + _WINDOW]
        if _CONTEXT.search(ctx):
            out.append(m.group(0))
    return out


def _doc_files():
    files = []
    for pattern in ("docs/**/*.md", "test/corpus/*.md", "presidio/*.yml", "presidio/*.yaml"):
        files.extend(ROOT.glob(pattern))
    for name in ("README.md", "CONTEXT.md", "KONZEPT.md", "PROJEKT-STATUS.md",
                 "COMMUNITY-POSTS.md", "docker-compose.yml", ".env.example"):
        files.append(ROOT / name)
    files.append(ROOT / "deploy" / "coolify" / "docker-compose.yaml")
    return [f for f in sorted(set(files)) if f.is_file()]  # ISA.md deliberately absent


class TestNoStaleUnwiredClaims(unittest.TestCase):
    def test_docs_do_not_claim_the_list_is_unwired(self):
        for f in _doc_files():
            hits = _violations(_flat(f.read_text(encoding="utf-8")))
            self.assertEqual(
                hits, [],
                f"{f.relative_to(ROOT)}: stale claim about the stopword list / allow_list: {hits}",
            )

    def test_detector_catches_the_qa_mutation(self):
        mutation = ("Offen: Der Guardrail sendet die allow_list noch nicht, "
                    "die Liste ist nicht ausgeliefert.")
        self.assertTrue(_violations(mutation))

    def test_detector_catches_known_old_phrasings(self):
        for text in (
            "mit Wortliste — noch nicht verdrahtet",
            "Nur sendet der Guardrail sie nicht an Presidio — im Proxy ist sie nicht angeschlossen.",
            "Spezifikation, nicht umgesetzt: die Wortliste des Guardrails",
            "sie beschreiben den erreichbaren, nicht den ausgelieferten Zustand der Wortliste",
            "Der Guardrail sendet die Liste noch nicht (§7).",
        ):
            with self.subTest(text=text):
                self.assertTrue(_violations(text))

    def test_detector_does_not_flag_unrelated_or_correct_text(self):
        for text in (
            "Die Bash-Suite ist lauffaehig, aber noch nicht verdrahtet.",
            "Der Guardrail sendet die Liste an jeden Presidio-Aufruf.",
            "Ein echter Docker-Build wurde nicht ausgefuehrt.",
        ):
            with self.subTest(text=text):
                self.assertEqual(_violations(text), [])


if __name__ == "__main__":
    unittest.main()
