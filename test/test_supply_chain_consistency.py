"""Consistency guard between Dockerfile comment, ADR-0003, supply-chain.md and
the compose/test comments (DATENSCHLE-89).

Three things must never drift apart again:
  1. every verbatim quote of the Dockerfile comment in the docs really is in
     presidio/Dockerfile.analyzer,
  2. the CVE-ID set listed in the Dockerfile comment equals the one in ADR-0003
     (and supply-chain.md),
  3. the total finding count is the same everywhere (and equals the table sum).
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CVE_RE = re.compile(r"CVE-\d{4}-\d+")


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def _norm(text):
    text = re.sub(r"^\s*#", " ", text, flags=re.M)
    return re.sub(r"\s+", " ", text).strip()


def _dockerfile_comment():
    return "\n".join(
        l for l in _read("presidio/Dockerfile.analyzer").splitlines()
        if l.lstrip().startswith("#")
    )


def _quotes_of_dockerfile_comment(doc):
    """Quotes („...") in paragraphs that talk about the Dockerfile comment."""
    found = []
    for para in re.split(r"\n\s*\n", _read(doc)):
        flat = re.sub(r"\s+", " ", para)
        if "Dockerfile.analyzer" in flat and "Kommentar" in flat:
            found.extend(re.findall(r"„([^“”\"]+)[“”\"]", flat))
    return found


def _package_block_cves(doc):
    ids = set()
    for line in _read(doc).splitlines():
        if re.match(r"^(libgnutls30t64|libssl3t64|openssl)\s", line):
            ids.update(CVE_RE.findall(line))
    return ids


def _table_total(doc):
    """Returns (stated total of the Summe row, recomputed row sum)."""
    rows, summe = [], None
    for line in _read(doc).splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.startswith("| **Summe**"):
            summe = int(re.sub(r"\D", "", cells[-1]))
        elif re.match(r"^\| `(litellm|postgres|presidio-[a-z-]+):", line):
            rows.append(int(re.sub(r"\D", "", cells[-1].split("(")[0])))
    return summe, sum(rows)


class TestDockerfileQuotesAreReal(unittest.TestCase):
    def test_quotes_in_docs_appear_verbatim_in_dockerfile(self):
        comment = _norm(_dockerfile_comment())
        for doc in ("docs/adr/0003-image-cve-gate.md", "docs/foundation/supply-chain.md"):
            quotes = _quotes_of_dockerfile_comment(doc)
            self.assertTrue(quotes, f"{doc}: expected at least one verbatim quote")
            for q in quotes:
                self.assertIn(_norm(q), comment, f"{doc}: not in Dockerfile: {q!r}")


class TestCveIdsConsistent(unittest.TestCase):
    def test_dockerfile_cve_set_equals_adr(self):
        docker_ids = set(CVE_RE.findall(_dockerfile_comment()))
        adr_ids = _package_block_cves("docs/adr/0003-image-cve-gate.md")
        self.assertTrue(adr_ids)
        self.assertEqual(docker_ids, adr_ids)

    def test_supply_chain_cve_set_equals_adr(self):
        self.assertEqual(
            _package_block_cves("docs/foundation/supply-chain.md"),
            _package_block_cves("docs/adr/0003-image-cve-gate.md"),
        )


class TestTotalFindingCountConsistent(unittest.TestCase):
    def test_tables_sum_matches_stated_total(self):
        totals = set()
        for doc in ("docs/adr/0003-image-cve-gate.md", "docs/foundation/supply-chain.md"):
            stated, computed = _table_total(doc)
            self.assertEqual(stated, computed, doc)
            totals.add(stated)
        self.assertEqual(len(totals), 1)

    def test_compose_and_test_docstring_use_table_total(self):
        stated, _ = _table_total("docs/adr/0003-image-cve-gate.md")
        for rel in ("docker-compose.yml", "test/test_image_policy.py"):
            flat = re.sub(r"[\s#]+", " ", _read(rel))
            m = re.search(r"der (?:rund )?(\d{4}) Gesamtbefunde", flat)
            self.assertIsNotNone(m, rel)
            self.assertEqual(int(m.group(1)), stated, rel)


if __name__ == "__main__":
    unittest.main()
