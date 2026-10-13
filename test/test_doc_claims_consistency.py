"""Repo-wide guard against drifting CVE claims (DATENSCHLE-83 / -89).

Structure principle: the CVE numbers and the "6 instead of 32" calculation
live ONLY in docs/adr/0003-image-cve-gate.md, explicitly as an upstream
calculation (the built image is not scanned). Everywhere else the repo
refers to ADR-0003 instead of repeating numbers, and nobody claims the CI
gate is satisfiable by DATENSCHLE-83 alone.
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
ADR = "docs/adr/0003-image-cve-gate.md"
SELF = {pathlib.Path(__file__).name, "test_compose_image_profile.py",
        "test_supply_chain_consistency.py"}  # these parse/quote the ADR table itself


def _files():
    out = []
    for pattern in ("docs/**/*.md", ".github/**/*.yml", ".github/**/*.yaml",
                    "presidio/*", "test/*.py"):
        out.extend(ROOT.glob(pattern))
    out.extend([ROOT / "docker-compose.yml", ROOT / "README.md", ROOT / "CONTEXT.md"])
    return [f for f in sorted(set(out)) if f.is_file() and f.name not in SELF]


def _flat(path):
    """Text with comment markers and line breaks flattened, so a claim that
    wraps over several lines is still one claim."""
    lines = [l.strip().lstrip("#").strip() for l in path.read_text(encoding="utf-8").splitlines()]
    return " ".join(" ".join(lines).split())


def _rel(f):
    return f.relative_to(ROOT).as_posix()


class TestCveClaimsConsistency(unittest.TestCase):
    def test_no_unqualified_32_claim(self):
        pat = re.compile(r"statt\s+(?:mit\s+)?32")
        for f in _files():
            flat = _flat(f)
            for m in pat.finditer(flat):
                ctx = flat[max(0, m.start() - 150): m.end() + 150]
                self.assertIn("Upstream-Rechnung", ctx,
                              f"{_rel(f)}: unqualified '{m.group(0)}'")

    def test_gate_satisfiable_claims_name_anonymizer_and_postgres(self):
        pat = re.compile(r"(?<!un)erf(?:ue|ü)llbar", re.I)
        for f in _files():
            flat = _flat(f)
            for m in pat.finditer(flat):
                # The qualifier must stand in the SAME sentence as the claim.
                start = max(flat.rfind(". ", 0, m.start()), flat.rfind(": ", 0, m.start())) + 1
                ends = [e for e in (flat.find(". ", m.end()), len(flat)) if e != -1]
                sentence = flat[start: min(ends)]
                self.assertTrue("Anonymizer" in sentence and "Postgres" in sentence,
                                f"{_rel(f)}: 'erfuellbar' without Anonymizer/Postgres in same sentence: {sentence!r}")

    def test_no_shipped_stack_claim_next_to_finding_numbers(self):
        pat = re.compile(r"ausgelieferten\s+(?:Standard-)?Stacks?\b")
        nums = re.compile(r"\b(?:32|61|4346|3847)\b|\b6 statt\b")
        for f in _files():
            flat = _flat(f)
            for m in pat.finditer(flat):
                ctx = flat[m.start(): m.end() + 300]
                self.assertIsNone(nums.search(ctx),
                                  f"{_rel(f)}: finding numbers scoped to the shipped stack")

    RAW = re.compile(
        r"\b(?:4346|3847)\b|\b42 der 61\b|\b32\s*(?:→|−|->)\s*\d|statt\s+(?:mit\s+)?32"
        r"|\b(?:5|21)\s*(?:->|→)\s*0\b|\b62\s*(?:-|–|%?\s*bis)\s*76\b"
        r"|\|\s*\*\*Summe\*\*|\|\s*(?:Analyzer|Anonymizer|Image-Redactor)\s+(?:vorher|\*\*nachher\*\*)"
        r"|\|\s*`(?:litellm|postgres|presidio-[a-z-]+):[^|]*`\s*\|\s*\*{0,2}\d+\*{0,2}\s*\|\s*\*{0,2}\d+"
    )

    def test_cve_numbers_and_raw_tables_only_in_adr(self):
        # STRICT (Oliver): raw measurement numbers/tables live only in ADR-0003.
        for f in _files():
            if _rel(f) == ADR:
                continue
            flat = _flat(f)
            raw = "\n".join(l.strip() for l in f.read_text(encoding="utf-8").splitlines())
            for text in (flat, raw):
                m = self.RAW.search(text)
                self.assertIsNone(m, f"{_rel(f)}: raw CVE number/table outside ADR-0003: {m and m.group(0)!r}")

    def test_supply_chain_and_image_scan_refer_to_adr(self):
        for rel in ("docs/foundation/supply-chain.md", ".github/workflows/image-scan.yml"):
            self.assertIn("ADR-0003", _flat(ROOT / rel), rel)

    def test_adr_states_numbers_are_upstream_calculation(self):
        flat = _flat(ROOT / ADR)
        self.assertIn("Upstream-Rechnung", flat)
        self.assertIn("nicht gescannt", flat)


if __name__ == "__main__":
    unittest.main()
