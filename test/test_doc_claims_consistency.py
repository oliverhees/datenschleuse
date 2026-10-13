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
SELF = {pathlib.Path(__file__).name, "test_compose_image_profile.py"}


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
        pat = re.compile(r"(?<!un)erf[uü]llbar", re.I)
        for f in _files():
            flat = _flat(f)
            for m in pat.finditer(flat):
                ctx = flat[max(0, m.start() - 400): m.end() + 400]
                self.assertTrue("Anonymizer" in ctx and "Postgres" in ctx,
                                f"{_rel(f)}: 'erfuellbar' without Anonymizer/Postgres: ...{ctx[300:520]}...")

    def test_no_shipped_stack_claim_next_to_finding_numbers(self):
        pat = re.compile(r"ausgelieferten\s+(?:Standard-)?Stacks?\b")
        nums = re.compile(r"\b(?:32|61|4346|3847)\b|\b6 statt\b")
        for f in _files():
            flat = _flat(f)
            for m in pat.finditer(flat):
                ctx = flat[m.start(): m.end() + 300]
                self.assertIsNone(nums.search(ctx),
                                  f"{_rel(f)}: finding numbers scoped to the shipped stack")

    def test_cve_numbers_outside_adr_only_with_adr_reference(self):
        pat = re.compile(r"\b(?:4346|3847)\b|\b42 der 61\b|\b32\s*(?:→|−|->)\s*\d|statt\s+(?:mit\s+)?32")
        for f in _files():
            if _rel(f) == ADR:
                continue
            flat = _flat(f)
            for m in pat.finditer(flat):
                ctx = flat[max(0, m.start() - 600): m.end() + 600]
                self.assertTrue("ADR-0003" in ctx or "0003-image-cve-gate" in ctx,
                                f"{_rel(f)}: number '{m.group(0)}' without reference to ADR-0003")

    def test_adr_states_numbers_are_upstream_calculation(self):
        flat = _flat(ROOT / ADR)
        self.assertIn("Upstream-Rechnung", flat)
        self.assertIn("nicht gescannt", flat)


if __name__ == "__main__":
    unittest.main()
