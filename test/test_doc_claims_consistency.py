"""Repo-wide guard against drifting CVE claims (DATENSCHLE-83 / -89).

LIMIT OF THE SWEEP (known, documented): it is a heuristic over digit counts
next to severity words, "N of M" phrases, percent ranges / number arrows near
finding words, and long digit runs (CI run/job IDs). Number WORDS ("zweiunddreissig"),
abbreviations such as "crit", and phrasings outside those patterns are NOT
detected. ISA.md (archive) is excluded on purpose.

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
    # ISA.md stays out on purpose (historical archive).
    out.extend([ROOT / n for n in ("docker-compose.yml", "README.md", "CONTEXT.md",
                                   "KONZEPT.md", "PROJEKT-STATUS.md")])
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

    ADR_PATH_RE = re.compile(r"docs/adr/[\w.-]+\.md")

    def _check_adr_refs(self, label, text):
        self.assertIn("ADR-0003", text, label)
        self.assertIn(ADR, text, f"{label}: must reference the path {ADR}")
        self.assertTrue((ROOT / ADR).is_file())
        for path in self.ADR_PATH_RE.findall(text):
            self.assertTrue((ROOT / path).is_file(), f"{label}: references non-existent {path}")

    def test_supply_chain_and_image_scan_refer_to_adr(self):
        self._check_adr_refs("image-scan.yml", _flat(ROOT / ".github/workflows/image-scan.yml"))
        text = (ROOT / "docs/foundation/supply-chain.md").read_text(encoding="utf-8")
        start = text.index("### Der Presidio-Altbestand")
        m = re.search(r"\n### (?!#)", text[start + 5:])
        section = text[start: start + 5 + m.start()] if m else text[start:]
        self._check_adr_refs("section 'Der Presidio-Altbestand'", " ".join(section.split()))

    def test_relative_references_point_the_right_way(self):
        text = (ROOT / "docs/foundation/supply-chain.md").read_text(encoding="utf-8")
        block = text.index("libgnutls30t64  CVE-")
        refs = list(re.finditer(r"CVE-ID-Codeblock\s+weiter\s+(oben|unten)", text))
        self.assertTrue(refs, "expected the reference to the CVE-ID code block")
        for m in refs:
            expected = "oben" if block < m.start() else "unten"
            self.assertEqual(m.group(1), expected, "reference direction does not match block position")

    def test_dockerfile_comment_quote_does_not_wrap_mid_quote(self):
        text = (ROOT / "docs/foundation/supply-chain.md").read_text(encoding="utf-8")
        self.assertIn("„gebaute Image wird derzeit NICHT in der CI gescannt\"", text)

    def test_old_pin_claim_has_no_unbacked_green_statement(self):
        sc = " ".join((ROOT / "docs/foundation/supply-chain.md").read_text(encoding="utf-8").split())
        self.assertNotIn("und er lief grün", sc)
        adr = " ".join((ROOT / ADR).read_text(encoding="utf-8").split())
        self.assertIn("a9c7b0f0", adr)
        self.assertNotIn("früheren Lauf", adr)

    # --- generalized sweep (DATENSCHLE-89, QA-F1): the CLASS of error ----------
    # Any CVE measurement (counts next to severity words, "N of M", percent
    # ranges, number arrows) and any CI run/job ID outside ADR-0003 is a
    # violation. Audit finding IDs (MEDIUM-4, HIGH-2), versions, ports, digests,
    # dates and UIDs must NOT trigger.
    _NOT = r"(?:(?!Schritt|DATENSCHLE|Audit|exit-code|Gesetz)\D)"
    SWEEP = {
        "count before severity word": re.compile(
            r"(?<![-\w.])\d+\s*(?:behebbar\w*|CRITICAL\w*|HIGH\b|MEDIUM\b|Befund\w*|kritisch\w*)(?!-\d)", re.I),
        "severity word before count": re.compile(
            r"\b(?:CRITICAL|HIGH|MEDIUM|behebbar\w*)\b(?!-\d)" + _NOT + r"{0,40}?(?<![-\w.])\d{1,6}(?![\w.-])", re.I),
        "N of M": re.compile(
            r"\b\d+\s+(?:der|von)\s+\d+\s+(?:kritischen|CRITICAL|Gesamtbefunde\w*|Befunden)", re.I),
        "CI run/job id": re.compile(r"\b\d{9,}\b"),
    }
    CONTEXT_SWEEP = {
        "percent range near findings": (
            re.compile(r"\d+\s*(?:-|–|bis)\s*\d+\s*%"), re.compile(r"Befund|CRITICAL|CVE|behebbar", re.I)),
        "number arrow near findings": (
            re.compile(r"(?<![\w.])\d+\s*(?:->|→)\s*\d+(?![\w.])"), re.compile(r"Befund|CRITICAL|CVE|behebbar", re.I)),
    }

    # Rhetorical example in ADR-0004 (client wording), not a measurement.
    ALLOWED_PHRASES = ("nicht *5 Critical Findings*",)

    def _sweep_findings(self, name, text):
        out = []
        for phrase in self.ALLOWED_PHRASES:
            text = text.replace(phrase, " ")
        for label, pat in self.SWEEP.items():
            for m in pat.finditer(text):
                out.append(f"{name}: {label}: {m.group(0)!r}")
        for label, (pat, ctxpat) in self.CONTEXT_SWEEP.items():
            for m in pat.finditer(text):
                if ctxpat.search(text[max(0, m.start() - 80): m.end() + 80]):
                    out.append(f"{name}: {label}: {m.group(0)!r}")
        return out

    def test_generalized_sweep_no_cve_measurements_or_run_ids_outside_adr(self):
        findings = []
        for f in _files():
            if _rel(f) == ADR or f.parent.name == "test":
                continue
            findings += self._sweep_findings(_rel(f), _flat(f))
        self.assertEqual(findings, [], "CVE measurements/run IDs outside ADR-0003:\n" + "\n".join(findings))

    def test_sweep_has_no_false_positives_on_legit_data(self):
        legit = (
            "Audit-Fund MEDIUM-4, HIGH-2 und S1-R/HIGH-1; Version v1.97.0, Port 5001:3000, "
            "sha256:286e3fa7f3a7426e775e8564fe1870f1ba8f999d3ab8bbb8cc46a44355d9d6e9, "
            "Datum 2026-08-19, UID 1001, Alles unter HIGH steht in Schritt 1 im Bericht, "
            "60–95 % Einsparung, 26 von 32 PII-freien Texten, DATENSCHLE-59."
        )
        self.assertEqual(self._sweep_findings("legit", legit), [])

    def test_sweep_detects_known_variants(self):
        for bad in ("Es gibt 32 behebbare CRITICALs.", "0 CRITICAL  -> gruen", "9 CRITICAL (openssl)",
                    "Genehmigung der 32 behebbaren CRITICALs", "Messung `5 behebbare CRITICALs`",
                    "(Run 32252889633, 2026-08-19)", "um 62–76 % weniger Befunde",
                    "Gesamtbefunde 4346 → 12", "gemessen 5 → 0 CRITICAL"):
            self.assertTrue(self._sweep_findings("x", bad), bad)

    def test_adr_states_numbers_are_upstream_calculation(self):
        flat = _flat(ROOT / ADR)
        self.assertIn("Upstream-Rechnung", flat)
        self.assertIn("nicht gescannt", flat)


if __name__ == "__main__":
    unittest.main()
