"""Code, reason table and README must say the same about retrying a block.

Security audit round 2 (Info): the README said "a block is not retryable" for
every reason, but ``analyzer_unavailable`` is a temporary outage of a Presidio
service. Clients that read the README literally would never retry.
"""

import os
import pathlib
import re
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..", "litellm")))

import datenschleuse_guardrail as dg  # noqa: E402

ROOT = pathlib.Path(_HERE).parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
BASELINE = (ROOT / "docs" / "foundation" / "security-baseline.md").read_text(encoding="utf-8")


class TestRetryWording(unittest.TestCase):
    def test_code_declares_exactly_the_temporary_reasons(self):
        self.assertEqual(dg.TEMPORARY_BLOCK_REASONS, ("analyzer_unavailable",))
        self.assertTrue(set(dg.TEMPORARY_BLOCK_REASONS) <= set(dg.BLOCK_REASONS))

    def test_reason_table_has_a_retry_column_matching_the_code(self):
        rows = {}
        for line in BASELINE.splitlines():
            m = re.match(r"\| `(\w+)` \| (.*) \| (Ja|Nein)[^|]*\|\s*$", line)
            if m and m.group(1) in dg.BLOCK_REASONS:
                rows[m.group(1)] = m.group(3)
        self.assertEqual(set(rows), set(dg.BLOCK_REASONS))
        for reason, retry in rows.items():
            self.assertEqual(retry == "Ja", reason in dg.TEMPORARY_BLOCK_REASONS, reason)

    def test_readme_does_not_call_every_block_not_retryable(self):
        self.assertNotIn("Ein Block ist nicht wiederholbar.", README)
        self.assertNotIn("nicht wiederholen", README)
        section = README.split("### Blockierte Anfragen erkennen", 1)[1].split("###", 1)[0]
        self.assertIn("analyzer_unavailable", section)
        self.assertRegex(section, r"(?s)analyzer_unavailable.{0,400}(vorübergehend|später)")

    def test_baseline_recommendation_agrees(self):
        self.assertNotIn("Ein Block ist nicht wiederholbar; derselbe Request blockt erneut.", BASELINE)


if __name__ == "__main__":
    unittest.main()
