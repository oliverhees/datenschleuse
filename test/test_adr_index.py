"""ADR index guard (DATENSCHLE-65, QA-F2).

CONTEXT.md is the entry point for newcomers ("Architektur-Entscheidungen").
ADR-0003..0005 were missing there, so they were orphaned. This test makes
every ADR file reachable from CONTEXT.md. It checks that the *link target*
exists in the ADR table; a mention in prose does not count.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
ADR_DIR = ROOT / "docs" / "adr"
CONTEXT = (ROOT / "CONTEXT.md").read_text(encoding="utf-8")


def _adr_files():
    return sorted(
        p.name for p in ADR_DIR.glob("[0-9][0-9][0-9][0-9]-*.md")
        if not p.name.startswith("0000-")
    )


class AdrIndexTest(unittest.TestCase):
    def test_there_are_adrs_to_check(self):
        # Guard against a vacuous pass (glob matching nothing).
        self.assertGreaterEqual(len(_adr_files()), 5)

    def test_every_adr_is_linked_in_context_table(self):
        rows = [ln for ln in CONTEXT.splitlines() if ln.startswith("| [ADR-")]
        for name in _adr_files():
            number = name[:4]
            linked = [
                r for r in rows
                if f"](docs/adr/{name})" in r and r.startswith(f"| [ADR-{number}]")
            ]
            self.assertEqual(
                len(linked), 1,
                f"{name} is not linked exactly once as a table row in CONTEXT.md",
            )

    def test_every_linked_adr_exists(self):
        for target in re.findall(r"\]\((docs/adr/[^)#]+)\)", CONTEXT):
            self.assertTrue((ROOT / target).is_file(), f"dead ADR link: {target}")


if __name__ == "__main__":
    unittest.main()
