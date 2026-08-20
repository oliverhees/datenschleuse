#!/usr/bin/env python3
"""Tests for the image-pin drift guard (test/check_image_pins.py).

Why this file exists (DATENSCHLE-59, Security-Audit finding HIGH-2 and LOW-1):

The guard used to carry a hardcoded three-entry list of files to inspect.
`deploy/coolify/docker-compose.yaml` -- the compose file the hosted instance is
deployed from, i.e. the path we sell -- was not in it. It contained
`postgres:16-alpine` and `mcr.microsoft.com/presidio-anonymizer:latest`, two
floating tags. The guard nevertheless printed

    OK: 5 gepinnte Images, alle mit Digest, alle in der Scan-Matrix abgedeckt.

and exited 0. That is a global all-clear about a file it never opened -- exactly
the failure its own docstring warns about ("a scanner reporting green about the
wrong thing, which is worse than no scanner at all").

The guard also had no test of its own and was not collected by the suite (no
`test_` prefix). Both are fixed here.

The tests below are deliberately split in two:

  * Discovery tests run against the REAL repository. They are the ones that were
    red before the fix, and they are what stops a future compose file from
    silently falling out of scope again.
  * Validation tests run against synthetic files in a temp dir. They pin the
    actual detection behaviour without depending on the repo's current content.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import check_image_pins as guard


class DiscoveryTest(unittest.TestCase):
    """What the guard looks at -- the part that was silently too narrow."""

    def setUp(self) -> None:
        self.discovered = set(guard.discover_used_files(guard.ROOT))

    def test_coolify_compose_is_in_scope(self) -> None:
        """The regression test for HIGH-2.

        `deploy/coolify/docker-compose.yaml` is the deploy path of the hosted
        instance. Before the fix it was not in the hardcoded USED_FILES list, so
        its two floating tags never reached the check.
        """
        self.assertIn(
            Path("deploy/coolify/docker-compose.yaml"),
            self.discovered,
            "Der Coolify-Deploy (der verkaufte Pfad) ist nicht im Pruefumfang. "
            "Genau dieses Loch war HIGH-2.",
        )

    def test_previously_known_files_stay_in_scope(self) -> None:
        """Floor guard: the glob must never cover LESS than the old fixed list.

        A glob that matches nothing would make every run green. This asserts the
        three originally-checked files are still found, so a broken pattern
        fails loudly instead of quietly passing.
        """
        for known in (
            Path("litellm/Dockerfile"),
            Path("presidio/Dockerfile.analyzer"),
            Path("docker-compose.yml"),
        ):
            self.assertIn(known, self.discovered, f"{known} aus dem Pruefumfang gefallen")

    def test_discovery_is_never_empty(self) -> None:
        """An empty scope is a broken scanner, not a clean repo."""
        self.assertTrue(self.discovered, "Kein einziges Dockerfile/Compose gefunden")

    def test_discovery_stays_inside_the_repo(self) -> None:
        """No absolute paths, no escaping into sibling agent worktrees.

        The repo carries dozens of full checkouts under `.claude/worktrees/`.
        A naive filesystem walk would scan all of them. Discovery is therefore
        based on tracked files, and this asserts the result stays relative and
        does not reach into that directory.
        """
        for path in self.discovered:
            self.assertFalse(path.is_absolute(), f"{path} ist absolut")
            self.assertNotIn(
                ".claude", path.parts, f"{path} zeigt in einen fremden Worktree"
            )


class ValidationTest(unittest.TestCase):
    """What the guard does with what it finds."""

    def _write(self, name: str, body: str) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / name).write_text(body, encoding="utf-8")
        return root

    def test_floating_tag_is_reported(self) -> None:
        root = self._write(
            "docker-compose.yml",
            "services:\n  db:\n    image: postgres:16-alpine\n",
        )
        _used, problems = guard.collect_used(root, [Path("docker-compose.yml")])
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("postgres:16-alpine", problems[0])
        self.assertIn("no @sha256 digest", problems[0])

    def test_latest_tag_is_reported(self) -> None:
        root = self._write(
            "docker-compose.yml",
            "services:\n  a:\n    image: mcr.microsoft.com/presidio-anonymizer:latest\n",
        )
        _used, problems = guard.collect_used(root, [Path("docker-compose.yml")])
        self.assertEqual(len(problems), 1, problems)
        self.assertIn(":latest", problems[0])

    def test_pinned_reference_passes(self) -> None:
        digest = "sha256:" + "a" * 64
        root = self._write(
            "docker-compose.yml",
            f"services:\n  db:\n    image: postgres:16.15-alpine@{digest}\n",
        )
        used, problems = guard.collect_used(root, [Path("docker-compose.yml")])
        self.assertEqual(problems, [])
        self.assertIn(digest, used)

    def test_commented_out_reference_is_ignored(self) -> None:
        root = self._write(
            "docker-compose.yml",
            "# image: postgres:16-alpine  <- Beispiel in der Doku, keine echte Referenz\n"
            "services:\n  db:\n    image: postgres:16.15-alpine@sha256:" + "b" * 64 + "\n",
        )
        _used, problems = guard.collect_used(root, [Path("docker-compose.yml")])
        self.assertEqual(problems, [])

    def test_dockerfile_from_is_checked_too(self) -> None:
        root = self._write("Dockerfile", "FROM python:3.12-slim\n")
        _used, problems = guard.collect_used(root, [Path("Dockerfile")])
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("python:3.12-slim", problems[0])


class RealRepositoryTest(unittest.TestCase):
    """End-to-end: the repository as it stands must pass its own guard."""

    def test_repository_has_no_pin_drift(self) -> None:
        self.assertEqual(
            guard.main(),
            0,
            "check_image_pins.py meldet Drift -- siehe Ausgabe oben.",
        )


if __name__ == "__main__":
    unittest.main()
