#!/usr/bin/env python3
"""Enforce the GitHub-Actions pinning rule from supply-chain.md section 2.

Why this exists (DATENSCHLE-59, audit finding MEDIUM-2):

Section 2 of the supply-chain playbook requires every `uses:` reference to point
at a COMMIT SHA, and its update procedure explicitly warns about annotated tags.
The rule was written in the same pull request that broke it: all four
`aquasecurity/trivy-action` pins carried `a9c7b0f0...`, which is the annotated
TAG OBJECT of v0.36.0, not the commit (`ed142fd0...`).

A rule with no enforcement is a suggestion. Nothing in CI checked section 2, so
the violation shipped in the PR that introduced the rule -- and the same trap
was hit again minutes later while pinning `github/codeql-action`, whose v4.37.7
tag is also annotated. Twice in one change is not carelessness, it is a missing
check.

Two levels, deliberately separated:

  * OFFLINE (always runs, hermetic): shape only -- 40 lowercase hex, a version
    comment, no floating refs. This alone would NOT have caught MEDIUM-1: a tag
    object id is also 40 hex. It catches the much more common `@v4` / `@main`.
  * ONLINE (opt-in via DS_CHECK_ACTION_PINS_ONLINE=1): asks GitHub whether each
    SHA is really a commit. This is the check that catches MEDIUM-1. It is
    opt-in so the normal suite stays offline and deterministic.

Run the online check before merging any workflow change:

    DS_CHECK_ACTION_PINS_ONLINE=1 python3 -m unittest test_action_pins -v
"""

from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = ROOT / ".github" / "workflows"

# `- uses: owner/repo@ref  # comment`
USES_RE = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>\S+)\s*(?P<comment>#.*)?$", re.MULTILINE)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_COMMENT_RE = re.compile(r"#\s*v?\d+\.\d+(\.\d+)?")


def workflow_files() -> "list[Path]":
    files = sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))
    return files


def uses_references() -> "list[tuple[Path, str, str]]":
    """(file, full uses value, trailing comment) for every `uses:` line."""
    found = []
    for path in workflow_files():
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            match = USES_RE.match(line)
            if not match:
                continue
            ref = match.group("ref")
            # Local composite actions and docker refs are not SHA-pinnable.
            if ref.startswith("./") or ref.startswith("docker://"):
                continue
            found.append((path.relative_to(ROOT), ref, match.group("comment") or ""))
    return found


class OfflineShapeTest(unittest.TestCase):
    """Runs always. Cheap invariants that need no network."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.refs = uses_references()

    def test_workflows_exist(self) -> None:
        """Guard against a glob that silently matches nothing."""
        self.assertTrue(workflow_files(), "Keine Workflow-Dateien gefunden")
        self.assertTrue(self.refs, "Keine `uses:`-Zeilen gefunden -- Erkennung kaputt?")

    def test_every_uses_is_pinned_to_a_40_hex_sha(self) -> None:
        for path, ref, _comment in self.refs:
            with self.subTest(ref=ref):
                self.assertIn("@", ref, f"{path}: '{ref}' ohne @-Ref")
                sha = ref.split("@", 1)[1]
                self.assertRegex(
                    sha,
                    SHA_RE,
                    f"{path}: '{ref}' ist nicht auf 40 Hex-Zeichen gepinnt. "
                    f"Ein bewegliches Tag im Fremd-Repo fuehrt beliebigen Code "
                    f"in unserer CI aus (supply-chain.md §2).",
                )

    def test_every_pin_carries_a_version_comment(self) -> None:
        """A bare SHA is reproducible but unreadable -- nobody can tell its age."""
        for path, ref, comment in self.refs:
            with self.subTest(ref=ref):
                self.assertRegex(
                    comment,
                    VERSION_COMMENT_RE,
                    f"{path}: '{ref}' ohne `# vX.Y.Z`-Lesehilfe.",
                )


@unittest.skipUnless(
    os.environ.get("DS_CHECK_ACTION_PINS_ONLINE") == "1",
    "Online-Pruefung nur mit DS_CHECK_ACTION_PINS_ONLINE=1 (braucht Netz + gh)",
)
class OnlineObjectTypeTest(unittest.TestCase):
    """The check that would have caught MEDIUM-1.

    A 40-hex string can be a commit OR an annotated tag object. Only GitHub can
    tell them apart: the commits API returns 422 for a tag object id.
    """

    def test_every_pin_is_a_commit_not_a_tag_object(self) -> None:
        for path, ref, _comment in uses_references():
            target, sha = ref.split("@", 1)
            # Subdirectory actions look like `owner/repo/sub/dir@sha`
            # (e.g. github/codeql-action/upload-sarif). Only the first two
            # segments are the repository -- the rest is a path inside it.
            repo = "/".join(target.split("/")[:2])
            with self.subTest(ref=ref):
                proc = subprocess.run(
                    ["gh", "api", f"repos/{repo}/commits/{sha}", "--jq", ".sha"],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(
                    proc.returncode,
                    0,
                    f"{path}: '{ref}' ist kein Commit dieses Repos. Sehr "
                    f"wahrscheinlich das annotierte Tag-Objekt -- aufloesen mit "
                    f"`gh api repos/{repo}/git/tags/{sha} --jq .object.sha` "
                    f"(supply-chain.md §2). stderr: {proc.stderr.strip()[:200]}",
                )
                self.assertEqual(proc.stdout.strip(), sha)


if __name__ == "__main__":
    unittest.main()
