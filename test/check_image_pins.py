#!/usr/bin/env python3
"""Guard against drift between the pinned images and the image-scan matrix.

Every container image the stack uses is declared twice on purpose:

  * where it is *used*    -- litellm/Dockerfile, presidio/Dockerfile.analyzer,
                             docker-compose.yml
  * where it is *scanned* -- .github/workflows/image-scan.yml (matrix)

Duplication that nobody checks silently rots. If someone bumps a digest in
the Dockerfile but forgets the matrix, the weekly CVE scan keeps scanning an
image we no longer ship -- a scanner reporting green about the wrong thing,
which is worse than no scanner at all.

This script fails when:

  1. any image reference in the used-files is missing an @sha256 digest
     (i.e. someone reintroduced a floating tag), or
  2. the set of digests in the used-files differs from the set in the matrix.

Runs on the stdlib alone -- no new dependency (Gesetz 5).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

USED_FILES = [
    Path("litellm/Dockerfile"),
    Path("presidio/Dockerfile.analyzer"),
    Path("docker-compose.yml"),
]
MATRIX_FILE = Path(".github/workflows/image-scan.yml")

# `FROM <ref>` in a Dockerfile, `image: <ref>` in compose. Comment lines are
# dropped beforehand so the explanatory prose above each pin is not mistaken
# for a real reference.
USE_RE = re.compile(r"^\s*(?:FROM|image:)\s+(\S+)", re.MULTILINE)
MATRIX_RE = re.compile(r"^\s*ref:\s+(\S+)", re.MULTILINE)
DIGEST_RE = re.compile(r"@(sha256:[0-9a-f]{64})$")


def strip_comments(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def collect(path: Path, pattern: "re.Pattern[str]") -> list:
    full = ROOT / path
    if not full.exists():
        print(f"FAIL: {path} not found", file=sys.stderr)
        sys.exit(2)
    return pattern.findall(strip_comments(full.read_text(encoding="utf-8")))


def main() -> int:
    problems = []
    used = {}

    for path in USED_FILES:
        for ref in collect(path, USE_RE):
            match = DIGEST_RE.search(ref)
            if not match:
                problems.append(
                    f"{path}: '{ref}' has no @sha256 digest -- floating tags are "
                    f"forbidden (docs/foundation/supply-chain.md section 1)"
                )
                continue
            used[match.group(1)] = f"{path}: {ref}"

    scanned = {}
    for ref in collect(MATRIX_FILE, MATRIX_RE):
        match = DIGEST_RE.search(ref)
        if not match:
            problems.append(
                f"{MATRIX_FILE}: matrix entry '{ref}' has no @sha256 digest"
            )
            continue
        scanned[match.group(1)] = ref

    for digest, where in sorted(used.items()):
        if digest not in scanned:
            problems.append(
                f"{where}\n    -> not covered by the image-scan matrix in "
                f"{MATRIX_FILE}. Add it, or the weekly CVE scan misses this image."
            )
    for digest, ref in sorted(scanned.items()):
        if digest not in used:
            problems.append(
                f"{MATRIX_FILE}: matrix scans '{ref}',\n    -> but no file in "
                f"{[str(p) for p in USED_FILES]} uses that digest any more "
                f"(stale entry)."
            )

    if problems:
        print("Image-Pin-Drift gefunden:\n", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(
        f"OK: {len(used)} gepinnte Images, alle mit Digest, "
        f"alle in der Scan-Matrix abgedeckt."
    )
    for _digest, where in sorted(used.items(), key=lambda kv: kv[1]):
        print(f"  {where}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
