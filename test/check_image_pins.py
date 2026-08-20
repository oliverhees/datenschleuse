#!/usr/bin/env python3
"""Guard against unpinned images and against drift vs. the image-scan matrix.

Every container image the stack uses is declared twice on purpose:

  * where it is *used*    -- every tracked Dockerfile and docker-compose file
  * where it is *scanned* -- .github/workflows/image-scan.yml (matrix)

Duplication that nobody checks silently rots. If someone bumps a digest in
the Dockerfile but forgets the matrix, the weekly CVE scan keeps scanning an
image we no longer ship -- a scanner reporting green about the wrong thing,
which is worse than no scanner at all.

This script fails when:

  1. any image reference in the used-files is missing an @sha256 digest
     (i.e. someone reintroduced a floating tag), or
  2. the set of digests in the used-files differs from the set in the matrix.

WHY THE FILE LIST IS DISCOVERED, NOT HARDCODED (DATENSCHLE-59, finding HIGH-2):

Until this change the list was three fixed entries. `deploy/coolify/docker-
compose.yaml` -- the deploy path of the hosted instance, i.e. the one we sell --
was not among them, and it carried `postgres:16-alpine` and
`presidio-anonymizer:latest`. The script printed "OK: 5 gepinnte Images, alle
mit Digest" and exited 0: a global all-clear about a file it had never opened.
That is precisely the failure mode the paragraph above warns about, committed by
the guard itself.

A hardcoded list cannot cover a file that does not exist yet. Discovery can.
Every tracked `Dockerfile*` and `docker-compose*.y*ml` is now in scope
automatically, so the next compose file added anywhere in the repo is checked on
the day it lands rather than on the day someone remembers to extend this list.

Discovery goes through `git ls-files` rather than a filesystem walk on purpose:
the repository carries dozens of complete checkouts under `.claude/worktrees/`,
and `rglob` would happily scan all of them. Tracked files are exactly the files
we ship.

Runs on the stdlib alone -- no new dependency (Gesetz 5).
"""

from __future__ import annotations

import fnmatch
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Basename patterns for files that can reference a container image.
# Dockerfile, Dockerfile.analyzer, docker-compose.yml, docker-compose.yaml,
# docker-compose.prod.yml, compose files under deploy/ -- all of them.
USED_PATTERNS = ("Dockerfile", "Dockerfile.*", "docker-compose*.yml", "docker-compose*.yaml")

# Files that MUST always end up in scope. This is a floor, not a ceiling: it
# does not limit what is checked, it makes a discovery that silently stops
# matching fail loudly instead of reporting a clean repo. A guard whose scope
# quietly shrank to zero is the exact bug this file exists to prevent.
REQUIRED_IN_SCOPE = (
    Path("litellm/Dockerfile"),
    Path("presidio/Dockerfile.analyzer"),
    Path("docker-compose.yml"),
    Path("deploy/coolify/docker-compose.yaml"),
)

MATRIX_FILE = Path(".github/workflows/image-scan.yml")

# Referenzen auf LOKAL GEBAUTE Images. Ein Image, das dieser Arbeitsbaum selbst
# erzeugt, existiert in keiner Registry und hat deshalb keinen Digest, auf den
# man pinnen koennte -- die Forderung waere nicht streng, sondern unerfuellbar.
#
# WICHTIG, weil hier schon einmal ein Loch entstand: Das ist eine ALLOWLIST,
# keine Denylist. Alles, was nicht ausdruecklich hier steht, MUSS gepinnt sein.
# Eine neue Referenz faellt damit auf die sichere Seite (rot), nicht auf die
# bequeme. Genau andersherum als die frueher hartcodierte Datei-Liste, die
# alles Unbekannte stillschweigend durchliess.
#
# Jeder Eintrag braucht eine Begruendung, und die Ausgabe nennt sie -- eine
# unsichtbare Ausnahme ist eine vergessene Ausnahme.
LOCAL_BUILD_REFS = {
    "datenschleuse-datenschleuse:latest": (
        "lokal von docker-compose.yml gebaut (Projekt `datenschleuse`, Dienst "
        "`datenschleuse`); liegt in keiner Registry, hat also keinen Digest. "
        "Der Inhalt ist ueber litellm/Dockerfile gepinnt."
    ),
}

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


def discover_used_files(root: Path) -> list[Path]:
    """Every tracked Dockerfile / compose file, relative to `root`.

    Fails hard when git is unavailable or the listing is empty. Returning an
    empty list would make the whole check pass -- silently, and about nothing.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        print(
            f"FAIL: 'git ls-files' in {root} nicht ausfuehrbar ({exc}). Der "
            f"Pruefumfang liesse sich nicht bestimmen -- lieber rot als "
            f"falsch gruen.",
            file=sys.stderr,
        )
        sys.exit(2)

    found = [
        Path(name)
        for name in out.decode("utf-8").split("\0")
        if name
        and any(fnmatch.fnmatch(Path(name).name, pat) for pat in USED_PATTERNS)
    ]

    missing = [p for p in REQUIRED_IN_SCOPE if p not in found]
    if missing:
        print(
            "FAIL: Dateien aus dem Pflicht-Pruefumfang nicht gefunden: "
            f"{[str(p) for p in missing]}. Entweder wurden sie geloescht/"
            "umbenannt (dann REQUIRED_IN_SCOPE mit anpassen) oder die "
            "Erkennung ist kaputt.",
            file=sys.stderr,
        )
        sys.exit(2)

    return sorted(found)


def collect(root: Path, path: Path, pattern: "re.Pattern[str]") -> list:
    full = root / path
    if not full.exists():
        print(f"FAIL: {path} not found", file=sys.stderr)
        sys.exit(2)
    return pattern.findall(strip_comments(full.read_text(encoding="utf-8")))


def collect_used(root: Path, files: "list[Path]") -> "tuple[dict, list[str]]":
    """Map digest -> "<file>: <ref>" and report every reference without one."""
    used: dict = {}
    problems: list[str] = []
    for path in files:
        for ref in collect(root, path, USE_RE):
            if ref in LOCAL_BUILD_REFS:
                continue
            match = DIGEST_RE.search(ref)
            if not match:
                problems.append(
                    f"{path}: '{ref}' has no @sha256 digest -- floating tags are "
                    f"forbidden (docs/foundation/supply-chain.md section 1)"
                )
                continue
            used[match.group(1)] = f"{path}: {ref}"
    return used, problems


def collect_scanned(root: Path, matrix_file: Path) -> "tuple[dict, list[str]]":
    scanned: dict = {}
    problems: list[str] = []
    for ref in collect(root, matrix_file, MATRIX_RE):
        match = DIGEST_RE.search(ref)
        if not match:
            problems.append(f"{matrix_file}: matrix entry '{ref}' has no @sha256 digest")
            continue
        scanned[match.group(1)] = ref
    return scanned, problems


def compare(used: dict, scanned: dict, files: "list[Path]") -> "list[str]":
    problems: list[str] = []
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
                f"{[str(p) for p in files]} uses that digest any more "
                f"(stale entry)."
            )
    return problems


def is_shipped(path: Path) -> bool:
    """Does this file define part of what we ship?

    Two different invariants live in this script and they are NOT the same:

      * Every image reference must carry a digest -- supply-chain integrity.
        Applies everywhere, test scaffolding included.
      * Every image must be in the weekly CVE matrix -- applies only to what we
        actually ship. Test-only images belong in neither the matrix nor the
        shipped-images table of the playbook; demanding it there would push
        scaffolding into a document about the delivered product.

    Test scaffolding is identified by path: anything under `test/`.
    """
    return path.parts[0] != "test"


def main() -> int:
    files = discover_used_files(ROOT)
    used, problems = collect_used(ROOT, files)
    shipped_files = [f for f in files if is_shipped(f)]
    shipped_used, _ = collect_used(ROOT, shipped_files)
    scanned, scan_problems = collect_scanned(ROOT, MATRIX_FILE)
    problems += scan_problems
    problems += compare(shipped_used, scanned, shipped_files)

    if problems:
        print("Image-Pin-Drift gefunden:\n", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(
        f"OK: {len(used)} gepinnte Images in {len(files)} geprueften Dateien, "
        f"alle mit Digest, alle in der Scan-Matrix abgedeckt."
    )
    for path in files:
        marker = "" if is_shipped(path) else "  (nur Digest-Pflicht, Test-Gestell)"
        print(f"  geprueft: {path}{marker}")
    for ref, reason in sorted(LOCAL_BUILD_REFS.items()):
        print(f"  ausgenommen (lokal gebaut): {ref}\n      {reason}")
    for _digest, where in sorted(used.items(), key=lambda kv: kv[1]):
        print(f"  {where}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
