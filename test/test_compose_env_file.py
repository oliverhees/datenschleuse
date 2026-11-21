"""Compose project directory guard (DATENSCHLE-106, QA audit 3, Q1).

``tools/init-env.sh`` writes ``.env`` to the repository root. With
``docker compose -f deploy/coolify/docker-compose.yaml`` Compose takes the
directory of the compose file (``deploy/coolify/``) as project directory and
reads ``.env`` from THERE, so the generated file is silently ignored and every
required variable is "missing a value". Every such command therefore carries
``--env-file .env`` (run from the repository root).

1. Docs/script guard: no ``docker compose`` command with
   ``-f deploy/coolify...`` in a tracked Markdown, shell or workflow file
   lacks ``--env-file``.
2. Real ``docker compose config`` in a temporary copy, both ways: without
   ``--env-file`` it fails, with it it passes. Skips cleanly when the docker
   CLI or its compose plugin is missing; ``config`` needs no daemon.
"""
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
COOLIFY = "deploy/coolify/docker-compose.yaml"
SEGMENT_END = re.compile(r"&&|\|\||[;|]|`")


def _tracked(*suffixes):
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    names = [n for n in out.split("\0") if n.endswith(suffixes)]
    # test files quote the commands as test data
    return [ROOT / n for n in names if not n.startswith("test/")]


def _logical_lines(text):
    """Lines with trailing-backslash continuations joined."""
    joined, buffer = [], ""
    for line in text.splitlines():
        if line.rstrip().endswith("\\"):
            buffer += line.rstrip()[:-1] + " "
        else:
            joined.append(buffer + line)
            buffer = ""
    if buffer:
        joined.append(buffer)
    return joined


def coolify_compose_commands(text):
    """Every ``docker compose ...`` command segment that names the Coolify file."""
    found = []
    for line in _logical_lines(text):
        for match in re.finditer(r"docker compose\b", line):
            segment = SEGMENT_END.split(line[match.start():], maxsplit=1)[0]
            if "deploy/coolify" in segment:
                found.append(segment.strip())
    return found


class TestCoolifyCommandsCarryEnvFile(unittest.TestCase):
    def test_the_detector_sees_a_bare_command(self):
        # Proves the guard below can fail.
        bare = f"docker compose -f {COOLIFY} up -d --build"
        self.assertEqual(coolify_compose_commands(bare), [bare])
        self.assertEqual(coolify_compose_commands(f"a \\\n && docker compose -f {COOLIFY} up"), [f"docker compose -f {COOLIFY} up"])
        self.assertEqual(coolify_compose_commands("docker compose up -d"), [])

    def test_there_are_commands_to_check(self):
        total = sum(len(coolify_compose_commands(p.read_text(encoding="utf-8"))) for p in _tracked(".md", ".sh", ".yml", ".yaml"))
        self.assertGreaterEqual(total, 5)

    def test_every_coolify_compose_command_has_env_file(self):
        for path in _tracked(".md", ".sh", ".yml", ".yaml"):
            for command in coolify_compose_commands(path.read_text(encoding="utf-8")):
                with self.subTest(file=str(path.relative_to(ROOT)), command=command):
                    self.assertIn("--env-file .env", command)

    def test_the_document_says_why(self):
        text = (ROOT / "docs" / "DEPLOY.md").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?s)--env-file.{0,400}(Projektverzeichnis|Verzeichnis der Compose-Datei)")


def _compose_available():
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "compose", "version"], capture_output=True, timeout=60).returncode == 0


class TestRealComposeConfig(unittest.TestCase):
    """Runs the real ``docker compose config`` (no daemon needed)."""

    def setUp(self):
        if not _compose_available():
            self.skipTest("docker CLI with the compose plugin not available")

    def _copy(self, tmp):
        root = pathlib.Path(tmp)
        (root / "deploy" / "coolify").mkdir(parents=True)
        (root / "tools").mkdir()
        shutil.copy(ROOT / COOLIFY, root / COOLIFY)
        shutil.copy(ROOT / ".env.example", root / ".env.example")
        shutil.copy(ROOT / "tools" / "init-env.sh", root / "tools" / "init-env.sh")
        made = subprocess.run(["bash", "tools/init-env.sh"], cwd=root, capture_output=True, text=True, timeout=60)
        self.assertEqual(made.returncode, 0, made.stderr)
        with (root / ".env").open("a", encoding="utf-8") as handle:
            handle.write("EUROUTER_API_KEY=scratch-value\n")
        return root

    def _config(self, root, *flags):
        return subprocess.run(["docker", "compose", *flags, "-f", COOLIFY, "config", "-q"], cwd=root, capture_output=True, text=True, timeout=120)

    def test_without_env_file_the_generated_env_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._config(self._copy(tmp))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing a value", result.stderr)

    def test_with_env_file_the_generated_env_is_used(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._config(self._copy(tmp), "--env-file", ".env")
            self.assertEqual(result.returncode, 0, result.stderr)
