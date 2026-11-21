"""CI must run the LiteLLM-dependent tests (DATENSCHLE-106, QA audit 3, Q2).

``TestMessagesSurviveLiteLlmLogRedaction`` calls LiteLLM's real
``redact_string``. It skips when ``litellm`` is not importable, and CI never
installed it, so it never ran there. The ``test`` job now installs the pinned
version and sets ``DS_REQUIRE_LITELLM=1``, which turns a missing import into a
failure (see ``test_admin_credentials.py``). The version has one source: the
tag of the base image in ``litellm/Dockerfile``.
"""
import pathlib
import re
import subprocess
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
CI = ROOT / ".github" / "workflows" / "ci.yml"
VERSION_SCRIPT = ROOT / ".github" / "scripts" / "litellm-version.sh"
DOCKERFILE = ROOT / "litellm" / "Dockerfile"


def _steps(job):
    return yaml.safe_load(CI.read_text(encoding="utf-8"))["jobs"][job]["steps"]


class TestCiInstallsLiteLlm(unittest.TestCase):
    def test_version_script_prints_the_dockerfile_tag(self):
        result = subprocess.run(["bash", str(VERSION_SCRIPT)], capture_output=True, text=True, cwd=ROOT, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        tag = re.search(r"^FROM ghcr\.io/berriai/litellm:v(\d+\.\d+\.\d+)@sha256:", DOCKERFILE.read_text(encoding="utf-8"), re.M)
        self.assertIsNotNone(tag)
        self.assertEqual(result.stdout.strip(), tag.group(1))

    def test_version_script_fails_loudly_without_a_version(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "litellm").mkdir()
            (root / "litellm" / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            result = subprocess.run(["bash", str(VERSION_SCRIPT)], capture_output=True, text=True, cwd=root, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), "")

    def test_the_test_job_installs_the_pinned_litellm_from_that_single_source(self):
        runs = [s.get("run", "") for s in _steps("test")]
        install = [r for r in runs if "pip install" in r and "litellm==" in r]
        self.assertEqual(len(install), 1, runs)
        self.assertIn(".github/scripts/litellm-version.sh", install[0])
        self.assertNotRegex(install[0], r"litellm==\d")  # no second copy of the number

    def test_the_unit_test_step_requires_litellm(self):
        step = next(s for s in _steps("test") if "unittest discover" in s.get("run", ""))
        self.assertEqual(str(step.get("env", {}).get("DS_REQUIRE_LITELLM")), "1")

    def test_install_comes_before_the_tests(self):
        runs = [s.get("run", "") for s in _steps("test")]
        i = next(n for n, r in enumerate(runs) if "litellm==" in r)
        j = next(n for n, r in enumerate(runs) if "unittest discover" in r)
        self.assertLess(i, j)


class TestMissingLiteLlmFailsWhenRequired(unittest.TestCase):
    def test_a_missing_import_is_a_failure_with_the_variable_and_a_skip_without(self):
        code = (
            "import sys, unittest\n"
            "sys.modules['litellm'] = None  # makes the import fail\n"
            "sys.path.insert(0, 'test'); sys.path.insert(0, 'litellm')\n"
            "import test_admin_credentials as m\n"
            "s = unittest.defaultTestLoader.loadTestsFromName('TestMessagesSurviveLiteLlmLogRedaction', m)\n"
            "r = unittest.TextTestRunner(stream=open('/dev/null', 'w')).run(s)\n"
            "print(len(r.failures) + len(r.errors), len(r.skipped))\n"
        )
        import os

        def run(extra):
            env = {k: v for k, v in os.environ.items() if k != "DS_REQUIRE_LITELLM"}
            env.update(extra)
            out = subprocess.run(["python3", "-c", code], capture_output=True, text=True, cwd=ROOT, env=env, timeout=120)
            self.assertEqual(out.returncode, 0, out.stderr[-500:])
            return out.stdout.split()[-2:]

        self.assertEqual(run({}), ["0", "2"])
        self.assertEqual(run({"DS_REQUIRE_LITELLM": "1"}), ["2", "0"])
