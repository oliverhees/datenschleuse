"""Guards for .github/workflows/release.yml (published images).

Static: triggers, least privilege, pinned actions only from ci.yml, tests
before the build, smoke test before any tag, attestations on every build.
Dynamic: the version/latest step is executed in a throw-away git repository,
so the rule "latest only for a final tag whose commit is on main, never on a
manual start" is tested, not just read.

The workflow itself is NOT run here (it pushes to GHCR); its first real run
is the first release.
"""
import pathlib
import re
import subprocess
import tempfile
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
WF = ROOT / ".github" / "workflows" / "release.yml"
CI = ROOT / ".github" / "workflows" / "ci.yml"
BUILD = ROOT / ".github" / "scripts" / "release-build.sh"


def _uses(path):
    return set(re.findall(r"^\s*-?\s*uses:\s*(\S+)", path.read_text(encoding="utf-8"), re.M))


class StaticShape(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wf = yaml.safe_load(WF.read_text(encoding="utf-8"))
        cls.jobs = cls.wf["jobs"]

    def test_triggers(self):
        on = self.wf[True]  # YAML 1.1 reads the key `on` as True
        self.assertEqual(on["push"], {"tags": ["v*"]})
        self.assertIn("workflow_dispatch", on)
        self.assertNotIn("pull_request", on)

    def test_least_privilege(self):
        self.assertEqual(self.wf["permissions"], {"contents": "read"})
        for name, job in self.jobs.items():
            perms = job.get("permissions")
            if name in ("build-amd64", "build-arm64", "publish"):
                self.assertEqual(perms, {"contents": "read", "packages": "write"}, name)
            elif name == "smoke":
                self.assertEqual(perms, {"contents": "read", "packages": "read"}, name)
            else:
                self.assertIsNone(perms, f"{name} must inherit contents: read")

    def test_only_github_token(self):
        secrets = set(re.findall(r"secrets\.([A-Za-z_]+)", WF.read_text(encoding="utf-8")))
        self.assertEqual(secrets, {"GITHUB_TOKEN"})

    def test_only_actions_already_pinned_in_ci(self):
        self.assertTrue(_uses(WF) <= _uses(CI), _uses(WF) - _uses(CI))

    def test_no_expression_inside_run(self):
        for name, job in self.jobs.items():
            for step in job["steps"]:
                self.assertNotIn("${{", step.get("run", ""), f"{name}: use env: instead")

    def test_order_test_build_smoke_publish(self):
        self.assertIn("test", self.jobs["build-amd64"]["needs"])
        self.assertIn("test", self.jobs["build-arm64"]["needs"])
        self.assertIn("build-amd64", self.jobs["smoke"]["needs"])
        self.assertIn("smoke", self.jobs["publish"]["needs"])
        self.assertEqual(self.jobs["build-arm64"]["runs-on"], "ubuntu-24.04-arm")

    def test_tests_match_ci(self):
        runs = [s.get("run", "") for s in self.jobs["test"]["steps"]]
        self.assertIn('python3 -m unittest discover -s ./test -p "test_*.py"', runs)
        self.assertIn("python3 test/check_image_pins.py", runs)

    def test_attestations_and_push_by_digest(self):
        script = BUILD.read_text(encoding="utf-8")
        for flag in ("--provenance=mode=max", "--sbom=true", "push-by-digest=true"):
            self.assertIn(flag, script)
        self.assertIn("SPACY_MODEL=de_core_news_lg", script)
        self.assertIn("SPACY_MODEL=de_core_news_md", script)

    def test_image_names(self):
        env = self.wf["env"]
        self.assertEqual(env["PROXY_IMAGE"], "ghcr.io/oliverhees/datenschleuse")
        self.assertEqual(env["ANALYZER_IMAGE"], "ghcr.io/oliverhees/datenschleuse-analyzer")
        self.assertRegex(env["BUILDKIT_IMAGE"], r"@sha256:[0-9a-f]{64}$")

    def test_smoke_uses_pushed_digests(self):
        run = "\n".join(s.get("run", "") for s in self.jobs["smoke"]["steps"])
        self.assertIn("sh test/smoke-images.sh", run)
        self.assertIn('$PROXY_IMAGE@$PROXY_DIGEST', run)


class VersionStep(unittest.TestCase):
    """Executes the `version` step's shell in a temporary repository."""

    @classmethod
    def setUpClass(cls):
        wf = yaml.safe_load(WF.read_text(encoding="utf-8"))
        cls.script = next(s["run"] for s in wf["jobs"]["version"]["steps"] if s.get("id") == "v")
        cls.tmp = tempfile.TemporaryDirectory()
        repo = pathlib.Path(cls.tmp.name)
        git = ["git", "-C", str(repo), "-c", "user.email=t@example.invalid", "-c", "user.name=t"]
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        subprocess.run(git + ["commit", "-q", "--allow-empty", "-m", "on main"], check=True)
        cls.on_main = subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        subprocess.run(git + ["update-ref", "refs/remotes/origin/main", cls.on_main], check=True)
        subprocess.run(git + ["checkout", "-q", "-b", "side"], check=True)
        subprocess.run(git + ["commit", "-q", "--allow-empty", "-m", "side"], check=True)
        cls.off_main = subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        cls.repo = repo

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _run(self, event, ref_type, ref_name, commit):
        out = self.repo / "out.txt"
        out.write_text("")
        env = {
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "EVENT": event, "REF_TYPE": ref_type, "REF_NAME": ref_name,
            "COMMIT": commit, "DEFAULT_BRANCH": "main", "GITHUB_OUTPUT": str(out),
        }
        res = subprocess.run(["sh", "-c", self.script], cwd=self.repo, env=env, capture_output=True, text=True)
        values = dict(l.split("=", 1) for l in out.read_text().splitlines() if "=" in l)
        return res.returncode, values

    def test_final_tag_on_main_gets_latest(self):
        self.assertEqual(self._run("push", "tag", "v1.2.3", self.on_main), (0, {"version": "1.2.3", "latest": "true"}))

    def test_prerelease_never_latest(self):
        self.assertEqual(self._run("push", "tag", "v1.2.3-rc.1", self.on_main)[1]["latest"], "false")

    def test_tag_off_main_not_latest(self):
        self.assertEqual(self._run("push", "tag", "v1.2.3", self.off_main), (0, {"version": "1.2.3", "latest": "false"}))

    def test_manual_start_never_latest(self):
        code, values = self._run("workflow_dispatch", "branch", "main", self.on_main)
        self.assertEqual(code, 0)
        self.assertEqual(values, {"version": f"sha-{self.on_main[:12]}", "latest": "false"})

    def test_manual_start_on_tag_never_latest(self):
        self.assertEqual(self._run("workflow_dispatch", "tag", "v1.2.3", self.on_main)[1]["latest"], "false")

    def test_malformed_tag_fails(self):
        self.assertNotEqual(self._run("push", "tag", "v1.2", self.on_main)[0], 0)
        self.assertNotEqual(self._run("push", "tag", "vfoo", self.on_main)[0], 0)


if __name__ == "__main__":
    unittest.main()
