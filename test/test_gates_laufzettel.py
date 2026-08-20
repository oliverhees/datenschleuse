"""Tests fuer .github/scripts/check-laufzettel.sh (DATENSCHLE-76).

Der Check baut synthetische Repos nach, die exakt die Topologie einer
GitHub-Actions-`pull_request`-Ausfuehrung haben:

    actions/checkout@v4 checkt bei `pull_request` NICHT die Branch-Spitze aus,
    sondern `refs/pull/N/merge` -- einen von GitHub fabrizierten Probe-Merge
    aus (main-Spitze, PR-Spitze). HEAD im Job ist also ein Commit, den niemand
    geschrieben hat und der nach dem Merge nicht existiert.

Belegt am echten Lauf 32262669651 / Job 96080256803:
    HEAD is now at 27fb42b Merge e3c4958... into 42d75ed...
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO_ROOT, ".github", "scripts", "check-laufzettel.sh")


def git(cwd, *args):
    return subprocess.run(
        ["git"] + list(args),
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class Szenario:
    """Baut ein synthetisches origin + PR und fuehrt den Check aus."""

    def __init__(self, tmp):
        self.tmp = tmp
        self.origin = os.path.join(tmp, "origin.git")
        self.up = os.path.join(tmp, "up")
        subprocess.run(["git", "init", "-q", "--bare", self.origin], check=True)
        subprocess.run(["git", "init", "-q", "-b", "main", self.up], check=True)
        git(self.up, "config", "user.email", "team@datenschleuse.test")
        git(self.up, "config", "user.name", "Schmiede")
        git(self.up, "remote", "add", "origin", self.origin)
        os.makedirs(os.path.join(self.up, "litellm"))
        os.makedirs(os.path.join(self.up, ".gates"))
        self.write("litellm/guardrail.py", "MASK = 1\n")
        self.write("README.md", "# datenschleuse\n")
        git(self.up, "add", "-A")
        git(self.up, "commit", "-qm", "base")
        git(self.up, "push", "-q", "origin", "main")

    def write(self, rel, text):
        path = os.path.join(self.up, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def branch(self, name):
        git(self.up, "checkout", "-q", "-b", name)

    def commit(self, msg, files):
        for rel, text in files.items():
            self.write(rel, text)
        git(self.up, "add", "-A")
        git(self.up, "commit", "-qm", msg)
        return git(self.up, "rev-parse", "HEAD")

    def verdict(self, gate, pinned, verdict="pass"):
        """Bildet verdict.sh nach: committet ausschliesslich .gates/<gate>.json."""
        self.write(
            ".gates/%s.json" % gate,
            json.dumps(
                {"gate": gate, "verdict": verdict, "commit": pinned,
                 "branch": "feature/x", "timestamp": "2026-08-20T00:00:00Z"},
                indent=2,
            ) + "\n",
        )
        git(self.up, "add", ".gates/%s.json" % gate)
        git(self.up, "commit", "-qm",
            "[gate] %s: %s @ %s" % (gate, verdict, pinned[:8]),
            "--only", ".gates/%s.json" % gate)
        return git(self.up, "rev-parse", "HEAD")

    def fremder_merge_auf_main(self):
        """Ein anderer PR wird nach main gemergt, waehrend unserer offen ist."""
        aktuell = git(self.up, "rev-parse", "--abbrev-ref", "HEAD")
        git(self.up, "checkout", "-q", "main")
        self.write("litellm/anderes_modul.py", "OTHER = 1\n")
        git(self.up, "add", "-A")
        git(self.up, "commit", "-qm", "[DATENSCHLE-99] fremder PR")
        git(self.up, "push", "-q", "origin", "main")
        git(self.up, "checkout", "-q", aktuell)

    def pruefe(self, pr_branch, als_merge_ref=True):
        """Simuliert den gates-Job. als_merge_ref=True == echtes actions/checkout."""
        git(self.up, "push", "-q", "-f", "origin", pr_branch)
        pr_head = git(self.up, "rev-parse", pr_branch)

        if als_merge_ref:
            # GitHub fabriziert refs/pull/N/merge = merge(main-Spitze, PR-Spitze)
            git(self.up, "checkout", "-q", "--detach", "main")
            git(self.up, "merge", "-q", "--no-ff", pr_head,
                "-m", "Merge %s into main" % pr_head)
            git(self.up, "push", "-q", "-f", "origin", "HEAD:refs/heads/pull-merge")
            ci_ref = "origin/pull-merge"
        else:
            ci_ref = "origin/" + pr_branch

        ci = os.path.join(self.tmp, "ci-%d" % len(os.listdir(self.tmp)))
        subprocess.run(["git", "clone", "-q", self.origin, ci], check=True)
        git(ci, "config", "user.email", "ci@datenschleuse.test")
        git(ci, "config", "user.name", "CI")
        git(ci, "checkout", "-q", "--detach", ci_ref)

        env = dict(os.environ, BASE_REF="main", PR_HEAD_SHA=pr_head)
        proc = subprocess.run(["bash", SCRIPT], cwd=ci, env=env,
                              capture_output=True, text=True)
        return proc.returncode, proc.stdout + proc.stderr


class LaufzettelCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="laufzettel-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.s = Szenario(self.tmp)

    def _pr_mit_vollstaendigem_laufzettel(self):
        self.s.branch("feature/DATENSCHLE-00-demo")
        code = self.s.commit("[DATENSCHLE-00] Feature", {"litellm/guardrail.py": "MASK = 2\n"})
        sec = self.s.verdict("security", code)
        self.s.verdict("qa", sec)
        return "feature/DATENSCHLE-00-demo"

    # --- Richtung 1: vollstaendiger Laufzettel geht durch --------------------

    def test_vollstaendiger_laufzettel_geht_durch(self):
        pr = self._pr_mit_vollstaendigem_laufzettel()
        rc, out = self.s.pruefe(pr)
        self.assertEqual(rc, 0, "Vollstaendiger Laufzettel muss durchgehen:\n" + out)

    # --- Richtung 2: nachtraeglicher Code-Commit wird abgelehnt --------------

    def test_nachtraeglicher_code_commit_wird_abgelehnt(self):
        pr = self._pr_mit_vollstaendigem_laufzettel()
        self.s.commit("[DATENSCHLE-00] Nachtrag nach dem Audit",
                      {"litellm/guardrail.py": "MASK = 3\n"})
        rc, out = self.s.pruefe(pr)
        self.assertNotEqual(rc, 0, "Code nach dem Audit muss abgelehnt werden:\n" + out)
        self.assertIn("litellm/guardrail.py", out,
                      "Die geaenderte Datei wird nicht benannt:\n" + out)

    # --- Richtung 3: Tarnfall (.gates UND Code in einem Commit) -------------

    def test_tarnfall_gates_plus_code_wird_abgelehnt(self):
        pr = self._pr_mit_vollstaendigem_laufzettel()
        # Ein einziger Commit, der wie ein Gate-Commit aussieht, aber Code schmuggelt.
        self.s.write(".gates/security.json", json.dumps(
            {"gate": "security", "verdict": "pass",
             "commit": git(self.s.up, "rev-parse", "HEAD"),
             "branch": "feature/x", "timestamp": "2026-08-20T00:00:00Z"}, indent=2) + "\n")
        self.s.commit("[gate] security: pass (getarnt)",
                      {"litellm/guardrail.py": "MASK = 666  # geschmuggelt\n"})
        rc, out = self.s.pruefe(pr)
        self.assertNotEqual(
            rc, 0,
            "Tarnfall: ein Commit mit .gates UND Code muss als Code-Commit zaehlen:\n" + out)
        # Und zwar aus dem richtigen Grund: der geschmuggelte Code muss benannt sein.
        self.assertIn("litellm/guardrail.py", out,
                      "Der geschmuggelte Code wird nicht benannt:\n" + out)

    # --- Der echte Defekt: fremder Merge auf main --------------------------

    def test_fremder_merge_auf_main_entwertet_das_verdict_nicht(self):
        """Kernbefund DATENSCHLE-76.

        Waehrend unser PR offen ist, mergt ein anderes Lane nach main. Unser
        Branch hat sich nicht veraendert -- das auditierte Artefakt ist
        unveraendert. Der Check darf nicht rot werden.
        """
        pr = self._pr_mit_vollstaendigem_laufzettel()
        self.s.fremder_merge_auf_main()
        rc, out = self.s.pruefe(pr)
        self.assertEqual(
            rc, 0,
            "Fremder Merge auf main darf offene Audits nicht entwerten:\n" + out)

    def test_synthetischer_merge_commit_zaehlt_nicht_als_code_commit(self):
        """Der von GitHub fabrizierte Probe-Merge ist ein CI-Artefakt.

        Niemand hat ihn geschrieben, er steht nicht im PR und ueberlebt den
        Merge nicht. Er darf nicht als 'Code-Commit NACH dem Audit' zaehlen.
        """
        pr = self._pr_mit_vollstaendigem_laufzettel()
        self.s.fremder_merge_auf_main()
        rc, out = self.s.pruefe(pr, als_merge_ref=True)
        self.assertNotIn("Code-Commit(s) NACH dem Audit", out,
                         "Der Probe-Merge wird faelschlich dem PR angelastet:\n" + out)
        self.assertEqual(rc, 0, out)

    # --- fail-closed --------------------------------------------------------

    def test_unbekannter_gepinnter_sha_schlaegt_fehl(self):
        self.s.branch("feature/DATENSCHLE-01-demo")
        code = self.s.commit("[DATENSCHLE-01] Feature", {"litellm/guardrail.py": "MASK = 9\n"})
        self.s.verdict("security", "0" * 40)
        self.s.verdict("qa", code)
        rc, out = self.s.pruefe("feature/DATENSCHLE-01-demo")
        self.assertNotEqual(rc, 0, "Unbekannter gepinnter SHA muss fail-closed sein:\n" + out)

    def test_verdict_fail_schlaegt_fehl(self):
        self.s.branch("feature/DATENSCHLE-02-demo")
        code = self.s.commit("[DATENSCHLE-02] Feature", {"litellm/guardrail.py": "MASK = 8\n"})
        sec = self.s.verdict("security", code, verdict="fail")
        self.s.verdict("qa", sec)
        rc, out = self.s.pruefe("feature/DATENSCHLE-02-demo")
        self.assertNotEqual(rc, 0, "verdict=fail muss rot sein:\n" + out)


if __name__ == "__main__":
    unittest.main()
