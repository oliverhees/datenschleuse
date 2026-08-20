"""Tests fuer das Stop-Gate ueber Worktree-Grenzen hinweg (DATENSCHLE-79).

Ausgangslage: In diesem Projekt arbeiten mehrere Agenten gleichzeitig in
eigenen Worktrees unter `.claude/worktrees/agent-*`. Die Hooks werden fuer
alle aus derselben Hauptauscheckung gestartet, und `CLAUDE_PROJECT_DIR`
zeigt fuer alle auf ebendiese. `track.sh` legte seine Marker deshalb in
EIN gemeinsames Verzeichnis:

    $CLAUDE_PROJECT_DIR/.claude/.last_code_edit
    $CLAUDE_PROJECT_DIR/.claude/.last_test_run

Damit bewertete `stop-gate.sh` fremde Laeufe als eigene. Ein roter Test in
Worktree A blockierte die Session in Worktree B — obwohl Gesetz 2 diesen
roten Test ausdruecklich VERLANGT (erst rot, dann Implementierung). Der
Waechter schlug an einem Tag sechsmal grundlos an und hat dabei nie einen
echten Fehler gefangen.

Warum das mehr ist als laestig: Ein Alarm, der regelmaessig ohne Anlass
schrillt, wird reflexhaft weggeklickt. Dann faengt er auch den einen Fall
nicht mehr, fuer den er gebaut wurde.

Diese Suite faehrt die ECHTEN Hook-Skripte als Subprozess gegen echte
Wegwerf-Repos mit echten `git worktree`-Auscheckungen — die Logik wird
nicht in Python nachgebaut. Beide Richtungen werden geprueft: fremd darf
nicht blocken, eigen MUSS weiter blocken.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _hooks_dir():
    """Findet .claude/hooks — auch aus einem Worktree heraus.

    Die Hooks liegen in der Hauptauscheckung und sind (per .gitignore)
    nicht Teil des Repos. `--git-common-dir` zeigt aus jedem Worktree auf
    das gemeinsame .git der Hauptauscheckung; deren Elternverzeichnis ist
    die Auscheckung selbst.
    """
    try:
        common = subprocess.run(
            ["git", "rev-parse", "--git-common-dir"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, OSError):
        return None
    if not common:
        return None
    haupt = os.path.dirname(os.path.abspath(os.path.join(REPO_ROOT, common)))
    return os.path.join(haupt, ".claude", "hooks")


HOOKS = _hooks_dir()
TRACK = os.path.join(HOOKS, "track.sh") if HOOKS else ""
STOP_GATE = os.path.join(HOOKS, "stop-gate.sh") if HOOKS else ""

# Wortlaut eines echten roten unittest-Laufs aus dieser Codebase. Durch
# "| tail -40" endet die Pipeline mit Exit 0 — der Kommandostring allein
# beweist also nichts, das Fazit in der Ausgabe schon (DATENSCHLE-55).
ROTER_LAUF_CMD = 'PYTHONPATH=litellm python3 -m unittest discover -s test 2>&1 | tail -40'
ROTER_LAUF_OUT = (
    "======================================================================\n"
    "FAIL: test_beispiel (test_x.Beispiel)\n"
    "----------------------------------------------------------------------\n"
    "Ran 381 tests in 6.495s\n"
    "\n"
    "FAILED (failures=5)"
)
GRUENER_LAUF_CMD = 'PYTHONPATH=litellm python3 -m unittest discover -s test'
GRUENER_LAUF_OUT = "Ran 381 tests in 6.495s\n\nOK (skipped=1)"


def git(cwd, *args):
    return subprocess.run(
        ["git"] + list(args),
        cwd=cwd, check=True, capture_output=True, text=True,
    ).stdout.strip()


class Schmiede:
    """Baut die echte Topologie nach: eine Hauptauscheckung, viele Worktrees."""

    def __init__(self, tmp):
        self.tmp = tmp
        # Entspricht CLAUDE_PROJECT_DIR: fuer ALLE Agenten dasselbe.
        self.projekt = os.path.join(tmp, "datenschleuse")
        os.makedirs(self.projekt)
        subprocess.run(["git", "init", "-q", "-b", "main", self.projekt], check=True)
        git(self.projekt, "config", "user.email", "team@datenschleuse.test")
        git(self.projekt, "config", "user.name", "Schmiede")
        os.makedirs(os.path.join(self.projekt, "litellm"))
        with open(os.path.join(self.projekt, "litellm", "guardrail.py"), "w",
                  encoding="utf-8") as fh:
            fh.write("MASK = 1\n")
        git(self.projekt, "add", "-A")
        git(self.projekt, "commit", "-qm", "base")
        os.makedirs(os.path.join(self.projekt, ".claude", "worktrees"))
        self.track = TRACK
        self.stop_gate = STOP_GATE

    def worktree(self, name):
        """Legt einen Agenten-Worktree an — dort, wo sie real liegen."""
        pfad = os.path.join(self.projekt, ".claude", "worktrees", "agent-" + name)
        git(self.projekt, "worktree", "add", "-q", "-b", "feature/" + name, pfad)
        return pfad

    # --- Hook-Aufrufe -----------------------------------------------------

    def ohne_scope_sh(self):
        """Installiert die Hooks OHNE den Helfer -- wie eine unvollstaendige
        Kopie, bei der die neue Datei vergessen wurde."""
        hooks = os.path.join(self.tmp, "hooks-ohne-scope")
        os.makedirs(hooks, exist_ok=True)
        for skript in (TRACK, STOP_GATE):
            shutil.copy(skript, hooks)
        self.track = os.path.join(hooks, os.path.basename(TRACK))
        self.stop_gate = os.path.join(hooks, os.path.basename(STOP_GATE))

    def _hook(self, skript, payload, cwd):
        """Faehrt einen Hook exakt so, wie Claude Code ihn faehrt.

        Der Payload traegt `cwd`, und der Prozess laeuft im selben
        Verzeichnis — beides empirisch am echten Payload verifiziert.
        """
        return subprocess.run(
            ["bash", skript],
            input=json.dumps(payload), cwd=cwd,
            env=dict(os.environ, CLAUDE_PROJECT_DIR=self.projekt),
            capture_output=True, text=True,
        )

    def code_aenderung(self, wt):
        """Eine Quellcode-Aenderung in genau diesem Worktree."""
        self._hook(self.track, {
            "tool_name": "Edit", "hook_event_name": "PostToolUse", "cwd": wt,
            "tool_input": {"file_path": os.path.join(wt, "litellm", "guardrail.py")},
            "tool_response": {},
        }, wt)
        time.sleep(0.05)   # damit die Zeitpruefung im Gate eindeutig bleibt

    def testlauf(self, wt, cmd, ausgabe):
        """Ein Testlauf in genau diesem Worktree."""
        self._hook(self.track, {
            "tool_name": "Bash", "hook_event_name": "PostToolUse", "cwd": wt,
            "tool_input": {"command": cmd},
            "tool_response": {"stdout": ausgabe, "stderr": "", "interrupted": False,
                              "isImage": False, "noOutputExpected": False},
        }, wt)
        time.sleep(0.05)

    def roter_lauf(self, wt):
        self.testlauf(wt, ROTER_LAUF_CMD, ROTER_LAUF_OUT)

    def gruener_lauf(self, wt):
        self.testlauf(wt, GRUENER_LAUF_CMD, GRUENER_LAUF_OUT)

    def stop(self, wt, aktiv=False, mit_cwd=True):
        """Die Session in diesem Worktree will enden. 0 = darf, 2 = blockiert."""
        payload = {"hook_event_name": "Stop", "stop_hook_active": aktiv}
        if mit_cwd:
            payload["cwd"] = wt
        proc = self._hook(self.stop_gate, payload, wt)
        return proc.returncode, proc.stdout + proc.stderr


@unittest.skipUnless(
    HOOKS and os.path.exists(STOP_GATE) and os.path.exists(TRACK),
    ".claude/hooks/ nicht vorhanden (per .gitignore nicht im Repo)",
)
class StopGateWorktreeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="stopgate-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.s = Schmiede(self.tmp)
        self.a = self.s.worktree("aaa")   # fremde Lane
        self.b = self.s.worktree("bbb")   # unsere Session

    # --- Richtung 1: fremde Lanes duerfen uns nicht blockieren -------------

    def test_roter_lauf_im_fremden_worktree_blockt_uns_nicht(self):
        """Der Kernbefund. A macht TDD (roter Test = Vorschrift), B will enden."""
        self.s.code_aenderung(self.a)
        self.s.roter_lauf(self.a)

        rc, out = self.s.stop(self.b)
        self.assertEqual(
            rc, 0,
            "Ein roter Lauf in einem FREMDEN Worktree blockiert unsere "
            "Session — genau der Fehlalarm aus DATENSCHLE-79:\n" + out)

    def test_fremde_code_aenderung_ohne_testlauf_blockt_uns_nicht(self):
        """Zweite Bedingung, Variante 'nie getestet'.

        A hat gerade Code angefasst und noch nicht getestet. Fuer B ist das
        voellig belanglos.
        """
        self.s.code_aenderung(self.a)

        rc, out = self.s.stop(self.b)
        self.assertEqual(
            rc, 0,
            "Eine fremde Code-Aenderung blockiert unsere Session:\n" + out)

    def test_fremde_code_aenderung_entwertet_unseren_gruenen_lauf_nicht(self):
        """Zweite Bedingung, Variante 'Aenderung nach dem Lauf'.

        B ist sauber fertig: Aenderung, danach gruener Lauf. Erst DANACH
        fasst A Code an. Das darf B nicht rueckwirkend entwerten.
        """
        self.s.code_aenderung(self.b)
        self.s.gruener_lauf(self.b)
        self.s.code_aenderung(self.a)

        rc, out = self.s.stop(self.b)
        self.assertEqual(
            rc, 0,
            "Eine fremde Code-Aenderung nach unserem gruenen Lauf entwertet "
            "ihn:\n" + out)

    # --- Richtung 2: der Waechter bleibt scharf ----------------------------
    #
    # Ohne diese Faelle waere das Gate nicht geschaerft, sondern abgeschafft.

    def test_eigener_roter_lauf_blockt_weiterhin(self):
        """Wer im EIGENEN Worktree rot hinterlaesst, kommt nicht raus."""
        self.s.code_aenderung(self.b)
        self.s.roter_lauf(self.b)

        rc, out = self.s.stop(self.b)
        self.assertEqual(
            rc, 2,
            "Der eigene rote Lauf muss die eigene Session blockieren "
            "(Gesetz 2) — sonst ist das Gate abgeschafft:\n" + out)
        self.assertIn("ROT", out, "Die Begruendung nennt den roten Lauf nicht:\n" + out)

    def test_eigene_code_aenderung_ohne_testlauf_blockt_weiterhin(self):
        """Code angefasst, nie getestet — im eigenen Worktree ein Block."""
        self.s.code_aenderung(self.b)

        rc, out = self.s.stop(self.b)
        self.assertEqual(
            rc, 2,
            "Eigene ungetestete Code-Aenderung muss blocken:\n" + out)

    def test_eigene_code_aenderung_nach_gruenem_lauf_blockt_weiterhin(self):
        """Zweite Bedingung, Gegenprobe: der eigene Nachtrag entwertet gruen."""
        self.s.code_aenderung(self.b)
        self.s.gruener_lauf(self.b)
        self.s.code_aenderung(self.b)

        rc, out = self.s.stop(self.b)
        self.assertEqual(
            rc, 2,
            "Eigene Code-Aenderung nach dem gruenen Lauf muss blocken:\n" + out)

    def test_eigener_gruener_lauf_laesst_uns_gehen(self):
        """Und der Normalfall bleibt reibungsfrei."""
        self.s.code_aenderung(self.b)
        self.s.gruener_lauf(self.b)

        rc, out = self.s.stop(self.b)
        self.assertEqual(rc, 0, "Gruener eigener Lauf muss durchgehen:\n" + out)

    # --- Robustheit der Zuordnung -----------------------------------------

    def test_ohne_cwd_im_payload_entscheidet_das_arbeitsverzeichnis(self):
        """Die Zuordnung darf nicht an einem einzelnen Payload-Feld haengen.

        Am echten PostToolUse-Payload ist `cwd` nachweislich vorhanden. Faellt
        es dennoch weg (aeltere CLI, anderes Event), muss das Prozess-Arbeits-
        verzeichnis dasselbe Ergebnis liefern — sonst kippt die Zuordnung
        stillschweigend zurueck auf 'alle teilen sich einen Marker'.
        """
        self.s.code_aenderung(self.b)
        self.s.gruener_lauf(self.b)
        self.s.code_aenderung(self.a)
        self.s.roter_lauf(self.a)

        rc, out = self.s.stop(self.b, mit_cwd=False)
        self.assertEqual(rc, 0, "Ohne cwd faellt die Zuordnung auf den "
                                "gemeinsamen Marker zurueck:\n" + out)

        # Gegenprobe: ohne cwd bleibt der EIGENE rote Lauf trotzdem ein Block.
        self.s.roter_lauf(self.b)
        rc, out = self.s.stop(self.b, mit_cwd=False)
        self.assertEqual(rc, 2, "Ohne cwd wird der eigene rote Lauf "
                                "uebersehen:\n" + out)

    def test_ohne_scope_sh_bleibt_das_gate_scharf(self):
        """Die Zuordnung bringt eine neue Abhaengigkeit mit -- und damit eine
        neue Absturzstelle.

        Die Hooks liegen ausserhalb von Git und werden von Hand kopiert.
        Wird scope.sh dabei vergessen, ist `marker_dir` keine Funktion, der
        Markerpfad waere leer und das Gate faende schlicht nichts mehr vor:
        es wuerde JEDE Session durchwinken, ohne ein Wort zu sagen. Ein
        stiller Totalausfall des Waechters ist schlimmer als der Fehlalarm,
        den dieses Ticket behebt. Fehlt der Helfer, faellt das Gate deshalb
        auf den gemeinsamen Marker zurueck: laut, aber scharf.
        """
        self.s.ohne_scope_sh()
        self.s.code_aenderung(self.b)
        self.s.roter_lauf(self.b)

        rc, out = self.s.stop(self.b)
        self.assertEqual(
            rc, 2,
            "Ohne scope.sh laesst das Gate einen roten Lauf durch — es ist "
            "dann lautlos abgeschaltet:\n" + out)

    def test_unbeschreibbares_scopes_verzeichnis_oeffnet_das_gate_nicht(self):
        """Kann das Markerverzeichnis nicht angelegt werden, darf der Pfad
        nicht trotzdem zurueckgegeben werden.

        Sonst laufen alle Schreibvorgaenge ins Leere, das Gate findet nichts
        vor und haelt die Lane fuer sauber -- ein Fail-Open, das es vor der
        Eingrenzung nicht gab (das Basisverzeichnis existierte immer).
        """
        scopes = os.path.join(self.s.projekt, ".claude", "scopes")
        os.makedirs(scopes, exist_ok=True)
        os.chmod(scopes, 0o555)
        self.addCleanup(os.chmod, scopes, 0o755)

        self.s.code_aenderung(self.b)
        self.s.roter_lauf(self.b)

        rc, out = self.s.stop(self.b)
        self.assertEqual(
            rc, 2,
            "Unbeschreibbares scopes-Verzeichnis laesst einen roten Lauf "
            "durch:\n" + out)

    def test_aufgebrauchter_zaehler_oeffnet_die_lane_nicht_dauerhaft(self):
        """Die Notbremse darf einmal pro Blockade greifen, nicht ein fuer alle Mal.

        Das Gate gibt nach MAX_BLOCKS Ablehnungen frei, damit keine Session
        haengenbleibt. Bleibt der Zaehler danach stehen, ist die Lane
        dauerhaft offen: jeder weitere Stop liest den vollen Zaehler und
        kommt beim ERSTEN Versuch durch -- ueber Session-Grenzen hinweg,
        weil die Zaehlerdatei im Markerverzeichnis liegen bleibt.
        """
        self.s.code_aenderung(self.b)
        self.s.roter_lauf(self.b)

        letzter = None
        for _ in range(10):
            letzter, _out = self.s.stop(self.b)
        self.assertEqual(letzter, 0, "Notbremse hat gar nicht ausgeloest")

        # Neuer Stop, unveraendert roter Stand: die Blockade beginnt von vorn.
        rc, out = self.s.stop(self.b)
        self.assertEqual(
            rc, 2,
            "Der aufgebrauchte Zaehler laesst die Lane dauerhaft offen — "
            "roter Lauf, und das Gate winkt sofort durch:\n" + out)

    # --- Der stille Fail-Open ---------------------------------------------

    def test_fremde_blocks_kaufen_uns_nicht_frei(self):
        """Auch der Ablehnungszaehler gehoert dem Worktree, nicht dem Projekt.

        Das Gate gibt nach MAX_BLOCKS Ablehnungen frei, damit keine Session
        haengenbleibt. Teilen sich alle Worktrees diesen Zaehler, dann
        verbrauchen die Ablehnungen der einen Lane das Kontingent der
        anderen — und B faellt beim ERSTEN eigenen Block heraus, obwohl
        sein Lauf rot ist. Das ist die gefaehrliche Richtung: ein Gate, das
        oeffnet, wo es schliessen muesste.

        Die Reihenfolge ist Absicht: B wird zuerst rot, dann arbeitet A.
        So ist der gemeinsame Zaehler juenger als Bs Code-Aenderung und die
        eingebaute Zaehler-Ruecksetzung greift nicht mehr.
        """
        self.s.code_aenderung(self.b)
        self.s.roter_lauf(self.b)

        self.s.code_aenderung(self.a)
        self.s.roter_lauf(self.a)
        for _ in range(9):
            self.s.stop(self.a)

        rc, out = self.s.stop(self.b)
        self.assertEqual(
            rc, 2,
            "Fremde Ablehnungen haben unser Block-Kontingent verbraucht — "
            "das Gate oeffnet trotz rotem eigenen Lauf:\n" + out)


if __name__ == "__main__":
    unittest.main()
