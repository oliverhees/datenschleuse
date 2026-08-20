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
import sys
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

HOOKS_VORHANDEN = bool(HOOKS and os.path.exists(STOP_GATE) and os.path.exists(TRACK))
IN_CI = os.environ.get("CI", "").strip().lower() not in ("", "0", "false", "no")


def hook_verfuegbarkeit(vorhanden, in_ci):
    """laufen | ueberspringen | warnen

    Die Hooks liegen ausserhalb von Git (.claude/ steht in .gitignore).
    Lokal ist ein Ueberspringen ehrlich: wer die Hooks nicht installiert
    hat, kann sie nicht pruefen. In CI ist ein wortloses Ueberspringen das
    Gegenteil von ehrlich -- dort fehlen die Hooks IMMER und die Suite
    meldete trotzdem gruen. Ein Test, der gruen meldet, ohne etwas zu
    pruefen, ist schlimmer als kein Test: er erzeugt Vertrauen ohne
    Deckung. Daran ist schon DATENSCHLE-62 haengengeblieben.

    Warum trotzdem nicht rot? Weil `test` ein erforderlicher Check ist.
    Ein dauerhaft roter Job blockiert JEDEN PR -- wegen einer Luecke, die
    laengst bekannt ist. Ein Gate, das an einer bekannten, noch nicht
    behobenen Luecke scheitert, wird abgeschaltet; dann faengt es auch den
    Fall nicht mehr, fuer den es da ist. Erst die Voraussetzung schaffen
    (Hooks versionieren), dann scharf schalten.

    Also: laut warnen, nicht blockieren. Die Faelle in
    HookVerfuegbarkeitTest bleiben davon unberuehrt -- sie laufen immer.
    """
    if vorhanden:
        return "laufen"
    return "warnen" if in_ci else "ueberspringen"


def warnung_text():
    """Der Wortlaut der Warnung. Muss Ursache UND Abhilfe nennen."""
    return (
        "Die Stop-Gate-Tests haben hier KEINE Deckung: .claude/hooks/ fehlt, "
        "es wurde nichts geprueft. "
        "Ursache: .claude/ steht in der .gitignore, die Hooks sind nicht "
        "versioniert. "
        "Abhilfe: Hooks an einen getrackten Ort legen, dann laufen diese "
        "Tests in CI wirklich mit."
    )


_gewarnt = False


def warnung_ausgeben():
    """Einmal pro Lauf, unuebersehbar, auf stderr.

    Ein einzelnes 's' in der Punktzeile uebersieht jeder. Deshalb ein
    Kasten -- und in GitHub Actions zusaetzlich eine Annotation, die im
    PR sichtbar wird, ohne den Job rot zu faerben.
    """
    global _gewarnt
    if _gewarnt:
        return
    _gewarnt = True
    rand = "!" * 78
    print("\n" + rand, file=sys.stderr)
    print("!! WARNUNG: TESTS OHNE DECKUNG", file=sys.stderr)
    for zeile in warnung_text().split(". "):
        if zeile.strip():
            print("!! " + zeile.strip().rstrip(".") + ".", file=sys.stderr)
    print(rand + "\n", file=sys.stderr)
    if os.environ.get("GITHUB_ACTIONS"):
        print("::warning title=Stop-Gate-Tests ohne Deckung::" + warnung_text(),
              file=sys.stderr)


class HookVerfuegbarkeitTest(unittest.TestCase):
    """Laeuft IMMER -- auch dort, wo die Hooks fehlen.

    Dieser Fall ist der Waechter ueber dem Waechter: Er haelt fest, dass die
    Suite sich in CI nicht selbst stumm schalten darf.
    """

    def test_mit_hooks_wird_gelaufen(self):
        self.assertEqual(hook_verfuegbarkeit(True, False), "laufen")
        self.assertEqual(hook_verfuegbarkeit(True, True), "laufen")

    def test_ohne_hooks_lokal_wird_uebersprungen(self):
        self.assertEqual(hook_verfuegbarkeit(False, False), "ueberspringen")

    def test_ohne_hooks_in_ci_wird_laut_gewarnt(self):
        self.assertEqual(
            hook_verfuegbarkeit(False, True), "warnen",
            "In CI darf die Suite sich nicht STUMM ueberspringen -- dann "
            "prueft sie nichts und niemand merkt es.")

    def test_die_warnung_nennt_ursache_und_abhilfe(self):
        """Eine Warnung ohne Abhilfe wird zur Tapete und dann weggeklickt."""
        text = warnung_text()
        self.assertIn("gitignore", text, "Die Ursache fehlt: " + text)
        self.assertIn("Abhilfe", text, "Die Abhilfe fehlt: " + text)
        self.assertIn("nichts geprueft", text,
                      "Die Warnung sagt nicht, dass nichts geprueft wurde: " + text)

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

    def code_aenderung(self, wt, aus=None):
        """Eine Quellcode-Aenderung in diesem Worktree.

        `aus` erlaubt, den Hook aus einem Unterverzeichnis zu fahren -- so
        arbeitet eine Session, die per cd tiefer gewechselt ist.
        """
        cwd = aus or wt
        self._hook(self.track, {
            "tool_name": "Edit", "hook_event_name": "PostToolUse", "cwd": cwd,
            "tool_input": {"file_path": os.path.join(wt, "litellm", "guardrail.py")},
            "tool_response": {},
        }, cwd)
        time.sleep(0.05)   # damit die Zeitpruefung im Gate eindeutig bleibt

    def testlauf(self, wt, cmd, ausgabe, aus=None):
        """Ein Testlauf in diesem Worktree."""
        cwd = aus or wt
        self._hook(self.track, {
            "tool_name": "Bash", "hook_event_name": "PostToolUse", "cwd": cwd,
            "tool_input": {"command": cmd},
            "tool_response": {"stdout": ausgabe, "stderr": "", "interrupted": False,
                              "isImage": False, "noOutputExpected": False},
        }, cwd)
        time.sleep(0.05)

    def roter_lauf(self, wt, aus=None):
        self.testlauf(wt, ROTER_LAUF_CMD, ROTER_LAUF_OUT, aus=aus)

    def gruener_lauf(self, wt, aus=None):
        self.testlauf(wt, GRUENER_LAUF_CMD, GRUENER_LAUF_OUT, aus=aus)

    def marker_datei(self, wt, name=".last_test_run"):
        """Fragt den Hook-Helfer selbst nach dem Pfad.

        Den Schluessel hier nachzubauen waere ein Eigentor: Er koennte sich
        aendern, der Nachbau bliebe gruen und pruefte ins Leere.
        """
        scope = os.path.join(os.path.dirname(self.track), "scope.sh")
        pfad = subprocess.run(
            ["bash", "-c", '. "$1"; marker_dir "$2" "$3"', "_", scope,
             os.path.join(self.projekt, ".claude"), wt],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        return os.path.join(pfad, name)

    def stop(self, wt, aktiv=False, mit_cwd=True):
        """Die Session in diesem Worktree will enden. 0 = darf, 2 = blockiert."""
        payload = {"hook_event_name": "Stop", "stop_hook_active": aktiv}
        if mit_cwd:
            payload["cwd"] = wt
        proc = self._hook(self.stop_gate, payload, wt)
        return proc.returncode, proc.stdout + proc.stderr


class StopGateWorktreeTest(unittest.TestCase):
    def setUp(self):
        lage = hook_verfuegbarkeit(HOOKS_VORHANDEN, IN_CI)
        if lage == "warnen":
            warnung_ausgeben()
            self.skipTest(warnung_text())
        if lage == "ueberspringen":
            self.skipTest(".claude/hooks/ nicht vorhanden (nicht im Repo)")
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

    def test_schluessel_ist_die_worktree_wurzel_nicht_das_cwd(self):
        """Die zentrale Design-Entscheidung dieses Tickets.

        Eine Session, die per cd in ein Unterverzeichnis gewechselt ist,
        gehoert weiter zu ihrer Lane. Waere der Schluessel das rohe cwd,
        zaehlte jedes Unterverzeichnis als eigene Lane -- ein roter Lauf
        waere durch ein blosses `cd` entwertet, und zwar lautlos.

        Ohne diesen Fall koennte jemand marker_dir auf das cwd vereinfachen
        und alle uebrigen Tests blieben gruen.
        """
        unter = os.path.join(self.b, "litellm")
        self.s.code_aenderung(self.b, aus=unter)
        self.s.roter_lauf(self.b, aus=unter)

        rc, out = self.s.stop(self.b)
        self.assertEqual(
            rc, 2,
            "Ein roter Lauf aus einem Unterverzeichnis zaehlt nicht mehr zur "
            "eigenen Lane — ein `cd` entwertet damit den Testnachweis:\n" + out)

    def test_beweisstueck_nennt_den_commit_des_eigenen_worktrees(self):
        """Der Marker soll belegen, WORAUF der Lauf stattfand.

        Notiert wird stattdessen der HEAD der Hauptauscheckung. In einem
        Worktree, der auf einem anderen Stand sitzt, nennt die Blockmeldung
        damit einen Commit, den der Testlauf nie beruehrt hat.
        """
        git(self.b, "commit", "-q", "--allow-empty", "-m", "[DATENSCHLE-00] eigener Stand")
        eigener = git(self.b, "rev-parse", "HEAD")
        haupt = git(self.s.projekt, "rev-parse", "HEAD")
        self.assertNotEqual(eigener, haupt, "Testaufbau: Staende muessen abweichen")

        self.s.gruener_lauf(self.b)

        with open(self.s.marker_datei(self.b), encoding="utf-8") as fh:
            notiert = json.load(fh)["sha"]
        self.assertEqual(
            notiert, eigener,
            "Das Beweisstueck nennt den HEAD der Hauptauscheckung statt den "
            "des Worktrees, in dem der Lauf stattfand.")

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
