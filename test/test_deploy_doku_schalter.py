"""Doku-Falsifikationstest fuer die Betreiber-Schalter (DATENSCHLE-69, F8).

Warum es diese Datei gibt
-------------------------
Gesetz 3: Verhalten geaendert -> Doku zieht mit. Aber eine Doku, die nur
einmal von Hand geschrieben wird, ist genau das, was dieses Projekt schon
mehrfach gebissen hat -- eine ZWEITE Beschreibung derselben Sache, die
auseinanderlaeuft (vgl. F9, und das Analyzer-Budget aus F3).

Und das ist hier nicht theoretisch: Beim Schreiben von docs/DEPLOY.md stand
der Freigabe-Header zuerst als ``X-Datenschleuse-Approval`` drin. Er heisst
in Wirklichkeit ``x-datenschleuse-sensitivity-approval``. Ein Betreiber
haette den Header exakt nach Anleitung gesetzt und waere ohne jede
Fehlermeldung nie freigegeben worden -- der Header waere schlicht nicht
erkannt worden. Dieser Test hat den Fehler gefunden.

Gemessen wird deshalb genau das, was ein Betreiber ABSCHREIBT: die
ENV-Namen, der Header-Name und die Vorgabewerte. Nicht der Prosatext --
der darf sich frei entwickeln.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.

Ausfuehren (aus dem Repo-Root):
    PYTHONPATH=litellm python3 -m unittest discover -s test \
        -p "test_deploy_doku_schalter.py" -v
"""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402
import sensitivity_classifier as sc  # noqa: E402

_DEPLOY = os.path.normpath(os.path.join(_HERE, "..", "docs", "DEPLOY.md"))


def _doku():
    with open(_DEPLOY, encoding="utf-8") as fh:
        return fh.read()


class TestDeployDokuNenntDieSchalter(unittest.TestCase):

    def test_doku_existiert(self):
        """Bauart-Absicherung: ohne Datei misst der Rest nichts."""
        self.assertTrue(os.path.isfile(_DEPLOY), _DEPLOY)
        self.assertGreater(len(_doku()), 500)

    def test_alle_drei_env_namen_stehen_drin(self):
        text = _doku()
        for name in (
            dg.APPROVAL_SECRET_ENV,
            dg.MAX_ANALYZER_CALLS_ENV,
            dg.MAX_MESSAGES_ENV,
        ):
            with self.subTest(env=name):
                self.assertIn(
                    name, text,
                    f"{name} ist im Code ein Betreiber-Schalter, steht aber "
                    "nicht in docs/DEPLOY.md -- wer ihn braucht, findet ihn nicht.",
                )

    def test_header_name_stimmt_mit_dem_code_ueberein(self):
        """DER Fehler, den dieser Test gefunden hat.

        Verglichen wird case-insensitiv: HTTP-Header sind es auch, und die
        Doku schreibt ihn in der ueblichen Grossschreibung.
        """
        self.assertIn(
            sc.APPROVAL_HEADER.lower(), _doku().lower(),
            "Der in der Doku genannte Freigabe-Header stimmt nicht mit "
            "sensitivity_classifier.APPROVAL_HEADER ueberein. Ein Betreiber, "
            "der ihn abschreibt, wird ohne Fehlermeldung nie freigegeben.",
        )

    def test_vorgabewerte_stimmen_mit_dem_code_ueberein(self):
        """Eine Doku, die einen anderen Default nennt als der Code, ist
        schlimmer als keine: sie wird geglaubt."""
        text = _doku()
        for wert in (dg.PAYLOAD_MAX_ANALYZER_CALLS, dg.PAYLOAD_MAX_MESSAGES):
            with self.subTest(default=wert):
                self.assertIn(
                    str(wert), text,
                    f"Der Default {wert} steht im Code, aber nicht in der Doku.",
                )

    def test_mindestlaenge_des_geheimnisses_steht_drin(self):
        self.assertIn(
            str(dg.APPROVAL_SECRET_MIN_LEN), _doku(),
            "Die Mindestlaenge bricht den START ab -- sie gehoert in die "
            "Doku, nicht nur in die Fehlermeldung.",
        )

    def test_erzeugungsbefehl_steht_daneben(self):
        """Eine Anleitung, die nur eine Anforderung nennt, laesst den
        Betreiber raten -- und er raet etwas, das gerade so durchkommt."""
        self.assertIn("secrets.token_urlsafe", _doku())


if __name__ == "__main__":
    unittest.main()
