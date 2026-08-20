"""Die Nachrichtengrenze ist betreiberseitig einstellbar (DATENSCHLE-69, F8).

Der Befund
----------
``PAYLOAD_MAX_MESSAGES = 256`` war fest verdrahtet. Gemessen: 256 geht durch,
257 blockt. Ein Tool-Zyklus kostet drei Messages (Aufruf, Ergebnis, Antwort),
die Grenze faellt also nach rund 85 Tool-Runden. Fuer Coding-Agenten ist das
der NORMALFALL, nicht der Ausnahmefall.

Und der Ausfall ist TERMINAL: Der Client schickt die volle Historie erneut,
jeder Folge-Request blockt ebenfalls. Die Sitzung ist tot -- ohne einen
Hinweis, was zu tun waere.

Die Entscheidung
----------------
Zwei Teile:

1. Die Grenze wird einstellbar (``DATENSCHLEUSE_MAX_MESSAGES``) und
   grosszuegiger vorbelegt. Seit F3 ist sie ohnehin nicht mehr die
   Kostenbremse -- das ist das Analyzer-Call-Budget. Sie begrenzt jetzt nur
   noch die STRUKTURGROESSE (eine Historie aus 100 000 leeren Nachrichten
   kostet null Analysen, aber sehr wohl Speicher und Traversierungszeit).
2. Die Blockmeldung nennt den Schalter. Eine Grenze, die eine Sitzung
   terminal beendet und verschweigt, was hilft, ist ein Betriebsausfall mit
   Ansage.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.

Ausfuehren (aus dem Repo-Root):
    PYTHONPATH=litellm python3 -m unittest discover -s test \
        -p "test_messages_limit_config.py" -v
"""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402


def _guard(**kwargs):
    kwargs.setdefault("presidio_analyzer_url", "http://presidio.invalid")
    kwargs.setdefault("language", "de")
    kwargs.setdefault("image_policy", "pass")
    guard = dg.DatenschleuseGuardrail(**kwargs)

    async def _keine_entitaeten(text):
        return []

    guard._analyze = _keine_entitaeten
    return guard


def _chat(n):
    return {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": f"Nachricht {i}"} for i in range(n)],
    }


class TestGrenzeIstEinstellbar(unittest.IsolatedAsyncioTestCase):
    async def _run(self, guard, data):
        return await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="acompletion"
        )

    async def test_betreiber_kann_die_grenze_setzen(self):
        guard = _guard(max_messages=3, max_analyzer_calls=10000)
        with self.assertRaises(dg.DatenschleuseBlocked):
            await self._run(guard, _chat(4))

    async def test_auf_der_grenze_geht_durch(self):
        guard = _guard(max_messages=3, max_analyzer_calls=10000)
        await self._run(guard, _chat(3))

    async def test_unsinnige_grenze_bricht_den_start_ab(self):
        with self.assertRaises(dg.DatenschleuseConfigError):
            _guard(max_messages=0)

    def test_vorgabe_ist_grosszuegiger_als_die_alten_256(self):
        """Der eigentliche Betriebsbefund: 256 fiel nach ~85 Tool-Runden.

        Seit F3 ist die Kostenbremse das Analyzer-Budget, nicht diese Zahl --
        sie darf deshalb deutlich hoeher liegen, ohne etwas aufzugeben.
        """
        self.assertGreater(dg.PAYLOAD_MAX_MESSAGES, 256)


class TestBlockmeldungNenntDenSchalter(unittest.IsolatedAsyncioTestCase):
    """Der Ausfall ist terminal: der Client schickt die volle Historie
    erneut, jeder Folge-Request blockt. Wer dann nicht erfaehrt, welcher
    Schalter hilft, hat eine tote Sitzung ohne Diagnose."""

    async def test_meldung_nennt_grenze_und_schalter(self):
        guard = _guard(max_messages=3, max_analyzer_calls=10000)
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=_chat(4),
                call_type="acompletion",
            )
        meldung = str(ctx.exception)
        self.assertIn(dg.MAX_MESSAGES_ENV, meldung, "Der Schalter fehlt")
        self.assertIn("3", meldung, "Die geltende Grenze fehlt")

    async def test_meldung_traegt_keinen_client_inhalt(self):
        guard = _guard(max_messages=1, max_analyzer_calls=10000)
        data = {
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "Max Mustermann, IBAN DE02120300000000202051"},
                {"role": "user", "content": "noch einer"},
            ],
        }
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data,
                call_type="acompletion",
            )
        meldung = str(ctx.exception)
        self.assertNotIn("Mustermann", meldung)
        self.assertNotIn("DE0212", meldung)


if __name__ == "__main__":
    unittest.main()
