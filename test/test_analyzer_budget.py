"""Das Analyzer-Call-Budget (DATENSCHLE-69, Runde 4, F3).

Der Befund
----------
Die Grenze sass auf der falschen Einheit. ``PAYLOAD_MAX_MESSAGES`` begrenzt
NACHRICHTEN -- aber eine einzelne Nachricht kann beliebig viele
Analyzer-Aufrufe kosten. Gemessen (Auditor, Runde 4, Request geht DURCH,
kein Block)::

    1 Message, 2000 Parts       ->   2 000 Calls   47,2 s
    tools[] mit 200             ->   1 400 Calls   33,5 s
    1 Message, 20 000 Parts     ->  20 000 Calls   ~8 min
    tools[] mit 20 000          -> 140 002 Calls   ~55 min
    20 000 tool_calls           ->  80 000 Calls   ~31 min

Und die Blockmeldung behauptete dabei woertlich "Jede Message kostet eine
eigene Analyse". Das stimmt nicht -- eine Message kostet 20 000.
``PAYLOAD_MAX_MESSAGES = 256`` multipliziert das noch: 256 x 2000 Parts sind
rund 3,4 STUNDEN aus einem einzigen Request.

Die Entscheidung
----------------
Keine drei neuen Einzelgrenzen (Parts, tools, tool_calls). Die schliessen drei
Symptome und lassen die Ebene offen, die morgen dazukommt. Stattdessen ein
BUDGET auf der Einheit, die die Kosten wirklich treibt: dem Analyzer-Aufruf.

ZWEI Schranken, nicht eine -- und das ist der Punkt dieser Datei:

1. Die VORAB-Schaetzung im Validate-Pfad blockt die pathologische Payload zum
   Nulltarif, bevor der erste Aufruf passiert.
2. Der LAUFZEIT-Zaehler in ``_analyze`` ist der Backstop. Er sitzt an der
   Engstelle, durch die jeder Aufruf muss, und zaehlt was PASSIERT statt was
   jemand vorhergesehen hat.

Warum beide: Eine Vorab-Zaehlung ist eine ZWEITE BESCHREIBUNG derselben
Traversierung. Genau diese Bauart hat dieses Projekt schon dreimal gebissen
(es ist F9 aus demselben Bericht: zwei handgepflegte Tupel, die auseinander-
laufen). Traegt jemand morgen ein Feld in den Masker ein und vergisst den
Schaetzer, zaehlt das Budget zu wenig und schuetzt still nicht mehr.

Der Test ``TestSchaetzungDecktDieWirklichkeit`` bindet beide zusammen:
Schaetzung >= tatsaechliche Aufrufe. Laufen sie auseinander, wird er ROT --
statt dass der Betrieb still unsicher wird.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.

Ausfuehren (aus dem Repo-Root):
    PYTHONPATH=litellm python3 -m unittest discover -s test \
        -p "test_analyzer_budget.py" -v
"""

import json
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
    return dg.DatenschleuseGuardrail(**kwargs)


class _ZaehlenderGuard:
    """Ersetzt ``_analyze`` durch einen Zaehler -- misst, wie viele Aufrufe
    der Maskierungspfad WIRKLICH macht.

    Bewusst nicht nur zaehlen, sondern auch ``_spend_analyzer_call()``
    aufrufen: sonst waere der Laufzeit-Backstop im Test versehentlich
    uebersprungen, und die Datei wuerde ihn gar nicht messen.
    """

    def __init__(self, guard):
        self.guard = guard
        self.calls = 0

        async def _zaehlend(text):
            if not text or not text.strip():
                return []
            self.calls += 1
            guard._spend_analyzer_call()
            return []

        guard._analyze = _zaehlend


def _chat(messages, **extra):
    data = {"model": "gpt-4o", "messages": messages}
    data.update(extra)
    return data


def _parts(n):
    """Eine EINZIGE Message mit n Text-Parts -- der Befund in Reinform."""
    return [{
        "role": "user",
        "content": [{"type": "text", "text": f"Text Nummer {i}"} for i in range(n)],
    }]


def _tool_calls(n):
    return [{
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": f"call_{i:04d}",
                "type": "function",
                "function": {"name": "f", "arguments": json.dumps({"k": f"v{i}"})},
            }
            for i in range(n)
        ],
    }]


class TestBudgetGreiftVorDemErstenAufruf(unittest.IsolatedAsyncioTestCase):
    """DER Befund: der neunte Weg. Eine Message, beliebig viele Aufrufe."""

    async def _run(self, data, guard=None):
        guard = guard or _guard()
        return await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="acompletion"
        )

    async def test_eine_message_mit_2000_parts_blockt(self):
        guard = _guard()
        zaehler = _ZaehlenderGuard(guard)
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await self._run(_chat(_parts(2000)), guard=guard)
        # ZUM NULLTARIF: der Block passiert VOR dem ersten Aufruf.
        self.assertEqual(
            zaehler.calls, 0,
            "Der Block muss vor dem ersten Analyzer-Aufruf greifen, "
            "sonst verhindert er genau das nicht, wogegen er gebaut ist.",
        )
        self.assertIn("Analyse", str(ctx.exception))

    async def test_tools_mit_20000_eintraegen_blockt(self):
        guard = _guard()
        zaehler = _ZaehlenderGuard(guard)
        tools = [
            {"type": "function",
             "function": {"name": f"f{i}", "description": f"macht Sache {i}"}}
            for i in range(20000)
        ]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await self._run(
                _chat([{"role": "user", "content": "Hi"}], tools=tools), guard=guard
            )
        self.assertEqual(zaehler.calls, 0)

    async def test_20000_tool_calls_blockt(self):
        guard = _guard()
        zaehler = _ZaehlenderGuard(guard)
        with self.assertRaises(dg.DatenschleuseBlocked):
            await self._run(_chat(_tool_calls(20000)), guard=guard)
        self.assertEqual(zaehler.calls, 0)

    async def test_normaler_request_sieht_das_budget_nie(self):
        """Gegenprobe. Ohne sie misst die Datei nur, dass irgendetwas blockt."""
        guard = _guard()
        zaehler = _ZaehlenderGuard(guard)
        await self._run(
            _chat([{"role": "user", "content": f"Nachricht {i}"} for i in range(5)]),
            guard=guard,
        )
        self.assertLessEqual(zaehler.calls, 20)


class TestBlockmeldung(unittest.IsolatedAsyncioTestCase):
    """Die Lehre aus den 256 Nachrichten: eine Grenze, die den Schalter nicht
    nennt, macht die Sitzung tot, ohne zu sagen was hilft."""

    async def _block(self, data):
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await _guard().async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data,
                call_type="acompletion",
            )
        return str(ctx.exception)

    async def test_meldung_nennt_grenze_bedarf_und_schalter(self):
        meldung = await self._block(_chat(_parts(2000)))
        self.assertIn(str(dg.PAYLOAD_MAX_ANALYZER_CALLS), meldung)
        self.assertIn("2000", meldung, "Der tatsaechliche Bedarf fehlt")
        self.assertIn(dg.MAX_ANALYZER_CALLS_ENV, meldung, "Der Schalter fehlt")

    async def test_meldung_traegt_keinen_client_inhalt(self):
        """Gesetz 5: nur Anzahlen, nie ein Wert aus der Payload."""
        geheim = "Max Mustermann IBAN DE02120300000000202051"
        msgs = [{
            "role": "user",
            "content": [{"type": "text", "text": geheim} for _ in range(2000)],
        }]
        meldung = await self._block(_chat(msgs))
        self.assertNotIn("Mustermann", meldung)
        self.assertNotIn("DE0212", meldung)


class TestLaufzeitBackstop(unittest.IsolatedAsyncioTestCase):
    """Die Schranke, die NICHT driften kann.

    Gemessen wird sie, indem der Schaetzer absichtlich blind gemacht wird --
    genau der Fall, den es zu ueberleben gilt: jemand baut ein neues Feld in
    den Masker ein und vergisst den Schaetzer.
    """

    async def test_zaehler_blockt_auch_wenn_der_schaetzer_zu_wenig_zaehlt(self):
        guard = _guard()

        # Der Schaetzer luegt: er meldet immer 0. Ohne Backstop liefe der
        # Request jetzt unbegrenzt durch.
        guard._count_analyzer_calls = lambda *a, **k: 0

        aufrufe = {"n": 0}

        async def _zaehlend(text):
            if not text or not text.strip():
                return []
            # Erst verbrauchen, dann zaehlen: der Aufruf, an dem das
            # Budget zuschlaegt, hat nie stattgefunden.
            guard._spend_analyzer_call()
            aufrufe["n"] += 1
            return []

        guard._analyze = _zaehlend

        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None,
                data=_chat(_parts(2000)), call_type="acompletion",
            )
        self.assertIn("Analyse", str(ctx.exception))
        # Er hat gearbeitet -- aber nur bis zur Grenze, nicht 2000 mal.
        self.assertLessEqual(aufrufe["n"], dg.PAYLOAD_MAX_ANALYZER_CALLS)
        self.assertGreater(aufrufe["n"], 0)

    async def test_budget_ist_pro_request_und_nicht_global(self):
        """Sonst waere die zweite Anfrage an derselben Instanz tot."""
        guard = _guard()
        for _ in range(3):
            zaehler = _ZaehlenderGuard(guard)
            await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None,
                data=_chat([{"role": "user", "content": "Hallo"}]),
                call_type="acompletion",
            )
            self.assertGreater(zaehler.calls, 0)


class TestSchaetzungDecktDieWirklichkeit(unittest.IsolatedAsyncioTestCase):
    """DIE KOPPLUNG. Der Test, der ein Auseinanderlaufen ROT macht.

    Schaetzung >= tatsaechliche Aufrufe, fuer eine Reihe von Payload-Formen.
    Zaehlt der Schaetzer irgendwo zu wenig, ist das Budget dort wirkungslos --
    und dieser Test faellt, statt dass es jemandem erst im Betrieb auffaellt.
    """

    FAELLE = {
        "nur content": [{"role": "user", "content": "Hallo Welt"}],
        "mehrere messages": [
            {"role": "user", "content": "Eins"},
            {"role": "assistant", "content": "Zwei"},
            {"role": "user", "content": "Drei"},
        ],
        "multimodale parts": [
            {"role": "user", "content": [
                {"type": "text", "text": "A"},
                {"type": "text", "text": "B"},
            ]},
        ],
        "name und refusal": [
            {"role": "assistant", "content": "X", "name": "bot", "refusal": "nein"},
        ],
        "reasoning_content": [
            {"role": "assistant", "content": "X", "reasoning_content": "denk denk"},
        ],
        "tool_calls": _tool_calls(3),
        "verschachtelte arguments": [{
            "role": "assistant", "content": None,
            "tool_calls": [{
                "id": "call_0001", "type": "function",
                "function": {"name": "f", "arguments": json.dumps(
                    {"a": {"b": ["c", "d", 42]}, "e": "f"}
                )},
            }],
        }],
        "leere strings zaehlen nicht": [
            {"role": "user", "content": "   "},
            {"role": "user", "content": "echt"},
        ],
    }

    EXTRA = {
        "tools": {"tools": [
            {"type": "function",
             "function": {"name": "such", "description": "sucht etwas"}},
        ]},
        "stop": {"stop": ["ENDE", "STOP"]},
        "user": {"user": "kunde-4711"},
        "response_format": {"response_format": {"type": "json_object"}},
    }

    async def _messen(self, data):
        guard = _guard()
        geschaetzt = guard._count_analyzer_calls(
            data, dg.PAYLOAD_ROUTES["acompletion"]
        )
        zaehler = _ZaehlenderGuard(guard)
        try:
            await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data,
                call_type="acompletion",
            )
        except dg.DatenschleuseBlocked:
            pass
        return geschaetzt, zaehler.calls

    async def test_schaetzung_ist_nie_zu_niedrig(self):
        for name, messages in self.FAELLE.items():
            with self.subTest(fall=name):
                geschaetzt, echt = await self._messen(_chat(messages))
                self.assertGreaterEqual(
                    geschaetzt, echt,
                    f"Schaetzer zaehlt zu wenig bei '{name}': "
                    f"{geschaetzt} < {echt} -- das Budget ist dort wirkungslos.",
                )

    async def test_schaetzung_deckt_auch_die_top_level_felder(self):
        basis = [{"role": "user", "content": "Hallo"}]
        for name, extra in self.EXTRA.items():
            with self.subTest(feld=name):
                geschaetzt, echt = await self._messen(_chat(basis, **extra))
                self.assertGreaterEqual(
                    geschaetzt, echt,
                    f"Schaetzer zaehlt zu wenig bei '{name}': {geschaetzt} < {echt}",
                )


class TestGrenzeIstEinstellbar(unittest.TestCase):
    def test_argument_hebt_die_grenze(self):
        guard = _guard(max_analyzer_calls=7)
        self.assertEqual(guard.max_analyzer_calls, 7)

    def test_unsinnige_grenze_bricht_den_start_ab(self):
        with self.assertRaises(dg.DatenschleuseConfigError):
            _guard(max_analyzer_calls=0)


class TestClientWirdWiederverwendet(unittest.IsolatedAsyncioTestCase):
    """``_analyze`` oeffnete pro Aufruf einen neuen AsyncClient -- eine
    frische TCP-Verbindung pro Analyse."""

    async def test_derselbe_client_ueber_mehrere_aufrufe(self):
        guard = _guard()
        a = guard._http_client()
        b = guard._http_client()
        self.assertIs(a, b, "Pro Aufruf ein neuer Client = Handshake pro Analyse")


if __name__ == "__main__":
    unittest.main()
