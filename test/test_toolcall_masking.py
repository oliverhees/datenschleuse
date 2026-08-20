"""Unit-Tests fuer die Maskierung von Nicht-``content``-Feldern einer Chat-
Message -- allen voran ``tool_calls[].function.arguments`` (DATENSCHLE-66).

Hintergrund
-----------
DATENSCHLE-57 hat die PART-Ebene innerhalb einer ``content``-Liste auf eine
Allowlist umgestellt, DATENSCHLE-64 den ``content``-CONTAINER selbst. Beide
Male blieb die Frage eine Ebene hoeher unbeantwortet: der Guardrail liest von
einer Message ueberhaupt nur ``msg["content"]``. JEDES andere Feld laeuft
ungeprueft ans Zielmodell.

Der empirisch belegte Bypass:

    {"role": "assistant", "content": null, "tool_calls": [
      {"function": {"name": "lookup",
       "arguments": "{\\"kunde\\": \\"Max Mustermann, IBAN DE02120300000000202051\\"}"}}]}

Fuer agentische Clients (Tool-/Function-Calling) ist genau das der
Normalbetrieb -- Kundendaten stehen regelmaessig in ``arguments``. Der
Durchbruch haengt NICHT an ``content: null``: mit einem harmlosen
content-String tritt er identisch auf (siehe
``test_bypass_is_not_about_content_none``).

Diese Tests belegen zusaetzlich das Allowlist-Prinzip auf MESSAGE-Ebene:
was der Guardrail an einer Nachricht nicht prueft, darf nicht stillschweigend
durchlaufen (dritte Luecke derselben Bauart vermeiden).

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.

Ausfuehren (aus dem Repo-Root):
    python3 -m unittest discover -s ./test -p "test_*.py"
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


# --- Test-Fixtures ---------------------------------------------------------
# Deterministischer Presidio-Ersatz im Stil der bestehenden Tests
# (test_datenschleuse_guardrail.py / test_content_container_allowlist.py):
# kein Container, keine HTTP-Calls, feste Entity-Positionen.
_NEEDLES = (
    ("Max Mustermann", "PERSON"),
    ("Erika Musterfrau", "PERSON"),
    ("DE02120300000000202051", "IBAN_CODE"),
    ("max@example.com", "EMAIL_ADDRESS"),
    ('Max "Maxi" Mustermann', "PERSON"),
)


async def fake_analyze(text):
    """Findet alle bekannten Testwerte an ihren echten Positionen im Text."""
    found = []
    for needle, entity_type in _NEEDLES:
        start = 0
        while True:
            idx = text.find(needle, start)
            if idx < 0:
                break
            found.append(
                {
                    "entity_type": entity_type,
                    "start": idx,
                    "end": idx + len(needle),
                    "score": 0.99,
                }
            )
            start = idx + len(needle)
    return found


def _guard():
    guard = dg.DatenschleuseGuardrail(image_policy="block")
    guard._analyze = fake_analyze  # type: ignore[method-assign]
    return guard


async def _run_pre_call(guard, messages):
    data = {"messages": messages}
    return await guard.async_pre_call_hook(
        user_api_key_dict=None, cache=None, data=data, call_type="completion"
    )


def _msg_with(out, field):
    """Holt die Nachricht, die ``field`` traegt. Bewusst NICHT ueber den Index:
    sobald etwas maskiert wurde, stellt der Guardrail eine System-Message mit
    dem Anonymisierungs-Hinweis voran und alle Indizes verschieben sich."""
    return next(m for m in out["messages"] if field in m and m.get(field) is not None)


def _tool_arguments(out):
    return _msg_with(out, "tool_calls")["tool_calls"][0]["function"]["arguments"]


def _assistant_with_tool_call(arguments, name="lookup", content=None):
    return {
        "role": "assistant",
        "content": content,
        "tool_calls": [
            {"id": "call_1", "type": "function",
             "function": {"name": name, "arguments": arguments}}
        ],
    }


# ===========================================================================
# 1. Der Bypass selbst
# ===========================================================================
class TestToolCallArgumentsAreMasked(unittest.IsolatedAsyncioTestCase):
    async def test_pii_in_tool_call_arguments_is_masked(self):
        """DER Kern-Fund: PII in ``tool_calls[].function.arguments`` lief
        unveraendert ans Zielmodell, weil die Message-Schleife nur
        ``content`` liest."""
        guard = _guard()
        args = json.dumps(
            {"kunde": "Max Mustermann, IBAN DE02120300000000202051"}
        )
        out = await _run_pre_call(guard, [_assistant_with_tool_call(args)])

        masked = _tool_arguments(out)
        self.assertNotIn("Mustermann", masked)
        self.assertNotIn("DE02120300000000202051", masked)
        self.assertIn("<PERSON_0>", masked)

    async def test_bypass_is_not_about_content_none(self):
        """Der Durchbruch haengt nicht an ``content: null`` -- mit einem
        harmlosen content-String tritt er identisch auf."""
        guard = _guard()
        args = json.dumps({"kunde": "Max Mustermann"})
        msg = _assistant_with_tool_call(args, content="Ich schaue das nach.")
        out = await _run_pre_call(guard, [msg])

        masked = _tool_arguments(out)
        self.assertNotIn("Mustermann", masked)

    async def test_masked_arguments_stay_valid_json(self):
        """Akzeptanzkriterium 2: ``arguments`` ist ein JSON-String. Maskiert
        werden die WERTE, nicht die Syntax -- sonst ist der Tool-Aufruf beim
        Zielmodell unbrauchbar."""
        guard = _guard()
        args = json.dumps(
            {
                "kunde": "Max Mustermann",
                "betrag": 42,
                "aktiv": True,
                "leer": None,
                "verlauf": ["Erika Musterfrau", {"mail": "max@example.com"}],
            }
        )
        out = await _run_pre_call(guard, [_assistant_with_tool_call(args)])
        masked = _tool_arguments(out)

        parsed = json.loads(masked)  # muss weiterhin parsen
        self.assertEqual(
            sorted(parsed), ["aktiv", "betrag", "kunde", "leer", "verlauf"],
            "Parameter-Namen (JSON-Syntax) muessen erhalten bleiben",
        )
        self.assertEqual(parsed["betrag"], 42)
        self.assertIs(parsed["aktiv"], True)
        self.assertIsNone(parsed["leer"])
        self.assertNotIn("Mustermann", parsed["kunde"])
        self.assertNotIn("Musterfrau", parsed["verlauf"][0])
        self.assertNotIn("max@example.com", parsed["verlauf"][1]["mail"])

    async def test_shared_reid_map_across_content_and_tool_calls(self):
        """Kein zweites Mapping: derselbe Klartextwert in ``content`` und in
        ``arguments`` bekommt denselben Platzhalter aus DEMSELBEN
        ``Masker.reid_map``."""
        guard = _guard()
        args = json.dumps({"kunde": "Max Mustermann"})
        messages = [
            {"role": "user", "content": "Bitte Max Mustermann pruefen."},
            _assistant_with_tool_call(args),
        ]
        out = await _run_pre_call(guard, messages)

        reid_map = dg.open_reid_map(out["metadata"][dg.REID_MAP_KEY])
        self.assertEqual(reid_map, {"<PERSON_0>": "Max Mustermann"})
        user_msg = next(m for m in out["messages"] if m.get("role") == "user")
        self.assertIn("<PERSON_0>", user_msg["content"])
        self.assertIn("<PERSON_0>", _tool_arguments(out))

    async def test_invalid_json_arguments_are_masked_as_plain_text(self):
        """Modelle liefern gelegentlich kaputtes JSON in ``arguments``.
        Nicht parsebar heisst NICHT ungeprueft: dann wird der Rohstring als
        Text maskiert (Maskieren ist nie ein Leck)."""
        guard = _guard()
        out = await _run_pre_call(
            guard, [_assistant_with_tool_call('{"kunde": "Max Mustermann"')]
        )
        masked = _tool_arguments(out)
        self.assertNotIn("Mustermann", masked)

    async def test_pii_in_json_key_is_masked(self):
        """Auch ein JSON-SCHLUESSEL ist ein Kanal ans Modell. Maskieren statt
        blocken haelt die Struktur gueltig."""
        guard = _guard()
        args = json.dumps({"Max Mustermann": "Bestandskunde"})
        out = await _run_pre_call(guard, [_assistant_with_tool_call(args)])
        masked = _tool_arguments(out)
        self.assertNotIn("Mustermann", masked)
        json.loads(masked)

    async def test_tier3_in_tool_call_arguments_blocks(self):
        """Das Schutzklassen-Gate darf nicht am content-Feld enden: eine
        Art.-9-Angabe mit Personenbezug in ``arguments`` blockt hart."""
        guard = _guard()
        args = json.dumps({"notiz": "Diagnose Depression bei Max Mustermann"})
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, [_assistant_with_tool_call(args)])


# ===========================================================================
# 2. Weitere Textfelder: function_call (Legacy), name, refusal
# ===========================================================================
class TestOtherTextFields(unittest.IsolatedAsyncioTestCase):
    async def test_legacy_function_call_arguments_masked(self):
        guard = _guard()
        messages = [
            {
                "role": "assistant",
                "content": None,
                "function_call": {
                    "name": "lookup",
                    "arguments": json.dumps({"kunde": "Max Mustermann"}),
                },
            }
        ]
        out = await _run_pre_call(guard, messages)
        masked = _msg_with(out, "function_call")["function_call"]["arguments"]
        self.assertNotIn("Mustermann", masked)
        json.loads(masked)

    async def test_message_name_field_masked(self):
        """``name`` (Teilnehmername) ist freier Text und geht ans Modell."""
        guard = _guard()
        messages = [{"role": "user", "name": "Max Mustermann", "content": "Hallo"}]
        out = await _run_pre_call(guard, messages)
        self.assertNotIn("Mustermann", _msg_with(out, "name")["name"])

    async def test_refusal_field_masked(self):
        guard = _guard()
        messages = [
            {"role": "assistant", "content": None,
             "refusal": "Ich kann zu Max Mustermann nichts sagen."}
        ]
        out = await _run_pre_call(guard, messages)
        self.assertNotIn("Mustermann", _msg_with(out, "refusal")["refusal"])


# ===========================================================================
# 3. Allowlist auf MESSAGE-Ebene (dritte Luecke derselben Bauart vermeiden)
# ===========================================================================
class TestMessageFieldAllowlist(unittest.IsolatedAsyncioTestCase):
    async def test_unknown_message_field_is_blocked(self):
        guard = _guard()
        messages = [
            {"role": "user", "content": "Hallo",
             "notizen": "Max Mustermann, IBAN DE02120300000000202051"}
        ]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, messages)

    async def test_unknown_role_is_blocked(self):
        guard = _guard()
        messages = [{"role": "Max Mustermann", "content": "Hallo"}]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, messages)

    async def test_non_dict_message_is_blocked(self):
        """Eine Message, die gar kein dict ist, wurde bisher stillschweigend
        uebersprungen -- also ungeprueft weitergereicht."""
        guard = _guard()
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, ["Max Mustermann"])

    async def test_non_list_messages_is_blocked(self):
        guard = _guard()
        data = {"messages": {"role": "user", "content": "Max Mustermann"}}
        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data, call_type="completion"
            )

    async def test_tool_call_id_with_payload_is_blocked(self):
        """IDs sind opake Korrelations-Tokens, kein Freitext-Kanal."""
        guard = _guard()
        msg = _assistant_with_tool_call(json.dumps({"a": 1}))
        msg["tool_calls"][0]["id"] = "Max Mustermann, IBAN DE02120300000000202051"
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, [msg])

    async def test_unknown_tool_call_field_is_blocked(self):
        guard = _guard()
        msg = _assistant_with_tool_call(json.dumps({"a": 1}))
        msg["tool_calls"][0]["schattenfeld"] = "Max Mustermann"
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, [msg])

    async def test_unknown_tool_call_type_is_blocked(self):
        guard = _guard()
        msg = _assistant_with_tool_call(json.dumps({"a": 1}))
        msg["tool_calls"][0]["type"] = "custom_von_morgen"
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, [msg])

    async def test_block_message_contains_no_payload(self):
        """Gesetz 5: die Blockmeldung darf nie Client-Inhalte transportieren."""
        guard = _guard()
        messages = [
            {"role": "user", "content": "Hallo",
             "Max Mustermann": "IBAN DE02120300000000202051"}
        ]
        try:
            await _run_pre_call(guard, messages)
            self.fail("DatenschleuseBlocked haette geworfen werden muessen")
        except dg.DatenschleuseBlocked as exc:
            self.assertNotIn("Mustermann", str(exc))
            self.assertNotIn("DE02120300000000202051", str(exc))

    async def test_known_optional_fields_pass(self):
        """Regression: die legitimen Felder eines Tool-Roundtrips muessen
        weiterhin durchlaufen (sonst ist Tool-Calling gebrochen)."""
        guard = _guard()
        messages = [
            {"role": "user", "content": "Bestellung 42?"},
            _assistant_with_tool_call(json.dumps({"order_id": "42"})),
            {"role": "tool", "tool_call_id": "call_1", "content": "Versendet."},
        ]
        out = await _run_pre_call(guard, messages)
        self.assertEqual(out["messages"][-1]["tool_call_id"], "call_1")


# ===========================================================================
# 4. Rueckweg: Re-Identifikation in Antwort-tool_calls
# ===========================================================================
def _response_with_tool_call(arguments, refusal=None):
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "refusal": refusal,
                    "tool_calls": [
                        {"id": "call_1", "type": "function",
                         "function": {"name": "lookup", "arguments": arguments}}
                    ],
                }
            }
        ]
    }


class TestPostCallReidentification(unittest.IsolatedAsyncioTestCase):
    async def test_tool_call_arguments_are_reidentified(self):
        guard = _guard()
        data = {"metadata": {dg.REID_MAP_KEY: dg.seal_reid_map({"<PERSON_0>": "Max Mustermann"})}}
        response = _response_with_tool_call(json.dumps({"kunde": "<PERSON_0>"}))

        out = await guard.async_post_call_success_hook(
            data=data, user_api_key_dict=None, response=response
        )
        args = out["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
        self.assertEqual(json.loads(args)["kunde"], "Max Mustermann")

    async def test_reidentification_keeps_json_valid_when_value_has_quotes(self):
        """Der Klartext kann Anfuehrungszeichen/Backslashes enthalten. Ein
        naives str.replace im JSON-String wuerde daraus kaputtes JSON machen
        -- der Tool-Aufruf waere beim Client unbrauchbar."""
        guard = _guard()
        original = 'Max "Maxi" Mustermann'
        data = {"metadata": {dg.REID_MAP_KEY: dg.seal_reid_map({"<PERSON_0>": original})}}
        response = _response_with_tool_call(json.dumps({"kunde": "<PERSON_0>"}))

        out = await guard.async_post_call_success_hook(
            data=data, user_api_key_dict=None, response=response
        )
        args = out["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
        self.assertEqual(json.loads(args)["kunde"], original)

    async def test_refusal_is_reidentified(self):
        guard = _guard()
        data = {"metadata": {dg.REID_MAP_KEY: dg.seal_reid_map({"<PERSON_0>": "Max Mustermann"})}}
        response = _response_with_tool_call(
            json.dumps({"a": 1}), refusal="Zu <PERSON_0> sage ich nichts."
        )
        out = await guard.async_post_call_success_hook(
            data=data, user_api_key_dict=None, response=response
        )
        self.assertIn(
            "Max Mustermann", out["choices"][0]["message"]["refusal"]
        )


# ===========================================================================
# 5. Rueckweg im Streaming: tool_calls-Fragmente
# ===========================================================================
def _delta_chunk(arg_fragment):
    return {
        "choices": [
            {
                "delta": {
                    "content": None,
                    "tool_calls": [
                        {"index": 0, "function": {"arguments": arg_fragment}}
                    ],
                },
                "finish_reason": None,
            }
        ]
    }


async def _async_gen(items):
    for item in items:
        yield item


class TestStreamingToolCallReidentification(unittest.IsolatedAsyncioTestCase):
    async def test_split_placeholder_in_arguments_is_reidentified(self):
        """Ein Platzhalter kann quer ueber zwei SSE-Chunks brechen -- genau
        das Problem, fuer das ReidStreamProcessor gebaut wurde, nur eben im
        ``arguments``-Kanal statt in ``delta.content``."""
        guard = _guard()
        request_data = {"metadata": {dg.REID_MAP_KEY: dg.seal_reid_map({"<PERSON_0>": "Max Mustermann"})}}
        chunks = [_delta_chunk('{"kunde": "<PER'), _delta_chunk('SON_0>"}')]

        collected = ""
        async for chunk in guard.async_post_call_streaming_iterator_hook(
            user_api_key_dict=None, response=_async_gen(chunks), request_data=request_data
        ):
            for tc in chunk["choices"][0]["delta"].get("tool_calls") or []:
                collected += tc["function"].get("arguments") or ""

        self.assertNotIn("<PERSON_0>", collected)
        self.assertEqual(json.loads(collected)["kunde"], "Max Mustermann")


# ===========================================================================
# 6. Audit-Findings zu a136670 (Security-Audit, DATENSCHLE-66)
# ===========================================================================
class TestTypeConfusion(unittest.IsolatedAsyncioTestCase):
    """F1 (HIGH): Das Register blockte unbekannte FELDER, aber nicht den
    falschen TYP in einem bekannten Feld.

    Alle Masker-Pfade waren ``if isinstance(..., str)`` bzw. ``if not
    isinstance(raw, str): return raw`` -- ein Nicht-String fiel still durch.
    LiteLLM typprueft das Feld nicht, der Body geht verbatim raus. Dass der
    Upstream danach vielleicht 400 antwortet, ist irrelevant: die PII hat den
    Perimeter verlassen.

    Lehre: ein isinstance-Guard im MASK-Pfad ist immer ein stiller Durchlass.
    Die Typpruefung gehoert in den VALIDATE-Pfad und muss blocken.
    """

    _PII = "Max Mustermann, IBAN DE02120300000000202051"

    async def test_arguments_as_dict_is_blocked(self):
        guard = _guard()
        msg = _assistant_with_tool_call(json.dumps({"a": 1}))
        msg["tool_calls"][0]["function"]["arguments"] = {"kunde": self._PII}
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, [msg])

    async def test_arguments_as_list_is_blocked(self):
        guard = _guard()
        msg = _assistant_with_tool_call(json.dumps({"a": 1}))
        msg["tool_calls"][0]["function"]["arguments"] = [self._PII]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, [msg])

    async def test_function_name_as_dict_is_blocked(self):
        guard = _guard()
        msg = _assistant_with_tool_call(json.dumps({"a": 1}))
        msg["tool_calls"][0]["function"]["name"] = {"kunde": self._PII}
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, [msg])

    async def test_message_name_as_dict_is_blocked(self):
        guard = _guard()
        messages = [{"role": "user", "content": "Hallo", "name": {"kunde": self._PII}}]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, messages)

    async def test_refusal_as_list_is_blocked(self):
        guard = _guard()
        messages = [{"role": "assistant", "content": None, "refusal": [self._PII]}]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, messages)

    async def test_legacy_function_call_arguments_as_dict_is_blocked(self):
        guard = _guard()
        messages = [
            {"role": "assistant", "content": None,
             "function_call": {"name": "lookup", "arguments": {"kunde": self._PII}}}
        ]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, messages)

    async def test_verification_pass_blocks_leftover_pii(self):
        """Das Sicherheitsnetz hinter allen Einzelpruefungen: der FERTIG
        maskierte arguments-String wird erneut analysiert. Findet der
        Analyzer dort noch Entitaeten, geht nichts raus -- unabhaengig
        davon, welchen Weg ein Wert genommen hat.

        Simuliert wird eine kuenftige Luecke im Maskierungspfad: die
        Maskierung gibt die Struktur unveraendert zurueck."""
        guard = _guard()

        async def broken_masking(node, masker, collected, depth=0):
            return node  # Luecke: maskiert nichts

        guard._mask_json_node = broken_masking  # type: ignore[method-assign]
        args = json.dumps({"kunde": "Max Mustermann"})
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, [_assistant_with_tool_call(args)])


class TestJsonRobustness(unittest.IsolatedAsyncioTestCase):
    async def test_duplicate_json_keys_are_blocked(self):
        """F2 (HIGH): ``json.loads`` behaelt bei doppelten Keys den letzten
        Wert -- der erste wird nie geparst, nie analysiert. War der Rest
        sauber, griff die ``masked == parsed``-Abkuerzung und der ROHSTRING
        ging byte-identisch raus, PII inklusive."""
        guard = _guard()
        raw = ('{"a":"Max Mustermann, IBAN DE02120300000000202051",'
               '"a":"harmlos"}')
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, [_assistant_with_tool_call(raw)])

    async def test_deeply_nested_arguments_block_instead_of_recursionerror(self):
        """F7 (LOW): tief verschachteltes JSON warf einen RecursionError aus
        dem Hook heraus -- ein unkontrollierter Fehlerpfad statt fail-closed."""
        guard = _guard()
        raw = "[" * 5000 + "]" * 5000
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, [_assistant_with_tool_call(raw)])

    async def test_nan_in_arguments_is_blocked(self):
        """F8 (LOW): ``NaN``/``Infinity`` sind kein striktes JSON. Sie wurden
        klaglos geparst und wieder emittiert."""
        guard = _guard()
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(
                guard, [_assistant_with_tool_call('{"wert": NaN}')]
            )

    async def test_moderately_nested_arguments_still_work(self):
        """Gegenprobe zur Tiefenbegrenzung: normal verschachtelte Tool-
        Argumente muessen weiterhin durchlaufen."""
        guard = _guard()
        raw = json.dumps({"a": {"b": {"c": {"d": ["Max Mustermann"]}}}})
        out = await _run_pre_call(guard, [_assistant_with_tool_call(raw)])
        masked = _tool_arguments(out)
        self.assertNotIn("Mustermann", masked)
        self.assertEqual(json.loads(masked)["a"]["b"]["c"]["d"][0], "<PERSON_0>")


class TestOpaqueIdPattern(unittest.IsolatedAsyncioTestCase):
    async def test_trailing_newline_in_id_is_blocked(self):
        """F6 (LOW): ``$`` matcht auch VOR einem abschliessenden Newline --
        ``"call_1\n"`` galt damit als gueltiger Identifier."""
        guard = _guard()
        msg = _assistant_with_tool_call(json.dumps({"a": 1}))
        msg["tool_calls"][0]["id"] = "call_1\n"
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, [msg])


# ===========================================================================
# 7. Provider-Felder im Register (QA-Audit: Hermes-Kompatibilitaet)
# ===========================================================================
class TestProviderFields(unittest.IsolatedAsyncioTestCase):
    """Festschreibung, nicht Abdeckung: diese Felder werden BEWUSST
    behandelt. Genau daran ist das QA-Gate gescheitert -- nicht am
    Buchstaben von AK5, sondern am Geist: was nicht geprueft wird, muss
    benannt und bewusst entschieden sein."""

    async def test_hermes_cache_control_passes(self):
        """Hermes injiziert ``cache_control`` auf Top-Level einer Message,
        sobald Provider-ID oder Hostname den Token ``litellm`` enthaelt. Ein
        Selbsthoster, der seine Subdomain ``litellm.seine-domain.de`` nennt --
        fuer unsere Zielgruppe naheliegend --, wuerde sonst ab der ersten
        Folge-Nachricht hart geblockt."""
        guard = _guard()
        messages = [
            {"role": "user", "content": "Hallo",
             "cache_control": {"type": "ephemeral"}}
        ]
        out = await _run_pre_call(guard, messages)
        user_msg = _msg_with(out, "cache_control")
        self.assertEqual(user_msg["cache_control"], {"type": "ephemeral"},
                         "cache_control muss unveraendert durchgereicht werden")

    async def test_cache_control_with_ttl_passes(self):
        guard = _guard()
        messages = [
            {"role": "user", "content": "Hallo",
             "cache_control": {"type": "ephemeral", "ttl": "1h"}}
        ]
        out = await _run_pre_call(guard, messages)
        self.assertEqual(_msg_with(out, "cache_control")["cache_control"]["ttl"], "1h")

    async def test_cache_control_wrong_type_is_blocked(self):
        """Die isinstance-Guard-Falle aus F1 darf hier nicht neu entstehen:
        ein unerwarteter Typ muss BLOCKEN, nicht durchrutschen."""
        guard = _guard()
        for wert in ("ephemeral", ["ephemeral"], 1):
            with self.subTest(wert=wert):
                messages = [{"role": "user", "content": "Hallo", "cache_control": wert}]
                with self.assertRaises(dg.DatenschleuseBlocked):
                    await _run_pre_call(guard, messages)

    async def test_cache_control_smuggling_is_blocked(self):
        """cache_control ist ein Marker, kein Freitext-Kanal."""
        guard = _guard()
        messages = [
            {"role": "user", "content": "Hallo",
             "cache_control": {"type": "ephemeral", "notiz": "Max Mustermann"}}
        ]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, messages)

    async def test_cache_control_unknown_marker_is_blocked(self):
        guard = _guard()
        messages = [
            {"role": "user", "content": "Hallo",
             "cache_control": {"type": "Max Mustermann"}}
        ]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, messages)

    async def test_reasoning_content_is_masked(self):
        """Ein Assistant-Turn mit zurueckgespieltem ``reasoning_content``
        muss durchgehen -- und die PII darin maskiert werden."""
        guard = _guard()
        messages = [
            {"role": "assistant", "content": "Ich pruefe das.",
             "reasoning_content": "Der Kunde Max Mustermann hat IBAN "
                                  "DE02120300000000202051 genannt."}
        ]
        out = await _run_pre_call(guard, messages)
        reasoning = _msg_with(out, "reasoning_content")["reasoning_content"]
        self.assertNotIn("Mustermann", reasoning)
        self.assertNotIn("DE02120300000000202051", reasoning)
        self.assertIn("<PERSON_0>", reasoning)

    async def test_reasoning_content_wrong_type_is_blocked(self):
        guard = _guard()
        messages = [
            {"role": "assistant", "content": None,
             "reasoning_content": {"text": "Max Mustermann"}}
        ]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, messages)

    async def test_reasoning_content_is_reidentified(self):
        guard = _guard()
        data = {"metadata": {dg.REID_MAP_KEY: dg.seal_reid_map({"<PERSON_0>": "Max Mustermann"})}}
        response = {"choices": [{"message": {
            "role": "assistant", "content": "Fertig.",
            "reasoning_content": "Ich habe <PERSON_0> geprueft."}}]}
        out = await guard.async_post_call_success_hook(
            data=data, user_api_key_dict=None, response=response
        )
        self.assertIn(
            "Max Mustermann", out["choices"][0]["message"]["reasoning_content"]
        )


class TestBlockDiagnostics(unittest.IsolatedAsyncioTestCase):
    """QA-Audit: ein Betreiber, dessen Session blockt, sah bisher nur eine
    Feld-ANZAHL und hatte keine Chance herauszufinden, was ihn blockiert --
    ausser Trial-and-Error gegen die Allowlist."""

    async def test_known_unsupported_field_is_named(self):
        """Bekannte Provider-Felder werden beim Namen genannt. Der Name
        stammt aus unserem eigenen, konstanten Vokabular -- nie vom
        Client."""
        guard = _guard()
        messages = [{"role": "user", "content": "Hallo", "audio": {"id": "x"}}]
        try:
            await _run_pre_call(guard, messages)
            self.fail("haette blocken muessen")
        except dg.DatenschleuseBlocked as exc:
            self.assertIn("audio", str(exc))

    async def test_unknown_field_gets_stable_fingerprint_not_name(self):
        """Ein frei erfundener Feldname kann selbst PII sein. Statt des
        Namens gibt es einen stabilen Fingerprint: derselbe Name ergibt
        denselben Wert (damit Trial-and-Error moeglich ist), der Name selbst
        bleibt aber draussen."""
        guard = _guard()

        async def block_for(feldname):
            try:
                await _run_pre_call(
                    guard, [{"role": "user", "content": "Hi", feldname: "x"}]
                )
                self.fail("haette blocken muessen")
            except dg.DatenschleuseBlocked as exc:
                return str(exc)

        eins = await block_for("Max Mustermann")
        zwei = await block_for("Max Mustermann")
        drei = await block_for("Erika Musterfrau")

        self.assertNotIn("Mustermann", eins)
        self.assertNotIn("Musterfrau", drei)
        self.assertEqual(eins, zwei, "gleicher Feldname -> gleicher Fingerprint")
        self.assertNotEqual(eins, drei, "anderer Feldname -> anderer Fingerprint")


class TestFingerprintIstNichtZurueckrechenbar(unittest.TestCase):
    """Der Fingerprint darf den Feldnamen nicht wieder preisgeben.

    Ein FELDNAME ist Client-Inhalt -- genau deshalb gibt es den Fingerprint.
    Er war aber ein ungesalzenes SHA-256 ueber ``repr(name)``, gekuerzt auf
    8 Hex-Zeichen. Feldnamen sind extrem entropiearm ("Max Mustermann", eine
    IBAN, eine E-Mail-Adresse): wer einen Fingerprint aus einem Log sieht,
    rechnet ihn per Woerterbuch-/Brute-Force zurueck. Damit gab der Schutz
    genau das preis, wovor er schuetzen sollte.

    Gegenmittel: ein prozesslokaler Zufalls-Salt. Die zugesagte Eigenschaft
    bleibt -- derselbe Name ergibt im selben Prozess denselben Wert, ein
    blockendes Feld laesst sich also weiter eingrenzen.
    """

    def test_fingerprint_ist_nicht_das_nackte_sha256(self):
        """DER Befund: ohne Salt kann jeder den Wert nachrechnen."""
        import hashlib

        name = "Max Mustermann"
        ungesalzen = hashlib.sha256(repr(name).encode("utf-8")).hexdigest()[:8]
        self.assertNotEqual(
            dg._field_fingerprint(name),
            ungesalzen,
            "Der Fingerprint ist ohne Geheimnis nachrechenbar -- ein "
            "Woerterbuchangriff holt den Feldnamen zurueck.",
        )

    def test_stabil_innerhalb_des_prozesses(self):
        """Die zugesagte Eigenschaft darf der Salt nicht kaputtmachen."""
        self.assertEqual(
            dg._field_fingerprint("kunde"), dg._field_fingerprint("kunde")
        )
        self.assertNotEqual(
            dg._field_fingerprint("kunde"), dg._field_fingerprint("konto")
        )

    def test_form_bleibt_kurz_und_loggbar(self):
        wert = dg._field_fingerprint("kunde")
        self.assertEqual(len(wert), 8)
        self.assertTrue(all(c in "0123456789abcdef" for c in wert))

    def test_nicht_string_namen_funktionieren_weiterhin(self):
        """Ein Feldname muss kein String sein -- der Fingerprint darf daran
        nicht scheitern, sonst waere der Fehlerpfad selbst ein Absturz."""
        for name in (42, None, ("a", "b")):
            with self.subTest(name=name):
                self.assertEqual(len(dg._field_fingerprint(name)), 8)


# ===========================================================================
# 8. Streaming: reasoning_content (QA-Audit zu fb3ae87)
# ===========================================================================
def _reasoning_chunk(fragment):
    return {
        "choices": [
            {"delta": {"content": None, "reasoning_content": fragment},
             "finish_reason": None}
        ]
    }


def _collect_stream(chunks_out, feld):
    """Sammelt ein Delta-Feld ueber alle ausgegebenen Chunks."""
    text = ""
    for chunk in chunks_out:
        wert = chunk["choices"][0]["delta"].get(feld)
        if isinstance(wert, str):
            text += wert
    return text


class TestStreamingReasoningReidentification(unittest.IsolatedAsyncioTestCase):
    """AK3 verlangt, dass die Re-Identifikation auf dem Rueckweg 'ebenso
    greift wie beim Textkanal' -- nicht nur, dass nichts leckt. Streaming-
    Reasoning ist Hermes' beworbenes Kernfeature: ein Nutzer mit
    Reasoning-Modell sah bisher rohe <PERSON_0>-Tokens in der Gedankenkette."""

    async def _run(self, chunks, reid_map):
        guard = _guard()
        request_data = {"metadata": {dg.REID_MAP_KEY: dg.seal_reid_map(reid_map)}}
        out = []
        async for chunk in guard.async_post_call_streaming_iterator_hook(
            user_api_key_dict=None, response=_async_gen(chunks), request_data=request_data
        ):
            out.append(chunk)
        return out

    async def test_reasoning_content_is_reidentified_in_stream(self):
        out = await self._run(
            [_reasoning_chunk("Ich pruefe <PERSON_0> genauer.")],
            {"<PERSON_0>": "Max Mustermann"},
        )
        text = _collect_stream(out, "reasoning_content")
        self.assertNotIn("<PERSON_0>", text)
        self.assertEqual(text, "Ich pruefe Max Mustermann genauer.")

    async def test_placeholder_split_across_reasoning_chunks(self):
        """Derselbe Chunk-Grenzen-Fall wie im Textkanal: der Platzhalter
        bricht mitten durch."""
        out = await self._run(
            [_reasoning_chunk("Ich pruefe <PER"), _reasoning_chunk("SON_0> genauer.")],
            {"<PERSON_0>": "Max Mustermann"},
        )
        text = _collect_stream(out, "reasoning_content")
        self.assertNotIn("<PERSON_0>", text)
        self.assertEqual(text, "Ich pruefe Max Mustermann genauer.")

    async def test_reasoning_and_content_in_same_stream(self):
        """Reasoning-Phase, dann Antwort-Phase -- beide Kanaele muessen
        vollstaendig und unvermischt ankommen."""
        chunks = [
            _reasoning_chunk("Kunde ist <PERSON_0>."),
            {"choices": [{"delta": {"content": "Hallo <PERSON_0>!"},
                          "finish_reason": None}]},
        ]
        out = await self._run(chunks, {"<PERSON_0>": "Max Mustermann"})
        self.assertEqual(
            _collect_stream(out, "reasoning_content"), "Kunde ist Max Mustermann."
        )
        self.assertEqual(_collect_stream(out, "content"), "Hallo Max Mustermann!")

    async def test_reasoning_stream_without_mapping_is_untouched(self):
        """Ohne Platzhalter darf nichts gepuffert oder veraendert werden
        (voller Streaming-Speed)."""
        out = await self._run([_reasoning_chunk("Kein PII hier.")], {})
        self.assertEqual(_collect_stream(out, "reasoning_content"), "Kein PII hier.")


# ===========================================================================
# 9. Content-Tail darf keine Fremdfragmente duplizieren (Security-Audit)
# ===========================================================================
class TestContentTailDoesNotDuplicate(unittest.IsolatedAsyncioTestCase):
    """Der Abschluss-Chunk des TEXT-Kanals klont den letzten Content-Chunk.
    Trug dieser gleichzeitig ein Reasoning- oder tool_call-Fragment, wanderte
    dessen -- bereits re-identifizierter und ausgelieferter -- Inhalt
    unveraendert in den Klon und kam ein zweites Mal beim Client an.

    Warum die Tests aus Runde 3 das nicht gefangen haben: sie legten
    Reasoning und Content in GETRENNTE Chunks. Die Duplizierung entsteht nur,
    wenn DERSELBE Chunk beides traegt -- die Testform konnte den Fehler
    strukturell nicht ausloesen. Genau das ist hier korrigiert."""

    async def _run(self, chunks, reid_map):
        guard = _guard()
        request_data = {"metadata": {dg.REID_MAP_KEY: dg.seal_reid_map(reid_map)}}
        out = []
        async for chunk in guard.async_post_call_streaming_iterator_hook(
            user_api_key_dict=None, response=_async_gen(chunks), request_data=request_data
        ):
            out.append(chunk)
        return out

    async def test_reasoning_not_duplicated_by_content_tail(self):
        chunks = [{
            "choices": [{
                "delta": {
                    "content": "Kunde <PERSON_0> ist da.",
                    "reasoning_content": "Ich denke ueber <PERSON_0> nach.",
                },
                "finish_reason": None,
            }]
        }]
        out = await self._run(chunks, {"<PERSON_0>": "Max Mustermann"})

        self.assertEqual(
            _collect_stream(out, "reasoning_content"),
            "Ich denke ueber Max Mustermann nach.",
            "Reasoning darf genau einmal ankommen, nicht doppelt",
        )
        self.assertEqual(
            _collect_stream(out, "content"), "Kunde Max Mustermann ist da."
        )

    async def test_tool_arguments_stay_valid_json_with_content_tail(self):
        """Der deterministisch kaputte Fall: das vom Client zusammengesetzte
        ``arguments`` ist kein gueltiges JSON mehr. Im agentischen Betrieb
        heisst das fehlschlagende oder falsche Aktion -- in genau dem Kanal,
        um den dieses Work Item geht."""
        chunks = [{
            "choices": [{
                "delta": {
                    "content": "Ich rufe das Tool fuer <PERSON_0> auf.",
                    "tool_calls": [
                        {"index": 0,
                         "function": {"arguments": '{"kunde":"<PERSON_0>"}'}}
                    ],
                },
                "finish_reason": None,
            }]
        }]
        out = await self._run(chunks, {"<PERSON_0>": "Max Mustermann"})

        args = ""
        for chunk in out:
            for call in chunk["choices"][0]["delta"].get("tool_calls") or []:
                args += call["function"].get("arguments") or ""

        self.assertEqual(
            json.loads(args), {"kunde": "Max Mustermann"},
            "zusammengesetzte arguments muessen gueltiges JSON bleiben",
        )

    async def test_refusal_is_reidentified_in_stream(self):
        """S1: ``refusal`` wurde im Streaming ueberhaupt nicht behandelt --
        weder re-identifiziert noch beim Klonen geleert, obwohl der
        Non-Streaming-Pfad es laengst kann."""
        chunks = [{
            "choices": [{
                "delta": {"content": None,
                          "refusal": "Zu <PERSON_0> sage ich nichts."},
                "finish_reason": None,
            }]
        }]
        out = await self._run(chunks, {"<PERSON_0>": "Max Mustermann"})
        self.assertEqual(
            _collect_stream(out, "refusal"), "Zu Max Mustermann sage ich nichts."
        )

    async def test_refusal_not_duplicated_by_content_tail(self):
        chunks = [{
            "choices": [{
                "delta": {"content": "Kurz zu <PERSON_0>:",
                          "refusal": "Zu <PERSON_0> sage ich nichts."},
                "finish_reason": None,
            }]
        }]
        out = await self._run(chunks, {"<PERSON_0>": "Max Mustermann"})
        self.assertEqual(
            _collect_stream(out, "refusal"), "Zu Max Mustermann sage ich nichts."
        )


if __name__ == "__main__":
    unittest.main()
