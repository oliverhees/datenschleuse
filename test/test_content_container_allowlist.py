"""Unit-Tests fuer die Allowlist des ``content``-CONTAINERS selbst
(DATENSCHLE-64, Folge-Fund aus dem QA-Audit von DATENSCHLE-57).

Hintergrund: DATENSCHLE-57 hat die PART-Ebene innerhalb einer ``content``-
Liste von einer Denylist auf eine Allowlist umgestellt (nur ``text`` und
``image_url`` passieren, alles andere blockt). Der QA-Auditor hat dieselbe
Frage eine Ebene hoeher gestellt: was, wenn ``content`` selbst gar keine
Liste ist?

``async_pre_call_hook`` prueft bislang ausschliesslich
``isinstance(content, str)`` und ``isinstance(content, list)``. Jede andere
Form -- allen voran ein einzelner Content-Part als dict OHNE umschliessende
Liste (ein naheliegender Client-Fehler und ein offensichtlicher Umgehungs-
versuch), aber auch eine Zahl oder ein bool -- faellt durch BEIDE Zweige und
laeuft komplett ungeprueft, unmaskiert zum Modell durch.

AUSNAHME (Korrektur nach erstem Security-Review): ``content is None`` (bzw.
ein ganz fehlender ``content``-Key) ist KEIN Bypass, sondern ein legitimer
Fall -- Assistant-Messages mit ``tool_calls`` haben im OpenAI-Format
spezifikationsgemaess kein ``content``. Es gibt dort nichts zu maskieren
oder zu leaken; ein Block wuerde Tool-Calling brechen. Dieser Fall bleibt
deshalb wie bisher unveraendert durchgereicht.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.

Ausfuehren (aus dem Repo-Root):
    python3 -m unittest discover -s ./test -p "test_content_container_allowlist.py" -v
"""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402


def _guard():
    return dg.DatenschleuseGuardrail(image_policy="block")


async def _run_pre_call(guard, messages):
    data = {"messages": messages}
    return await guard.async_pre_call_hook(
        user_api_key_dict=None, cache=None, data=data, call_type="completion"
    )


class TestContentContainerAllowlist(unittest.IsolatedAsyncioTestCase):
    # -- Der eigentliche Bypass: dict statt Liste --------------------------
    async def test_dict_content_with_pii_is_blocked(self):
        """Der zentrale QA-Fund: ein einzelner Content-Part als dict OHNE
        umschliessende Liste (z.B. ``{"type": "text", "text": "..."}`` statt
        ``[{"type": "text", "text": "..."}]``) lief bisher ungeprueft durch --
        weder ``isinstance(content, str)`` noch ``isinstance(content, list)``
        greifen. Genau die Luecke, die fuer Parts innerhalb einer Liste in
        DATENSCHLE-57 geschlossen wurde, galt fuer den Container selbst
        nicht."""
        guard = _guard()
        messages = [
            {
                "role": "user",
                "content": {"type": "text", "text": "GEHEIM Max Mustermann"},
            }
        ]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, messages)

    # -- Weitere nicht pruefbare Formen -------------------------------------
    async def test_content_number_is_blocked(self):
        guard = _guard()
        messages = [{"role": "user", "content": 12345}]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, messages)

    async def test_content_bool_is_blocked(self):
        guard = _guard()
        messages = [{"role": "user", "content": True}]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, messages)

    # -- Korrektur (siehe Team-Lead-Nachricht): content=None ist LEGITIM ----
    async def test_content_none_is_allowed_not_blocked(self):
        """KORREKTUR zum urspruenglichen DATENSCHLE-64-Auftrag: eine
        Assistant-Message mit ``tool_calls`` hat im OpenAI-Format legitim
        KEIN ``content`` (bzw. ``content: null``). content=None traegt
        keinerlei Text und damit keine PII -- es gibt nichts zu pruefen oder
        zu leaken. Ein pauschaler Block wuerde Tool-Calling komplett
        brechen, ein normales, spezifiziertes Nutzungsmuster. content=None
        muss deshalb WIE BISHER unveraendert durchgereicht werden."""
        guard = _guard()
        messages = [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "lookup_order", "arguments": '{"order_id": "42"}'},
                    }
                ],
            }
        ]
        out = await _run_pre_call(guard, messages)
        assistant_msg = out["messages"][0]
        self.assertIsNone(assistant_msg["content"])
        self.assertEqual(len(assistant_msg["tool_calls"]), 1, "tool_calls darf nicht verloren gehen")

    async def test_missing_content_key_is_allowed_not_blocked(self):
        """Aequivalent zu content=None: eine Message ganz OHNE content-Key
        (msg.get('content') liefert ebenfalls None) darf ebenso wenig
        blockieren."""
        guard = _guard()
        messages = [{"role": "assistant", "tool_calls": [{"id": "call_1"}]}]
        out = await _run_pre_call(guard, messages)
        self.assertNotIn("content", out["messages"][0])

    # -- Fehlermeldung darf keine Nutzdaten enthalten (Gesetz 5) ------------
    async def test_block_message_contains_no_payload(self):
        """Die Fehlermeldung darf nur den (harmlosen) Python-Typnamen
        enthalten, niemals den Wert selbst -- sonst koennte bei einem
        dict-content genau die PII in die Fehlermeldung durchschlagen, die
        blockiert werden sollte."""
        guard = _guard()
        messages = [
            {"role": "user", "content": {"geheim": "Max Mustermann wohnt in Berlin"}}
        ]
        try:
            await _run_pre_call(guard, messages)
            self.fail("DatenschleuseBlocked haette geworfen werden muessen")
        except dg.DatenschleuseBlocked as exc:
            self.assertNotIn("Mustermann", str(exc))
            self.assertNotIn("Berlin", str(exc))
            self.assertNotIn("geheim", str(exc))

    # -- Leere Liste: legitimer Fall, kein Block -----------------------------
    async def test_empty_list_content_is_not_blocked(self):
        """Eine leere content-Liste transportiert keinerlei Text oder Bild --
        nichts, das PII enthalten oder verstecken koennte. Sie durchlaeuft
        bereits den bestehenden ``isinstance(content, list)``-Zweig (die
        for-Schleife ueber [] tut schlicht nichts) und wird bewusst NICHT
        als 'unbekannte Form' behandelt: Blockieren haette hier keinen
        Sicherheitsgewinn, nur einen harmlosen Edge-Case unnoetig
        abgewiesen. Siehe PR-Begruendung / 'Annahmen:' im Rueckmeldungstext."""
        guard = _guard()
        messages = [{"role": "user", "content": []}]
        out = await _run_pre_call(guard, messages)
        self.assertEqual(out["messages"][0]["content"], [])

    # -- Regression: bekannte Formen bleiben unveraendert erlaubt -----------
    async def test_string_content_still_works(self):
        guard = _guard()

        async def fake_analyze(text):
            if "Mustermann" in text:
                return [{"entity_type": "PERSON", "start": 0, "end": 14, "score": 0.99}]
            return []

        guard._analyze = fake_analyze  # type: ignore[method-assign]
        out = await _run_pre_call(
            guard, [{"role": "user", "content": "Max Mustermann ist hier"}]
        )
        user_msg = next(m for m in out["messages"] if m.get("role") == "user")
        self.assertNotIn("Mustermann", user_msg["content"])

    async def test_list_content_still_works(self):
        guard = _guard()

        async def fake_analyze(text):
            if "Mustermann" in text:
                return [{"entity_type": "PERSON", "start": 0, "end": 14, "score": 0.99}]
            return []

        guard._analyze = fake_analyze  # type: ignore[method-assign]
        out = await _run_pre_call(
            guard,
            [{"role": "user", "content": [{"type": "text", "text": "Max Mustermann ist hier"}]}],
        )
        user_msg = next(m for m in out["messages"] if m.get("role") == "user")
        self.assertNotIn("Mustermann", user_msg["content"][0]["text"])

    # -- Minor aus dem Audit: Block gilt rollenunabhaengig -------------------
    async def test_unknown_part_type_blocks_regardless_of_role(self):
        """Der Part-Allowlist-Loop aus DATENSCHLE-57 laeuft rollenunabhaengig
        ueber alle messages. Bisher unbelegt: ein unbekannter Part-Typ in
        einer ASSISTANT-Message (nicht nur user) muss ebenso blockieren --
        eine kuenftige 'wir pruefen nur User-Input'-Optimierung wuerde das
        sonst stillschweigend brechen."""
        guard = _guard()
        messages = [
            {
                "role": "assistant",
                "content": [{"type": "brandneuer_typ_von_morgen", "irgendwas": "wert"}],
            }
        ]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, messages)


if __name__ == "__main__":
    unittest.main()
