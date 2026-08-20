"""Multi-Turn-Echo und ``citations`` auf Content-Parts (DATENSCHLE-65).

Abgrenzung zu ``test_content_part_field_allowlist.py``: dort steht der
Defekt selbst (Zusatzfeld eines Parts lief ungeprueft durch) und die
Behandlung von ``cache_control``. Hier geht es um die Luecke, die das
QA-Audit dieses PRs gefunden hat -- und um die Klasse von Feldern, die sie
verursacht.

Die Luecke: alle ``cache_control``-Tests des PRs sind SINGLE-TURN. Sie
schicken genau eine User-Nachricht. Das Standard-Muster eines Chat-Clients
ist aber Multi-Turn: der Client schickt die History zurueck, inklusive der
vorherigen ASSISTANT-Antwort. Und die traegt bei Anthropic Felder, die das
Modell selbst erzeugt hat -- ``citations`` zum Beispiel.

Folge vor diesem Test: die gesamte Folgeanfrage schlug fehl, sobald das
Modell einmal mit Zitaten geantwortet hatte. Vor DATENSCHLE-65 lief
``citations`` durch; die Regression stammt also aus diesem PR.

Die Entscheidung dahinter (siehe ``PART_FIELDS_VALIDATED`` im Guardrail):
``citations`` traegt Referenzen und Indizes, keinen Freitext -- MIT EINER
AUSNAHME, ``cited_text``. Deshalb wird die Struktur eng validiert und das
eine Freitext-Feld nicht durchgelassen, statt den ganzen Part zu blocken.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.

Ausfuehren (aus dem Repo-Root):
    python3 -m unittest discover -s ./test -p "test_*.py"
"""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402


_PII_NAME = "Max Mustermann"
_PII_IBAN = "DE02120300000000202051"
_PII = f"{_PII_NAME}, IBAN {_PII_IBAN}"


def _guard(image_policy="block"):
    guard = dg.DatenschleuseGuardrail(image_policy=image_policy)

    async def fake_analyze(text):
        found = []
        for needle, entity in ((_PII_NAME, "PERSON"), (_PII_IBAN, "IBAN_CODE")):
            start = text.find(needle)
            while start != -1:
                found.append(
                    {
                        "entity_type": entity,
                        "start": start,
                        "end": start + len(needle),
                        "score": 0.99,
                    }
                )
                start = text.find(needle, start + len(needle))
        return found

    guard._analyze = fake_analyze  # type: ignore[method-assign]
    return guard


async def _run_messages(guard, messages):
    """Ganze Konversation durch den Pre-Call-Hook -- nicht nur eine
    Nachricht. Genau diese Form fehlte den bisherigen Tests."""
    data = {"messages": messages}
    return await guard.async_pre_call_hook(
        user_api_key_dict=None, cache=None, data=data, call_type="completion"
    )


def _assistant_msg(out):
    return next(m for m in out["messages"] if m.get("role") == "assistant")


def _flatten(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out = []
        for key, item in value.items():
            out.extend(_flatten(key))
            out.extend(_flatten(item))
        return out
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            out.extend(_flatten(item))
        return out
    return []


def _char_citation(**overrides):
    """Das reale Anthropic-Format fuer eine ``char_location``-Zitatstelle,
    ohne ``cited_text`` (das wird separat getestet)."""
    citation = {
        "type": "char_location",
        "document_index": 0,
        "start_char_index": 0,
        "end_char_index": 10,
    }
    citation.update(overrides)
    return citation


def _echo_conversation(citations):
    """Das Standard-Multi-Turn-Muster: Frage, Antwort des Modells (mit
    Zitaten, wie das Modell sie geliefert hat), Folgefrage."""
    return [
        {"role": "user", "content": "Was steht im Dokument?"},
        {
            "role": "assistant",
            "content": [
                {
                    "type": "text",
                    "text": "Laut Dokument ist X der Fall.",
                    "citations": citations,
                }
            ],
        },
        {"role": "user", "content": "Und was folgt daraus?"},
    ]


class TestMultiTurnEchoWithCitations(unittest.IsolatedAsyncioTestCase):
    """Der QA-Fund: die Folgeanfrage schlug fehl, sobald das Modell einmal
    mit Zitaten geantwortet hatte."""

    async def test_multi_turn_echo_with_citations_is_not_blocked(self):
        """Der reproduzierende Test zum QA-Fund. Vor dem Fix: blockt."""
        guard = _guard()
        out = await _run_messages(guard, _echo_conversation([_char_citation()]))
        self.assertIsNotNone(out)

    async def test_citations_reach_the_provider_unchanged(self):
        """``citations`` ist validiert, nicht maskiert -- die Indizes muessen
        byte-identisch bleiben, sonst zeigen sie auf die falsche Stelle."""
        guard = _guard()
        citations = [_char_citation()]
        out = await _run_messages(guard, _echo_conversation(citations))
        part = _assistant_msg(out)["content"][0]
        self.assertEqual(part["citations"], [_char_citation()])

    async def test_empty_citations_list_is_accepted(self):
        """Eine leere Liste ist das, was ein Client schickt, wenn das Modell
        nichts zitiert hat -- kein Grund zu blocken."""
        guard = _guard()
        out = await _run_messages(guard, _echo_conversation([]))
        self.assertEqual(_assistant_msg(out)["content"][0]["citations"], [])

    async def test_multi_turn_echo_still_masks_the_assistant_text(self):
        """Wichtig: ``citations`` durchzulassen darf den Masker nicht
        aushebeln. Der Text desselben Parts wird weiterhin maskiert."""
        guard = _guard()
        messages = _echo_conversation([_char_citation()])
        messages[1]["content"][0]["text"] = f"Laut Dokument: {_PII}"
        out = await _run_messages(guard, messages)
        haystack = " ".join(_flatten(out.get("messages")))
        self.assertNotIn(_PII_NAME, haystack)
        self.assertNotIn(_PII_IBAN, haystack)


if __name__ == "__main__":
    unittest.main()
