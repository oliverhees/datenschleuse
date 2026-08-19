"""Unit-Tests fuer das CALL-TYPE-REGISTER -- die oberste Ebene (DATENSCHLE-69).

Hintergrund
-----------
Die Guardrail hat dieselbe Bauart-Luecke inzwischen viermal gehabt, jedes Mal
eine Ebene tiefer entdeckt:

  * DATENSCHLE-57  Part-Ebene innerhalb von ``content``
  * DATENSCHLE-64  der ``content``-Container selbst
  * DATENSCHLE-66  jedes Feld NEBEN ``content`` (und ``messages`` selbst)
  * DATENSCHLE-65  Feld-Ebene eines Parts

Ursache war jedes Mal dieselbe: gelesen wurde, was man kannte -- alles Uebrige
lief still durch. DATENSCHLE-69 ist die LETZTE, oberste Ebene: die ROUTE.

``async_pre_call_hook`` prueft ``call_type`` gegen eine Liste und gibt bei
Nicht-Treffer ``data`` UNVERAENDERT zurueck. Kein Maskieren, kein Block, kein
Fehler -- fail-OPEN. Wer die Datenschleuse ueber eine Route anspricht, die
nicht auf der Liste steht, ist komplett ungeschuetzt und merkt es nicht.

Empirisch gegen litellm 1.97.0 belegt (siehe
``docs/foundation/security-baseline.md`` und die Kommentare im Register):

  | Route                  | ``call_type`` am Hook | vor dem Fix auf der Liste? |
  |------------------------|-----------------------|----------------------------|
  | /v1/chat/completions    | ``acompletion``       | ja                         |
  | /v1/completions         | ``atext_completion``  | NEIN                       |
  | /v1/messages (Anthropic)| ``anthropic_messages``| NEIN                       |
  | /v1/responses           | ``aresponses``        | NEIN                       |

Betroffen sind ausgerechnet die agentischen Clients, die das README als
Zielgruppe nennt.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.

Ausfuehren (aus dem Repo-Root):
    python3 -m unittest discover -s ./test -p "test_calltype_allowlist.py" -v
"""

import copy
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402


# --- Test-Fixtures ---------------------------------------------------------
# Deterministischer Presidio-Ersatz im Stil der bestehenden Tests: kein
# Container, keine HTTP-Calls, feste Entity-Positionen.
_NEEDLES = (
    ("Max Mustermann", "PERSON"),
    ("Erika Musterfrau", "PERSON"),
    ("DE02120300000000202051", "IBAN_CODE"),
    ("max@example.com", "EMAIL_ADDRESS"),
)

# Der Wert, an dem ein Leck sichtbar wird: steht er nach dem Hook noch im
# Klartext im ausgehenden Payload, ist er auf dem Weg zum Cloud-Modell.
_IBAN = "DE02120300000000202051"


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


async def _run(guard, data, call_type):
    return await guard.async_pre_call_hook(
        user_api_key_dict=None, cache=None, data=data, call_type=call_type
    )


# --- Die realen Payload-Formen der betroffenen Routen ----------------------
# Bewusst NICHT erfunden, sondern die echten Schemata: /v1/responses nutzt
# ``input`` statt ``messages``, /v1/messages (Anthropic) hat ``system`` als
# eigenes Top-Level-Feld neben ``messages`` mit Content-Bloecken.
def _responses_payload():
    """OpenAI Responses API (/v1/responses): ``input`` statt ``messages``."""
    return {
        "model": "gpt-4o",
        "input": [
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": f"Meine IBAN ist {_IBAN}."}
                ],
            }
        ],
    }


def _anthropic_payload():
    """Anthropic Messages API (/v1/messages): ``system`` als Top-Level-Feld,
    Content-Bloecke mit eigenen Typnamen (``text`` statt ``input_text``)."""
    return {
        "model": "claude-sonnet-4",
        "system": f"Der Kunde heisst Max Mustermann, IBAN {_IBAN}.",
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": f"Pruefe {_IBAN} bitte."}],
            }
        ],
    }


def _text_completion_payload():
    """OpenAI Legacy Completions (/v1/completions): ``prompt`` statt
    ``messages``."""
    return {"model": "gpt-3.5-turbo-instruct", "prompt": f"Konto {_IBAN} pruefen"}


def _flatten(value):
    """Alle Strings eines beliebig verschachtelten Payloads einsammeln --
    damit der Leck-Nachweis nicht davon abhaengt, an welcher Stelle im
    Schema der Klartext genau steht."""
    out = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            out.append(str(key))
            out.extend(_flatten(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            out.extend(_flatten(item))
    return out


def _leaks_plaintext(payload):
    """True, wenn der Klartext-Wert IRGENDWO im ausgehenden Payload steht.

    Ausgenommen ist genau EIN Ort: das eigene Platzhalter->Klartext-Mapping
    unter ``metadata[REID_MAP_KEY]``. Dort MUSS der Klartext stehen -- das ist
    der Speicher, aus dem die Re-Identifikation auf dem Rueckweg den Wert
    zurueckholt. Er ist ein LiteLLM-interner Metadaten-Key und geht nicht an
    den Provider. Wuerde der Test ihn mitzaehlen, waere jede erfolgreiche
    Maskierung als Leck markiert und der Test wertlos."""
    payload = copy.deepcopy(payload)
    if isinstance(payload, dict):
        meta = payload.get("metadata")
        if isinstance(meta, dict):
            meta.pop(dg.REID_MAP_KEY, None)
    return any(_IBAN in text for text in _flatten(payload))


class TestCallTypeFailOpen(unittest.TestCase):
    """Der Defekt selbst: das Register muss ueberhaupt existieren.

    Vor dem Fix stand die Route-Entscheidung als anonymes Tupel im
    Funktionsrumpf (``call_type not in ("completion", ...)``). Ein Register auf
    Modulebene ist die Voraussetzung dafuer, dass eine neue litellm-Route zu
    einer BEWUSSTEN Entscheidung zwingt statt lautlos ein Leck zu oeffnen --
    genauso wie ``MESSAGE_FIELDS_MASKED`` / ``ALLOWED_MESSAGE_FIELDS`` eine
    Ebene tiefer (DATENSCHLE-66)."""

    def test_register_exists(self):
        for name in (
            "CALL_TYPES_CHAT_MESSAGES",
            "CALL_TYPES_TEXT_PROMPT",
            "ALLOWED_CALL_TYPES",
            "KNOWN_UNSUPPORTED_CALL_TYPES",
        ):
            self.assertTrue(
                hasattr(dg, name), f"Call-Type-Register {name} fehlt (fail-open)"
            )


class TestUnsupportedRoutesAreBlocked(unittest.IsolatedAsyncioTestCase):
    """AK 1 + AK 3: die realen Routen, die vor dem Fix Klartext-PII
    hinaustrugen -- einzeln erfasst, einzeln getestet."""

    async def test_aresponses_does_not_leak_plaintext(self):
        """/v1/responses -- ``call_type='aresponses'``.

        Der PoC des Befunds: die Klartext-IBAN stand nach dem Hook
        unveraendert im ausgehenden Payload."""
        guard = _guard()
        data = _responses_payload()
        try:
            out = await _run(guard, data, "aresponses")
        except dg.DatenschleuseBlocked:
            return  # fail-closed: geblockt ist ein gueltiges Ergebnis (AK 5)
        self.assertFalse(
            _leaks_plaintext(out),
            "Klartext-PII verlaesst die Datenschleuse ueber /v1/responses",
        )

    async def test_anthropic_messages_does_not_leak_plaintext(self):
        """/v1/messages (Anthropic-Format) -- ``call_type='anthropic_messages'``.

        Genau die Route, die agentische Clients sprechen."""
        guard = _guard()
        data = _anthropic_payload()
        try:
            out = await _run(guard, data, "anthropic_messages")
        except dg.DatenschleuseBlocked:
            return
        self.assertFalse(
            _leaks_plaintext(out),
            "Klartext-PII verlaesst die Datenschleuse ueber /v1/messages",
        )

    async def test_atext_completion_does_not_leak_plaintext(self):
        """/v1/completions -- ``call_type='atext_completion'``.

        Die Werte ``'completion'``/``'text_completion'`` auf der alten Liste
        trafen diese Route NICHT: der Proxy uebergibt hier ``atext_completion``."""
        guard = _guard()
        data = _text_completion_payload()
        try:
            out = await _run(guard, data, "atext_completion")
        except dg.DatenschleuseBlocked:
            return
        self.assertFalse(
            _leaks_plaintext(out),
            "Klartext-PII verlaesst die Datenschleuse ueber /v1/completions",
        )


class TestUnknownCallTypeFailsClosed(unittest.IsolatedAsyncioTestCase):
    """AK 2: ein UNBEKANNTER call_type wird geblockt, nicht durchgelassen --
    gleiches Prinzip wie beim Message-Feld-Register eine Ebene tiefer."""

    async def test_future_call_type_is_blocked(self):
        """Eine Route, die litellm erst morgen einfuehrt. Genau dieser Fall
        hat die Luecke ueberhaupt erst erzeugt."""
        guard = _guard()
        data = {"messages": [{"role": "user", "content": f"IBAN {_IBAN}"}]}
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run(guard, data, "a_route_litellm_adds_in_2027")

    async def test_known_but_unsupported_call_type_is_blocked(self):
        """Reale litellm-Routen, die wir bewusst NICHT pruefen (Embeddings,
        Bildgenerierung, Rerank, Passthrough, ...). Sie tragen genauso
        Anwendertext nach draussen und blocken deshalb."""
        for call_type in ("aembedding", "aimage_generation", "pass_through_endpoint"):
            with self.subTest(call_type=call_type):
                guard = _guard()
                with self.assertRaises(dg.DatenschleuseBlocked):
                    await _run(guard, {"input": f"IBAN {_IBAN}"}, call_type)

    async def test_none_call_type_is_blocked(self):
        """``None`` stand bisher explizit auf der Liste und lief damit
        ungeprueft durch. litellm 1.97.0 uebergibt nie ``None`` (die Signatur
        ist ``CallTypesLiteral``, nicht optional) -- ein ``None`` ist also
        entweder ein fremder Aufrufer oder ein Fehler. Beides ist nicht
        pruefbar und blockt."""
        guard = _guard()
        data = {"messages": [{"role": "user", "content": f"IBAN {_IBAN}"}]}
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run(guard, data, None)

    async def test_non_string_call_type_is_blocked(self):
        """Typpruefung im Validate-Pfad statt eines still ueberspringenden
        ``isinstance``-Guards im Verarbeitungspfad -- die Lehre aus dem
        schwersten Audit-Finding von DATENSCHLE-66."""
        for bad in (123, ["acompletion"], {"call_type": "acompletion"}, object()):
            with self.subTest(bad=type(bad).__name__):
                guard = _guard()
                data = {"messages": [{"role": "user", "content": f"IBAN {_IBAN}"}]}
                with self.assertRaises(dg.DatenschleuseBlocked):
                    await _run(guard, data, bad)


class TestSupportedRoutesStillWork(unittest.IsolatedAsyncioTestCase):
    """Regression: der Fix darf die tragende Route nicht brechen."""

    async def test_acompletion_still_masks(self):
        guard = _guard()
        data = {"messages": [{"role": "user", "content": f"IBAN {_IBAN}"}]}
        out = await _run(guard, data, "acompletion")
        self.assertFalse(_leaks_plaintext(out["messages"]))

    async def test_completion_still_masks(self):
        guard = _guard()
        data = {"messages": [{"role": "user", "content": f"IBAN {_IBAN}"}]}
        out = await _run(guard, data, "completion")
        self.assertFalse(_leaks_plaintext(out["messages"]))


if __name__ == "__main__":
    unittest.main()
