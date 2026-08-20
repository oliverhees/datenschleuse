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


# ===========================================================================
# Ergaenzungen zum Fix (DATENSCHLE-65)
# ===========================================================================
# Die vier Tests oben halten die Regression fest: ein Zitat OHNE Freitext
# darf nicht blocken und muss byte-identisch durchgehen. Sie sagen aber
# nichts ueber den Fall, den Anthropic tatsaechlich schickt.
#
# Denn ``cited_text`` ist im Request-Schema PFLICHT (TextCitationParam) und
# wird beim Echo ausdruecklich zurueckerwartet -- die Doku haelt sogar fest,
# dass es dabei nicht auf die Input-Tokens zaehlt. Ein reales Zitat traegt
# es also IMMER, dazu ``document_title``, den vom Nutzer vergebenen
# Dokumenttitel. Beides ist Freitext und kann PII tragen.
#
# Daraus folgt die Entscheidung, die diese Tests festhalten:
#   - die Struktur wird eng validiert, die Indizes bleiben unveraendert,
#   - die beiden Freitext-Felder werden MASKIERT statt geblockt,
#   - alles Uebrige blockt fail-closed.
# Blocken, sobald ``cited_text`` da ist, waere keine Haerte gewesen, sondern
# die Regression unter anderem Namen: sie haette jede reale Multi-Turn-
# Anfrage mit Zitaten weiterhin zerlegt und nur den kuenstlichen Testfall
# gruen gemacht.


def _full_char_citation(**overrides):
    """Das Zitat so, wie Anthropic es liefert und der Client es
    zurueckschickt -- inklusive der beiden Freitext-Felder."""
    citation = _char_citation(
        cited_text="Das Gras ist gruen.",
        document_title="Beispieldokument",
    )
    citation.update(overrides)
    return citation


def _with_extra_key(citation, key, value):
    """Zusatzschluessel, der KEIN gueltiger Python-Bezeichner sein muss --
    deshalb bewusst ueber das Dict statt ueber Keyword-Argumente."""
    citation = dict(citation)
    citation[key] = value
    return citation


class TestCitationFreeTextIsMasked(unittest.IsolatedAsyncioTestCase):
    """Der Kern der Entscheidung: Freitext im Zitat ist ein Textkanal ans
    Modell wie jeder andere und geht deshalb durch den Masker."""

    async def test_cited_text_with_pii_is_masked(self):
        guard = _guard()
        messages = _echo_conversation(
            [_full_char_citation(cited_text=f"Zitat: {_PII}")]
        )
        out = await _run_messages(guard, messages)
        haystack = " ".join(_flatten(out.get("messages")))
        self.assertNotIn(_PII_NAME, haystack)
        self.assertNotIn(_PII_IBAN, haystack)

    async def test_document_title_with_pii_is_masked(self):
        """Der Dokumenttitel kommt vom Nutzer ("Arztbrief_Mustermann.pdf").
        Er ist genauso Freitext wie das Zitat selbst -- wer nur
        ``cited_text`` behandelt, laesst ihn im Klartext rausgehen."""
        guard = _guard()
        messages = _echo_conversation(
            [_full_char_citation(document_title=f"Akte {_PII_NAME}")]
        )
        out = await _run_messages(guard, messages)
        haystack = " ".join(_flatten(out.get("messages")))
        self.assertNotIn(_PII_NAME, haystack)

    async def test_indices_survive_the_masking_unchanged(self):
        """Maskiert werden die Textfelder -- die Indizes NICHT. Sonst zeigt
        das Zitat nach der Schleuse auf eine andere Stelle."""
        guard = _guard()
        messages = _echo_conversation(
            [_full_char_citation(cited_text=f"Zitat: {_PII}")]
        )
        out = await _run_messages(guard, messages)
        citation = _assistant_msg(out)["content"][0]["citations"][0]
        self.assertEqual(citation["type"], "char_location")
        self.assertEqual(citation["document_index"], 0)
        self.assertEqual(citation["start_char_index"], 0)
        self.assertEqual(citation["end_char_index"], 10)

    async def test_pii_free_citation_reaches_the_provider_unchanged(self):
        """Kein Platzhalter-Roundtrip fuer Zitate ohne PII."""
        guard = _guard()
        out = await _run_messages(
            guard, _echo_conversation([_full_char_citation()])
        )
        citation = _assistant_msg(out)["content"][0]["citations"][0]
        self.assertEqual(citation, _full_char_citation())

    async def test_page_and_content_block_citations_are_masked_too(self):
        """Die beiden anderen Dokument-Zitattypen laufen ueber denselben
        Pfad -- sonst haengt der Fix an genau einem Typ."""
        for citation in (
            {
                "type": "page_location",
                "cited_text": f"Zitat: {_PII}",
                "document_index": 0,
                "document_title": "Bericht",
                "start_page_number": 1,
                "end_page_number": 2,
            },
            {
                "type": "content_block_location",
                "cited_text": f"Zitat: {_PII}",
                "document_index": 0,
                "document_title": "Bericht",
                "start_block_index": 0,
                "end_block_index": 1,
            },
        ):
            with self.subTest(citation_type=citation["type"]):
                guard = _guard()
                out = await _run_messages(
                    guard, _echo_conversation([dict(citation)])
                )
                haystack = " ".join(_flatten(out.get("messages")))
                self.assertNotIn(_PII_NAME, haystack)
                self.assertNotIn(_PII_IBAN, haystack)


class TestCitationRoundTrip(unittest.IsolatedAsyncioTestCase):
    """Der Rueckweg. Maskieren ohne Re-Identifikation waere kein Fix,
    sondern ein Platzhalter beim Kunden."""

    async def test_citation_masking_uses_the_shared_reid_map(self):
        """Der Fehler, der hier am leichtesten passiert: die Zitate mit
        einem EIGENEN Masker maskieren. Dann steht der Platzhalter zwar im
        Request, sein Klartext aber in keinem Mapping -- und der Rueckweg
        laeuft fuer immer ins Leere. Deshalb wird die Zusage direkt am
        Mapping geprueft, nicht nur am maskierten Text."""
        guard = _guard()
        messages = _echo_conversation(
            [_full_char_citation(cited_text=f"Zitat: {_PII_NAME}")]
        )
        out = await _run_messages(guard, messages)
        reid_map = out["metadata"][dg.REID_MAP_KEY]
        cited = _assistant_msg(out)["content"][0]["citations"][0]["cited_text"]

        platzhalter = [p for p in reid_map if p in cited]
        self.assertTrue(
            platzhalter,
            "Der Platzhalter im Zitat steht in keinem Mapping -- der "
            "Rueckweg koennte ihn nie aufloesen.",
        )
        self.assertEqual(reid_map[platzhalter[0]], _PII_NAME)

    async def test_placeholder_from_a_citation_is_reidentified_on_the_way_back(self):
        """End-to-end: was ueber ein Zitat maskiert rausging, kommt beim
        Client wieder im Klartext an."""
        guard = _guard()
        messages = _echo_conversation(
            [_full_char_citation(cited_text=f"Zitat: {_PII_NAME}")]
        )
        out = await _run_messages(guard, messages)
        cited = _assistant_msg(out)["content"][0]["citations"][0]["cited_text"]

        # Das Modell greift den maskierten Zitattext in seiner Antwort auf.
        response = {"choices": [{"message": {"content": f"Sie schrieben: {cited}"}}]}
        back = await guard.async_post_call_success_hook(
            data=out, user_api_key_dict=None, response=response
        )
        self.assertIn(_PII_NAME, back["choices"][0]["message"]["content"])


class TestCitationStructureIsValidatedFailClosed(unittest.IsolatedAsyncioTestCase):
    """Alles, was kein bekanntes Zitat ist, blockt -- statt als bequemster
    Schmuggelkanal des Parts durchzugehen."""

    async def _assert_blocks(self, citations):
        guard = _guard()
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await _run_messages(guard, _echo_conversation(citations))
        return str(ctx.exception)

    async def test_citations_that_are_not_a_list_block(self):
        for value in ("text", 42, {"type": "char_location"}, True):
            with self.subTest(value=type(value).__name__):
                guard = _guard()
                messages = _echo_conversation([])
                messages[1]["content"][0]["citations"] = value
                with self.assertRaises(dg.DatenschleuseBlocked):
                    await _run_messages(guard, messages)

    async def test_citation_entry_that_is_not_an_object_blocks(self):
        await self._assert_blocks(["nicht-objekt"])

    async def test_unknown_citation_type_blocks(self):
        await self._assert_blocks([_char_citation(type="zukunft_location")])

    async def test_missing_citation_type_blocks(self):
        citation = _char_citation()
        del citation["type"]
        await self._assert_blocks([citation])

    async def test_web_search_citation_blocks_and_is_named(self):
        """``web_search_result_location`` traegt ``url``/``title`` als
        Freitext und ``encrypted_index`` als Provider-Token, das
        byte-identisch zurueck muss. Kein geprueftes Zusammenspiel ->
        blocken, aber dem Betreiber sagen warum."""
        msg = await self._assert_blocks([{
            "type": "web_search_result_location",
            "cited_text": "...",
            "url": "https://example.invalid/a",
            "title": "Seite",
            "encrypted_index": "abc",
        }])
        self.assertIn("web_search_result_location", msg)

    async def test_search_result_citation_blocks_and_is_named(self):
        msg = await self._assert_blocks([{
            "type": "search_result_location",
            "cited_text": "...",
            "source": "kb://artikel-1",
            "title": "Artikel",
            "search_result_index": 0,
            "start_block_index": 0,
            "end_block_index": 1,
        }])
        self.assertIn("search_result_location", msg)

    async def test_unknown_field_in_a_citation_blocks(self):
        """Das Gegenstueck zum Part-Defekt eine Ebene tiefer: ein
        Zusatzfeld im Zitat lief sonst ungeprueft ans Modell."""
        await self._assert_blocks(
            [_with_extra_key(_full_char_citation(), "zusatz", _PII)]
        )

    async def test_file_id_blocks_and_is_named(self):
        """``file_id`` gibt es nur response-seitig; ein schema-konformer
        Client schickt es nie. Durchlassen hiesse einen weiteren opaken
        String-Kanal oeffnen, den nichts braucht."""
        msg = await self._assert_blocks([_full_char_citation(file_id="file_123")])
        self.assertIn("file_id", msg)

    async def test_non_string_free_text_field_blocks(self):
        """Kein ``isinstance``-Guard im Verarbeitungspfad: ein
        Nicht-String in ``cited_text`` blockt, statt still uebersprungen zu
        werden und unmaskiert durchzugehen."""
        for value in (42, {"a": "b"}, ["x"], True):
            with self.subTest(value=type(value).__name__):
                await self._assert_blocks([_full_char_citation(cited_text=value)])

    async def test_non_integer_index_blocks(self):
        for value in ("0", 1.5, {"a": 1}, [0]):
            with self.subTest(value=type(value).__name__):
                await self._assert_blocks(
                    [_full_char_citation(start_char_index=value)]
                )

    async def test_bool_is_not_an_index(self):
        """In Python ist ``True`` ein ``int``. Ein blosses
        ``isinstance(value, int)`` liesse es als Index durch."""
        await self._assert_blocks([_full_char_citation(document_index=True)])

    async def test_negative_and_oversized_indices_block(self):
        for value in (-1, dg.MAX_CITATION_INDEX + 1):
            with self.subTest(value=value):
                await self._assert_blocks(
                    [_full_char_citation(end_char_index=value)]
                )

    async def test_too_many_citations_block(self):
        """Jedes Zitat kostet Analyzer-Durchlaeufe. Vor dem Fix blockte
        ``citations`` und kostete null -- die Grenze gehoert deshalb mit
        der Oeffnung zusammen."""
        many = [_char_citation() for _ in range(dg.MAX_CITATIONS_PER_PART + 1)]
        await self._assert_blocks(many)


class TestCitationBlockMessagesLeakNothing(unittest.IsolatedAsyncioTestCase):
    """Gesetz 5: eine Blockmeldung geht an den Client. Sie darf keine
    Client-Werte enthalten -- auch ein Feldname ist Client-Inhalt."""

    async def test_unknown_field_name_is_not_echoed(self):
        guard = _guard()
        citations = [
            _with_extra_key(_full_char_citation(), _PII_NAME, _PII_IBAN)
        ]
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await _run_messages(guard, _echo_conversation(citations))
        msg = str(ctx.exception)
        self.assertNotIn(_PII_NAME, msg)
        self.assertNotIn(_PII_IBAN, msg)

    async def test_unknown_citation_type_value_is_not_echoed(self):
        guard = _guard()
        citations = [_char_citation(type=_PII)]
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await _run_messages(guard, _echo_conversation(citations))
        msg = str(ctx.exception)
        self.assertNotIn(_PII_NAME, msg)
        self.assertNotIn(_PII_IBAN, msg)

    async def test_block_message_stays_bounded(self):
        guard = _guard()
        citations = [
            _with_extra_key(_full_char_citation(), "A" * 5000, "B" * 5000)
        ]
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await _run_messages(guard, _echo_conversation(citations))
        msg = str(ctx.exception)
        self.assertLess(len(msg), 600)
        self.assertNotIn("A" * 50, msg)
        self.assertNotIn("B" * 50, msg)


if __name__ == "__main__":
    unittest.main()
