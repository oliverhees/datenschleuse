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

    async def test_web_search_echo_also_blocks_one_level_higher(self):
        """Der Grund, warum ``web_search_result_location`` NICHT geoeffnet
        wurde -- als Test statt als Behauptung im Kommentar.

        Anthropic verlangt fuer die Fortsetzung einer Web-Search-Konversation
        ausdruecklich, dass der Client die Assistant-Bloecke unveraendert
        zurueckschickt:

            "send the assistant's content blocks back exactly as you received
            them, including each result's encrypted_content. ... If
            encrypted_content is missing or modified, the request fails with
            a 400 validation error."

        Ein spec-konformer Echo traegt also AUCH ``server_tool_use`` und
        ``web_search_tool_result``. Die blocken am PART-Typ -- eine Ebene
        ueber dem Zitat. Wer nur den Zitat-Typ oeffnet, verschiebt den Block,
        er beseitigt ihn nicht: der Kunde haette den Bug weiter, und bezahlt
        waere es mit einem ungedeckelten ``encrypted_index``-Kanal.

        Schlaegt dieser Test eines Tages fehl, weil die Part-Typen zugelassen
        wurden, ist die Abwaegung neu zu fuehren -- und die bekannte
        Einschraenkung in security-baseline.md gehoert dann angefasst.
        """
        for part in (
            {
                "type": "server_tool_use",
                "id": "srvtoolu_01WYG3ziw53XMcoyKL4XcZmE",
                "name": "web_search",
                "input": {"query": "wer ist zustaendig"},
            },
            {
                "type": "web_search_tool_result",
                "tool_use_id": "srvtoolu_01WYG3ziw53XMcoyKL4XcZmE",
                "content": [{
                    "type": "web_search_result",
                    "url": "https://example.invalid/a",
                    "title": "Seite",
                    "encrypted_content": "EqgfCioIARgBIiQ3YTAwMjY1Mg==",
                }],
            },
        ):
            with self.subTest(part_type=part["type"]):
                guard = _guard()
                messages = [
                    {"role": "user", "content": "Wer ist zustaendig?"},
                    {"role": "assistant", "content": [part]},
                    {"role": "user", "content": "Und warum?"},
                ]
                with self.assertRaises(dg.DatenschleuseBlocked):
                    await _run_messages(guard, messages)

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


# ===========================================================================
# DER RUECKWEG IN SEINER ECHTEN FORM (QA-Audit zu 1e197f9, F1)
# ===========================================================================
# Der bisherige Roundtrip-Test dieses Files baut ``content`` als simplen
# String mit hineinkopiertem Zitattext. Diese Form kommt in keiner realen
# Antwort vor. Er belegt damit generische String-Re-Identifikation -- NICHT
# die Zusage, dass Zitate auf dem Rueckweg aufgeloest werden. Das Wort
# "end-to-end" war dadurch nicht gedeckt.
#
# Real sind zwei Formen, und der Hook behandelte BEIDE nicht:
#   1. ``message.content`` als LISTE von Bloecken. Der Hook verarbeitete
#      ``content`` nur unter ``isinstance(content, str)`` -- eine Liste
#      fiel komplett durch.
#   2. Zitate NEBEN dem Text in ``provider_specific_fields``. LiteLLM legt
#      sie dort ab (non-streaming: ``citations``, streaming:
#      ``delta.provider_specific_fields.citation``). Beide Hooks fassten
#      ``provider_specific_fields`` nirgends an.
#
# Folge beim Kunden: der Haupttext kam im Klartext, dasselbe Zitat trug den
# rohen Platzhalter. Das ist KEIN Vertraulichkeitsleck -- ein
# stehengebliebener Platzhalter ist die sichere Fehlerrichtung -- aber ein
# gebrochenes Versprechen.


def _placeholder_for(reid_map, klartext):
    """Der Platzhalter, den der Hinweg fuer diesen Klartext vergeben hat."""
    treffer = [p for p, v in reid_map.items() if v == klartext]
    assert treffer, f"Kein Platzhalter fuer {klartext!r} im Mapping"
    return treffer[0]


async def _masked_placeholder(guard):
    """Faehrt einen echten Hinweg und liefert (request_data, Platzhalter).

    Bewusst ueber den echten Pre-Call-Hook statt mit einem handgebauten
    Mapping: so ist der Platzhalter derselbe, den die Datenschleuse im
    Betrieb vergibt, und der Test kann nicht an einem erfundenen Mapping
    gruen werden.
    """
    out = await _run_messages(
        guard, [{"role": "user", "content": f"Bitte pruefen: {_PII_NAME}"}],
    )
    reid_map = out["metadata"][dg.REID_MAP_KEY]
    return out, _placeholder_for(reid_map, _PII_NAME)


class TestResponseCitationsAreReidentified(unittest.IsolatedAsyncioTestCase):
    """Nicht-gestreamte Antworten in ihrer ECHTEN Form."""

    async def test_citations_in_provider_specific_fields_are_reidentified(self):
        """Die Form, die LiteLLM aus einer Anthropic-Antwort baut: Text in
        ``content``, Zitate daneben in ``provider_specific_fields``.

        Vorher: der Text kam im Klartext an, dasselbe Zitat trug den rohen
        Platzhalter."""
        guard = _guard()
        request_data, ph = await _masked_placeholder(guard)
        response = {"choices": [{"message": {
            "content": f"Laut Dokument ist {ph} der Ansprechpartner.",
            "provider_specific_fields": {"citations": [{
                "type": "char_location",
                "cited_text": f"{ph} ist zustaendig.",
                "document_title": f"Akte {ph}",
                "document_index": 0,
                "start_char_index": 0,
                "end_char_index": 20,
            }]},
        }}]}
        back = await guard.async_post_call_success_hook(
            data=request_data, user_api_key_dict=None, response=response
        )
        message = back["choices"][0]["message"]
        citation = message["provider_specific_fields"]["citations"][0]

        self.assertNotIn(ph, message["content"])
        self.assertEqual(citation["cited_text"], f"{_PII_NAME} ist zustaendig.")
        self.assertEqual(citation["document_title"], f"Akte {_PII_NAME}")
        # Indizes bleiben unangetastet -- sie zeigen auf eine Position,
        # nicht auf einen Namen.
        self.assertEqual(citation["start_char_index"], 0)
        self.assertEqual(citation["end_char_index"], 20)

    async def test_citations_nested_in_a_list_content_block_are_reidentified(self):
        """``message.content`` als Liste von Bloecken. Der Hook sah bisher
        nur den String-Fall und liess die ganze Liste unangetastet: weder
        Text noch Zitat wurden aufgeloest."""
        guard = _guard()
        request_data, ph = await _masked_placeholder(guard)
        response = {"choices": [{"message": {"content": [{
            "type": "text",
            "text": f"Laut Dokument ist {ph} zustaendig.",
            "citations": [{
                "type": "char_location",
                "cited_text": f"{ph} ist zustaendig.",
                "document_title": f"Akte {ph}",
                "document_index": 0,
                "start_char_index": 0,
                "end_char_index": 20,
            }],
        }]}}]}
        back = await guard.async_post_call_success_hook(
            data=request_data, user_api_key_dict=None, response=response
        )
        block = back["choices"][0]["message"]["content"][0]

        self.assertEqual(block["text"], f"Laut Dokument ist {_PII_NAME} zustaendig.")
        self.assertEqual(
            block["citations"][0]["cited_text"], f"{_PII_NAME} ist zustaendig."
        )
        self.assertEqual(block["citations"][0]["document_title"], f"Akte {_PII_NAME}")

    async def test_web_search_citation_is_reidentified_on_the_way_back(self):
        """Der Rueckweg ist KEIN Sicherheitspfad, sondern ein Einloese-Pfad:
        er ersetzt ausschliesslich Platzhalter, die die Datenschleuse selbst
        vergeben hat, und liefert sie an den KUNDEN zurueck -- nicht an den
        Provider. Deshalb gilt er fuer JEDEN Zitat-Typ, auch fuer die, die
        der Hinweg fail-closed blockt. Ein Platzhalter, der hier stehen
        bleibt, ist ein gebrochenes Versprechen ohne Sicherheitsgewinn."""
        guard = _guard()
        request_data, ph = await _masked_placeholder(guard)
        response = {"choices": [{"message": {
            "content": "Siehe Quelle.",
            "provider_specific_fields": {"citations": [{
                "type": "web_search_result_location",
                "url": "https://example.invalid/akte",
                "title": f"Akte {ph}",
                "cited_text": f"{ph} ist zustaendig.",
                "encrypted_index": "Eo8BCioIAhgBIiQyYjQ0OWJmZg==",
            }]},
        }}]}
        back = await guard.async_post_call_success_hook(
            data=request_data, user_api_key_dict=None, response=response
        )
        citation = back["choices"][0]["message"][
            "provider_specific_fields"]["citations"][0]

        self.assertEqual(citation["cited_text"], f"{_PII_NAME} ist zustaendig.")
        self.assertEqual(citation["title"], f"Akte {_PII_NAME}")
        # ``encrypted_index`` ist ein Provider-Token und wird NICHT angefasst.
        self.assertEqual(citation["encrypted_index"], "Eo8BCioIAhgBIiQyYjQ0OWJmZg==")

    async def test_litellm_groups_citations_per_block_as_a_list_of_lists(self):
        """Die ECHTE Struktur, am LiteLLM-Quellcode belegt (main @ 007bd43,
        ``transformation.py``, Abschnitt ``## CITATIONS``):

            citations.append([{**citation, "supported_text": ...} for ...])

        Also eine LISTE VON LISTEN -- eine Sub-Liste je Text-Block, nicht
        eine flache Zitat-Liste. Der erste Test dieser Klasse nimmt die
        flache Form; die kommt so nur zustande, wenn genau ein Block
        Zitate traegt. Beide Formen muessen halten.

        Und: ``supported_text`` ist ein von LiteLLM ERFUNDENES Feld, das in
        keiner Anthropic-Doku steht. Es traegt den VOLLEN Text des
        stuetzenden Assistant-Blocks -- also denselben Freitext wie die
        Antwort selbst. Wer nur die Anthropic-Feldnamen kennt, laesst hier
        einen kompletten Antworttext-Klon mit rohen Platzhaltern stehen.
        """
        guard = _guard()
        request_data, ph = await _masked_placeholder(guard)
        response = {"choices": [{"message": {
            "content": f"Laut Akte ist {ph} zustaendig. Zweiter Absatz.",
            "provider_specific_fields": {"citations": [
                [{
                    "type": "char_location",
                    "cited_text": f"{ph} ist zustaendig.",
                    "document_title": f"Akte {ph}",
                    "document_index": 0,
                    "start_char_index": 0,
                    "end_char_index": 20,
                    "supported_text": f"Laut Akte ist {ph} zustaendig.",
                }],
                [{
                    "type": "page_location",
                    "cited_text": f"Seite 2 nennt {ph}.",
                    "document_title": None,
                    "document_index": 0,
                    "start_page_number": 2,
                    "end_page_number": 3,
                    "supported_text": "Zweiter Absatz.",
                }],
            ]},
        }}]}
        back = await guard.async_post_call_success_hook(
            data=request_data, user_api_key_dict=None, response=response
        )
        gruppen = back["choices"][0]["message"][
            "provider_specific_fields"]["citations"]

        self.assertEqual(len(gruppen), 2)
        erst, zweit = gruppen[0][0], gruppen[1][0]
        self.assertEqual(erst["cited_text"], f"{_PII_NAME} ist zustaendig.")
        self.assertEqual(erst["document_title"], f"Akte {_PII_NAME}")
        self.assertEqual(
            erst["supported_text"], f"Laut Akte ist {_PII_NAME} zustaendig."
        )
        self.assertEqual(zweit["cited_text"], f"Seite 2 nennt {_PII_NAME}.")
        # ``document_title`` ist laut Schema nullable -- None bleibt None.
        self.assertIsNone(zweit["document_title"])
        self.assertEqual(zweit["start_page_number"], 2)

    async def test_a_response_without_citations_is_unchanged(self):
        """Die Erweiterung darf den bestehenden String-Pfad nicht stoeren."""
        guard = _guard()
        request_data, ph = await _masked_placeholder(guard)
        response = {"choices": [{"message": {"content": f"Hallo {ph}."}}]}
        back = await guard.async_post_call_success_hook(
            data=request_data, user_api_key_dict=None, response=response
        )
        self.assertEqual(
            back["choices"][0]["message"]["content"], f"Hallo {_PII_NAME}."
        )


def _citation_delta_chunk(citation):
    """Die Form, in der LiteLLM ein Anthropic-``citations_delta`` ausliefert.

    Wichtig fuer den Fix: das Zitat kommt als VOLLSTAENDIGES Objekt pro
    Event, nicht als ueber Chunks zerlegter String. Deshalb braucht es hier
    KEINEN Sliding-Window-Puffer wie bei ``delta.content`` -- ein direkter
    Voll-Ersatz ist ausreichend und richtig.
    """
    return {"choices": [{
        "delta": {
            "content": None,
            "provider_specific_fields": {"citation": citation},
        },
        "finish_reason": None,
    }]}


async def _agen(items):
    for item in items:
        yield item


class TestStreamingCitationsAreReidentified(unittest.IsolatedAsyncioTestCase):
    """Derselbe Defekt im Streaming-Pfad. AK3 verlangt, dass die
    Re-Identifikation im Stream "ebenso greift wie beim Textkanal" -- fuer
    Zitate tat sie das gar nicht."""

    async def test_citation_delta_is_reidentified(self):
        guard = _guard()
        request_data, ph = await _masked_placeholder(guard)
        chunks = [_citation_delta_chunk({
            "type": "char_location",
            "cited_text": f"{ph} ist zustaendig.",
            "document_title": f"Akte {ph}",
            "document_index": 0,
        })]

        out = []
        async for chunk in guard.async_post_call_streaming_iterator_hook(
            user_api_key_dict=None, response=_agen(chunks), request_data=request_data
        ):
            out.append(chunk)

        citation = out[0]["choices"][0]["delta"][
            "provider_specific_fields"]["citation"]
        self.assertEqual(citation["cited_text"], f"{_PII_NAME} ist zustaendig.")
        self.assertEqual(citation["document_title"], f"Akte {_PII_NAME}")

    async def test_citation_delta_next_to_a_text_delta_does_not_disturb_it(self):
        """Ein Chunk kann Text UND Zitat tragen. Der Text-Kanal laeuft ueber
        den Sliding-Window-Puffer, das Zitat nicht -- die beiden duerfen sich
        nicht ins Gehege kommen."""
        guard = _guard()
        request_data, ph = await _masked_placeholder(guard)
        chunk = _citation_delta_chunk(
            {"type": "char_location", "cited_text": f"{ph} ist zustaendig."}
        )
        chunk["choices"][0]["delta"]["content"] = f"Laut Akte ist {ph} zustaendig."

        text = ""
        citation = None
        async for out in guard.async_post_call_streaming_iterator_hook(
            user_api_key_dict=None, response=_agen([chunk]), request_data=request_data
        ):
            delta = out["choices"][0]["delta"]
            text += delta.get("content") or ""
            psf = delta.get("provider_specific_fields") or {}
            if psf.get("citation") is not None:
                citation = psf["citation"]

        self.assertEqual(text, f"Laut Akte ist {_PII_NAME} zustaendig.")
        self.assertIsNotNone(citation)
        self.assertEqual(citation["cited_text"], f"{_PII_NAME} ist zustaendig.")

    async def test_citation_is_not_delivered_twice_by_the_tail_chunk(self):
        """Derselbe Defekt, den ``_blank_stream_fragments`` fuer Reasoning,
        refusal und tool_calls bereits behandelt -- nur fuer Zitate.

        Der Abschluss-Chunk KLONT den letzten Content-Chunk, um den
        Rest-Puffer des Textkanals auszuliefern. Trug dieser Chunk ein
        Zitat, wandert es unveraendert in den Klon -- und ist zu dem
        Zeitpunkt bereits beim Client. Folge: dasselbe Zitat zweimal in der
        Antwort.
        """
        guard = _guard()
        request_data, ph = await _masked_placeholder(guard)
        # Der Platzhalter bricht ueber die Chunk-Grenze: nur so entsteht
        # ueberhaupt ein Rest-Puffer und damit ein Abschluss-Chunk.
        # Das Zitat MUSS auf dem letzten Content-Chunk sitzen: genau den
        # klont der Abschluss-Chunk als Vorlage.
        half = len(ph) // 2
        erst = {"choices": [{
            "delta": {"content": f"Laut Akte ist {ph[:half]}"},
            "finish_reason": None,
        }]}
        zweit = _citation_delta_chunk(
            {"type": "char_location", "cited_text": f"{ph} ist zustaendig."}
        )
        zweit["choices"][0]["delta"]["content"] = ph[half:]

        zitate = []
        async for out in guard.async_post_call_streaming_iterator_hook(
            user_api_key_dict=None,
            response=_agen([erst, zweit]),
            request_data=request_data,
        ):
            psf = out["choices"][0]["delta"].get("provider_specific_fields") or {}
            if psf.get("citation") is not None:
                zitate.append(psf["citation"])

        self.assertEqual(
            len(zitate), 1,
            "Das Zitat wurde mehrfach ausgeliefert -- der Abschluss-Chunk "
            "hat es aus seiner Vorlage geerbt.",
        )


if __name__ == "__main__":
    unittest.main()
