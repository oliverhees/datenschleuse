"""Unit-Tests fuer die Content-Part-FELD-Allowlist (DATENSCHLE-65).

Abgrenzung zu ``test_content_part_allowlist.py`` (DATENSCHLE-57): dort geht es
um den Part-**Typ** ("nur 'text' und 'image_url' passieren"). Hier geht es um
die **Felder** eines Parts, der den Typtest bereits bestanden hat.

Der Defekt: die Part-Verarbeitung liest ``part["type"]`` und -- beim
Text-Part -- ``part["text"]``. Jedes WEITERE Feld desselben Parts lief
ungeprueft ans Zielmodell:

    {"role": "user", "content": [{"type": "text", "text": "hi",
                                  "zusatz": "Max Mustermann, IBAN DE0212..."}]}

Das ist dieselbe Bauart wie DATENSCHLE-57 (Part-Typen), -64 (content-Container)
und -66 (Message-Felder), nur eine Ebene tiefer: gelesen wurde, was man kannte,
alles Uebrige lief still durch.

Akut statt akademisch ist das wegen ``cache_control``: DATENSCHLE-66
legitimiert den Marker auf Message-Ebene, Anthropic-Clients haengen ihn aber
an CONTENT-PARTS. Das Muster "Part mit Zusatzfeld" ist damit Normalbetrieb --
weshalb ``cache_control`` durchgehen MUSS (validiert, nicht maskiert), waehrend
alles Unbekannte blockt.

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


# PII aus dem verifizierten PoC des Work Items. Bewusst hier als Konstante,
# damit jeder Test dieselben Werte im Ausgang sucht.
_PII_NAME = "Max Mustermann"
_PII_IBAN = "DE02120300000000202051"
_PII = f"{_PII_NAME}, IBAN {_PII_IBAN}"


def _guard(image_policy="block"):
    guard = dg.DatenschleuseGuardrail(image_policy=image_policy)

    async def fake_analyze(text):
        """Ersetzt den Presidio-Call. Erkennt genau die PoC-Werte -- damit
        laufen die Tests ohne Container und bleiben trotzdem aussagekraeftig:
        was der Fake findet, wuerde Presidio auch finden."""
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


async def _run_pre_call(guard, content, message_extra=None):
    msg = {"role": "user", "content": content}
    if message_extra:
        msg.update(message_extra)
    data = {"messages": [msg]}
    return await guard.async_pre_call_hook(
        user_api_key_dict=None, cache=None, data=data, call_type="completion"
    )


def _user_msg(out):
    """Die Nutzer-Nachricht aus dem ausgehenden Request. Wurde etwas maskiert,
    stellt der Guardrail einen Hinweis als erste Nachricht voran -- ein Zugriff
    ueber ``messages[0]`` waere also je nach Testfall eine andere Nachricht."""
    return next(m for m in out["messages"] if m.get("role") == "user")


def _flatten(value):
    """Alle Strings einer beliebig verschachtelten Struktur -- damit ein Test
    belegen kann, dass PII NIRGENDWO im ausgehenden Request mehr steht, egal
    in welchem Feld sie steckte."""
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


class TestContentPartFieldAllowlistDefect(unittest.IsolatedAsyncioTestCase):
    """Der eigentliche Defekt (roter Test zuerst)."""

    async def test_poc_extra_field_on_text_part_is_blocked(self):
        """Der verifizierte PoC aus dem Work Item: PII in einem Zusatzfeld
        eines Text-Parts lief unmaskiert und ungeblockt ans Modell."""
        guard = _guard()
        content = [{"type": "text", "text": "hi", "zusatz": _PII}]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, content)

    async def test_poc_pii_never_reaches_the_model(self):
        """Zweite Sicht auf denselben Defekt, unabhaengig vom Blockpfad: was
        auch immer passiert -- die PII darf den ausgehenden Request nicht
        verlassen. Entweder blockt der Request, oder sie ist maskiert."""
        guard = _guard()
        content = [{"type": "text", "text": "hi", "zusatz": _PII}]
        try:
            out = await _run_pre_call(guard, content)
        except dg.DatenschleuseBlocked:
            return  # blockiert -- nichts geht raus, Soll-Verhalten
        haystack = " ".join(_flatten(out.get("messages")))
        self.assertNotIn(_PII_NAME, haystack)
        self.assertNotIn(_PII_IBAN, haystack)

    async def test_extra_field_on_image_part_is_blocked(self):
        """Derselbe Defekt am anderen erlaubten Part-Typ."""
        guard = _guard(image_policy="pass")
        content = [
            {
                "type": "image_url",
                "image_url": {"url": "https://example.org/bild.png"},
                "zusatz": _PII,
            }
        ]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, content)

    async def test_nested_extra_field_in_image_url_container_is_blocked(self):
        """Eine Ebene tiefer, gleiche Bauart: der ``image_url``-Container ist
        ebenfalls client-kontrolliert. ``_handle_image_part`` ersetzt nur
        ``url`` -- jedes andere Feld des Containers ueberlebt die Bild-Policy
        unveraendert (bei ``pass`` sowieso)."""
        guard = _guard(image_policy="pass")
        content = [
            {
                "type": "image_url",
                "image_url": {"url": "https://example.org/bild.png", "zusatz": _PII},
            }
        ]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, content)


class TestCacheControlOnParts(unittest.IsolatedAsyncioTestCase):
    """``cache_control`` MUSS durchgehen -- sonst brechen Anthropic-Clients.
    Validiert wie auf Message-Ebene, NICHT maskiert: der Marker muss den
    Provider byte-identisch erreichen, sonst greift das Prompt-Caching nicht."""

    async def test_cache_control_on_text_part_passes_unchanged(self):
        guard = _guard()
        content = [
            {"type": "text", "text": "harmlos", "cache_control": {"type": "ephemeral"}}
        ]
        out = await _run_pre_call(guard, content)
        part = _user_msg(out)["content"][0]
        self.assertEqual(part["cache_control"], {"type": "ephemeral"})

    async def test_cache_control_with_ttl_on_text_part_passes(self):
        guard = _guard()
        content = [
            {
                "type": "text",
                "text": "harmlos",
                "cache_control": {"type": "ephemeral", "ttl": "1h"},
            }
        ]
        out = await _run_pre_call(guard, content)
        part = _user_msg(out)["content"][0]
        self.assertEqual(part["cache_control"], {"type": "ephemeral", "ttl": "1h"})

    async def test_cache_control_on_image_part_passes(self):
        """Anthropic erlaubt den Marker auf JEDEM Content-Block, auch auf
        Bildern. Er ist vollstaendig validiert (kein Freitext-Kanal), ein
        Block waere reine Client-Breakage ohne Sicherheitsgewinn."""
        guard = _guard(image_policy="pass")
        content = [
            {
                "type": "image_url",
                "image_url": {"url": "https://example.org/bild.png"},
                "cache_control": {"type": "ephemeral"},
            }
        ]
        out = await _run_pre_call(guard, content)
        part = _user_msg(out)["content"][0]
        self.assertEqual(part["cache_control"], {"type": "ephemeral"})

    async def test_cache_control_as_smuggling_channel_is_blocked(self):
        """Waere ``cache_control`` auf Part-Ebene nur 'erlaubt' statt eng
        validiert, waere es der bequemste Schmuggelkanal des Parts."""
        guard = _guard()
        for bogus in (
            {"type": "ephemeral", "notiz": _PII},   # Zusatzfeld im Marker
            {"type": _PII},                          # Freitext im type
            {"type": "ephemeral", "ttl": _PII},      # Freitext im ttl
            _PII,                                    # gar kein Objekt
        ):
            with self.subTest(bogus=type(bogus).__name__):
                content = [{"type": "text", "text": "hi", "cache_control": bogus}]
                with self.assertRaises(dg.DatenschleuseBlocked):
                    await _run_pre_call(guard, content)


class TestPartFieldTypeChecks(unittest.IsolatedAsyncioTestCase):
    """Kriterium 4: die Typpruefung gehoert in den Validate-Pfad und muss
    blocken. Ein ``isinstance``-Guard im Verarbeitungspfad ist immer ein
    stiller Durchlass (Security-Audit F1 auf Message-Ebene)."""

    async def test_text_part_with_non_string_text_blocks_as_field_error(self):
        guard = _guard()
        for bogus in ({"payload": _PII}, [_PII], 12345, True):
            with self.subTest(bogus=type(bogus).__name__):
                content = [{"type": "text", "text": bogus}]
                with self.assertRaises(dg.DatenschleuseBlocked):
                    await _run_pre_call(guard, content)

    async def test_text_part_without_text_field_is_blocked(self):
        """Ein Text-Part ohne ``text`` ist nicht spezifikationskonform. Frueher
        fiel er still in den Typ-Block; jetzt blockt er als das, was er ist --
        ein Part, dessen Nutzlast fehlt."""
        guard = _guard()
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, [{"type": "text"}])

    async def test_image_part_with_non_dict_non_string_image_url_is_blocked(self):
        guard = _guard(image_policy="pass")
        for bogus in (12345, [{"url": "x"}], True):
            with self.subTest(bogus=type(bogus).__name__):
                content = [{"type": "image_url", "image_url": bogus}]
                with self.assertRaises(dg.DatenschleuseBlocked):
                    await _run_pre_call(guard, content)

    async def test_image_url_detail_is_validated(self):
        guard = _guard(image_policy="pass")
        ok = [
            {
                "type": "image_url",
                "image_url": {"url": "https://example.org/b.png", "detail": "low"},
            }
        ]
        out = await _run_pre_call(guard, ok)
        self.assertEqual(_user_msg(out)["content"][0]["image_url"]["detail"], "low")

        bad = [
            {
                "type": "image_url",
                "image_url": {"url": "https://example.org/b.png", "detail": _PII},
            }
        ]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(_guard(image_policy="pass"), bad)


class TestPartBlockMessageLeaksNothing(unittest.IsolatedAsyncioTestCase):
    """Gesetz 5: in keiner Blockmeldung stehen Client-Werte -- auch ein
    FELDNAME ist Client-Inhalt (eine IBAN als Schluessel ist trivial)."""

    async def test_block_message_contains_no_field_value(self):
        guard = _guard()
        content = [{"type": "text", "text": "hi", "zusatz": _PII}]
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await _run_pre_call(guard, content)
        msg = str(ctx.exception)
        self.assertNotIn(_PII_NAME, msg)
        self.assertNotIn(_PII_IBAN, msg)

    async def test_block_message_contains_no_field_name(self):
        guard = _guard()
        content = [{"type": "text", "text": "hi", _PII: "wert"}]
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await _run_pre_call(guard, content)
        msg = str(ctx.exception)
        self.assertNotIn(_PII_NAME, msg)
        self.assertNotIn(_PII_IBAN, msg)

    async def test_block_message_is_bounded_against_flooding(self):
        guard = _guard()
        content = [{"type": "text", "text": "hi", "A" * 5000: "B" * 5000}]
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await _run_pre_call(guard, content)
        msg = str(ctx.exception)
        self.assertLess(len(msg), 600)
        self.assertNotIn("A" * 50, msg)
        self.assertNotIn("B" * 50, msg)

    async def test_known_provider_field_is_named_for_the_operator(self):
        """Kriterium 5: bekannte Provider-Felder werden beim Namen genannt
        (konstantes Vokabular aus der Guardrail, nie aus dem Request), damit
        ein Betreiber nicht per Trial-and-Error gegen die Allowlist raten
        muss. ``thinking`` ist ein echtes Anthropic-Part-Feld.

        Beispiel-Feld gewechselt (DATENSCHLE-65): hier stand ``citations``.
        Das Feld ist inzwischen im Register (validiert + Freitext maskiert,
        siehe ``test_content_part_citations.py``) und damit als Beispiel
        fuer ein NICHT registriertes Feld untauglich. Die gepruefte Zusage
        ist unveraendert -- nur an einem Feld gezeigt, das sie noch trifft.
        """
        guard = _guard()
        content = [{"type": "text", "text": "hi", "thinking": "..."}]
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await _run_pre_call(guard, content)
        self.assertIn("thinking", str(ctx.exception))


class TestRegressionKnownGoodPartsStillWork(unittest.IsolatedAsyncioTestCase):
    """Die Feld-Allowlist darf den Normalbetrieb nicht brechen."""

    async def test_plain_text_part_still_masked(self):
        guard = _guard()
        content = [{"type": "text", "text": f"Kontakt: {_PII}"}]
        out = await _run_pre_call(guard, content)
        text = _user_msg(out)["content"][0]["text"]
        self.assertNotIn(_PII_NAME, text)
        self.assertNotIn(_PII_IBAN, text)

    async def test_image_part_still_passes_with_pass_policy(self):
        guard = _guard(image_policy="pass")
        url = "https://example.org/bild.png"
        content = [{"type": "image_url", "image_url": {"url": url}}]
        out = await _run_pre_call(guard, content)
        self.assertEqual(_user_msg(out)["content"][0]["image_url"]["url"], url)

    async def test_image_url_as_bare_string_still_accepted(self):
        """Manche Clients schicken die URL direkt statt im Container --
        ``_image_part_url`` akzeptiert beides, die Allowlist darf das nicht
        nachtraeglich brechen."""
        guard = _guard(image_policy="pass")
        url = "https://example.org/bild.png"
        content = [{"type": "image_url", "image_url": url}]
        out = await _run_pre_call(guard, content)
        self.assertEqual(_user_msg(out)["content"][0]["image_url"], url)

    async def test_multiple_parts_all_validated(self):
        """Ein sauberer Part darf einen unsauberen nicht mitschmuggeln --
        auch nicht, wenn der unsaubere hinten steht."""
        guard = _guard()
        content = [
            {"type": "text", "text": "harmlos"},
            {"type": "text", "text": "auch harmlos", "zusatz": _PII},
        ]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, content)


if __name__ == "__main__":
    unittest.main()
