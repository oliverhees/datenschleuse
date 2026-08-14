"""Unit-Tests fuer die Content-Part-Allowlist der Datenschleuse-Guardrail.

Hintergrund (DATENSCHLE-57): in multimodalen Nachrichten prueft der Guardrail
bisher explizit nur ``type == "text"`` (Maskierung) und ``type == "image_url"``
(Bild-Policy). JEDER andere Part-Typ -- ``file`` (hochgeladene PDFs/Dokumente),
``input_audio``, ein Part ohne ``type``-Feld oder mit einem der Guardrail
unbekannten Typ -- lief bisher UNGEPRUEFT durch. Diese Tests belegen die
Umkehr auf eine Allowlist: nur explizit als sicher erkannte Part-Typen
("text" mit String-Inhalt, "image_url") passieren; alles andere wird
blockiert (fail-closed), egal ob der Typ heute schon bekannt ist oder erst
morgen von der OpenAI-API eingefuehrt wird.

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


def _guard():
    # image_policy explizit setzen, damit der Konstruktor nicht ueber die
    # Umgebung raet -- fuer diese Tests irrelevant, welche Policy es ist,
    # solange sie gueltig ist (kein Redactor-Dienst konfiguriert -> block).
    return dg.DatenschleuseGuardrail(image_policy="block")


async def _run_pre_call(guard, content):
    data = {"messages": [{"role": "user", "content": content}]}
    return await guard.async_pre_call_hook(
        user_api_key_dict=None, cache=None, data=data, call_type="completion"
    )


class TestContentPartAllowlist(unittest.IsolatedAsyncioTestCase):
    async def test_file_part_is_blocked(self):
        """Ein hochgeladenes PDF/Dokument (``type: file``) darf nicht
        ungeprueft durchgehen -- dieselbe PII, die auf einem Screenshot
        blockiert wird, darf in einem PDF nicht durchrutschen."""
        guard = _guard()
        content = [
            {
                "type": "file",
                "file": {"filename": "vertrag.pdf", "file_data": "data:application/pdf;base64,AAAA"},
            }
        ]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, content)

    async def test_input_audio_part_is_blocked(self):
        guard = _guard()
        content = [
            {"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}}
        ]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, content)

    async def test_part_without_type_field_is_blocked(self):
        """Ein Part ganz ohne ``type``-Feld ist nicht als sicher erkennbar."""
        guard = _guard()
        content = [{"text": "irrelevant, hat kein type-Feld"}]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, content)

    async def test_part_with_unknown_future_type_is_blocked(self):
        """Ein der Guardrail unbekannter, erfundener Typ -- steht stellvertretend
        fuer jeden kuenftigen Part-Typ, den die OpenAI-API einfuehren koennte.
        Die Allowlist-Logik darf hierfuer KEINE Codeaenderung brauchen."""
        guard = _guard()
        content = [{"type": "brandneuer_typ_von_morgen", "irgendwas": "wert"}]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, content)

    async def test_text_part_with_non_string_text_is_blocked(self):
        """Ein Part mit ``type: text``, dessen ``text``-Feld kein String ist,
        ist ebenfalls nicht sicher pruefbar -- kein stiller Pass-Through."""
        guard = _guard()
        content = [{"type": "text", "text": 12345}]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, content)

    async def test_non_dict_part_is_blocked(self):
        """Ein Part, der nicht einmal ein dict ist, ist erst recht nicht
        pruefbar."""
        guard = _guard()
        content = ["ein blanker string statt eines content-part-dicts"]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, content)

    # -- DATENSCHLE-64, zweites Finding: das ``type``-Feld ist voll --------
    # client-kontrolliert und darf NIE roh in die Blockmeldung uebernommen
    # werden (Security-Review: IBAN/Diagnose/5000-Zeichen-Flooding liessen
    # sich sonst ueber das type-Feld in den Log-/Response-Pfad schmuggeln).
    async def test_block_message_for_string_type_contains_no_payload(self):
        guard = _guard()
        pii_type = "Max Mustermann, IBAN DE02120300000000202051, mustermann@example.org"
        content = [{"type": pii_type}]
        try:
            await _run_pre_call(guard, content)
            self.fail("DatenschleuseBlocked haette geworfen werden muessen")
        except dg.DatenschleuseBlocked as exc:
            self.assertNotIn("Mustermann", str(exc))
            self.assertNotIn("DE02120300000000202051", str(exc))
            self.assertNotIn("example.org", str(exc))

    async def test_block_message_for_dict_type_contains_no_payload(self):
        """Auch wenn der Wert im type-Feld selbst wieder ein dict ist (z.B.
        ein verschachteltes Objekt mit sensiblen Daten), darf davon nichts
        in die Meldung durchschlagen."""
        guard = _guard()
        content = [{"type": {"payload": "Patientenakte Mustermann, Diagnose F32.1"}}]
        try:
            await _run_pre_call(guard, content)
            self.fail("DatenschleuseBlocked haette geworfen werden muessen")
        except dg.DatenschleuseBlocked as exc:
            self.assertNotIn("Mustermann", str(exc))
            self.assertNotIn("F32.1", str(exc))
            self.assertNotIn("Patientenakte", str(exc))

    async def test_block_message_bounded_against_flooding(self):
        """Ein extrem langes type-Feld (Log-Flooding-Versuch) darf die
        Meldung nicht aufblaehen -- die Meldung enthaelt den Wert ueberhaupt
        nicht, ist also automatisch laengenunabhaengig vom Input."""
        guard = _guard()
        content = [{"type": "A" * 5000}]
        try:
            await _run_pre_call(guard, content)
            self.fail("DatenschleuseBlocked haette geworfen werden muessen")
        except dg.DatenschleuseBlocked as exc:
            self.assertLess(len(str(exc)), 300)
            self.assertNotIn("A" * 100, str(exc))

    # -- Regression: bekannte, sichere Typen bleiben unveraendert erlaubt ----
    async def test_text_part_still_masked_normally(self):
        guard = _guard()

        async def fake_analyze(text):
            if "Mustermann" in text:
                return [{"entity_type": "PERSON", "start": 0, "end": 14, "score": 0.99}]
            return []

        guard._analyze = fake_analyze  # type: ignore[method-assign]
        content = [{"type": "text", "text": "Max Mustermann ist hier"}]
        out = await _run_pre_call(guard, content)
        user_msg = next(m for m in out["messages"] if m.get("role") == "user")
        self.assertNotIn("Mustermann", user_msg["content"][0]["text"])

    async def test_image_url_part_still_handled_by_image_policy(self):
        """Regression: image_url-Parts duerfen von der neuen Allowlist-Logik
        nicht als 'unbekannt' geblockt werden -- sie haben ihre eigene,
        etablierte Policy (redact/block/pass)."""
        guard = dg.DatenschleuseGuardrail(image_policy="pass")
        content = [
            {"type": "image_url", "image_url": {"url": "https://example.org/bild.png"}}
        ]
        out = await _run_pre_call(guard, content)
        user_msg = next(m for m in out["messages"] if m.get("role") == "user")
        self.assertEqual(
            user_msg["content"][0]["image_url"]["url"], "https://example.org/bild.png"
        )

    async def test_string_content_still_works_unchanged(self):
        """Regression + Edge-Case aus dem Auftrag: ``content`` als String
        (statt als Liste) ist der Normalfall reiner Textanfragen und muss
        unveraendert funktionieren -- die neue Part-Allowlist gilt nur fuer
        Listen-Content."""
        guard = _guard()

        async def fake_analyze(text):
            if "Mustermann" in text:
                return [{"entity_type": "PERSON", "start": 0, "end": 14, "score": 0.99}]
            return []

        guard._analyze = fake_analyze  # type: ignore[method-assign]
        out = await _run_pre_call(guard, "Max Mustermann ist hier")
        user_msg = next(m for m in out["messages"] if m.get("role") == "user")
        self.assertNotIn("Mustermann", user_msg["content"])

    async def test_mixed_content_blocks_on_first_unsafe_part_even_with_safe_text(self):
        """Ein sicherer Text-Part in derselben Nachricht darf einen
        unsicheren Part NICHT 'mit durchschmuggeln' -- die ganze Nachricht
        wird blockiert, sobald ein Part nicht auf der Allowlist steht."""
        guard = _guard()
        content = [
            {"type": "text", "text": "harmloser Text"},
            {"type": "file", "file": {"filename": "geheim.pdf", "file_data": "x"}},
        ]
        with self.assertRaises(dg.DatenschleuseBlocked):
            await _run_pre_call(guard, content)


if __name__ == "__main__":
    unittest.main()
