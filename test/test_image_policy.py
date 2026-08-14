"""Unit-Tests fuer die Bild-Policy der Datenschleuse-Guardrail.

Hintergrund: multimodale Nachrichten transportieren Bild-Parts
(``{"type": "image_url", ...}``). Der Guardrail maskierte bisher ausschliesslich
``type == "text"``-Parts — ein Screenshot mit denselben Daten drauf lief also
unveraendert zum Modell. Diese Tests decken den neuen Pfad ab.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.

Ausfuehren:
    python3 -m unittest test.test_image_policy -v
"""

import base64
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402


PNG = b"\x89PNG\r\n\x1a\n-nicht-echt-aber-egal"
REDACTED = b"\x89PNG\r\n\x1a\n-geschwaerzt"


def data_url(raw=PNG, mime="image/png"):
    return f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}"


def image_message(url=None, text=None):
    """Multimodale User-Message mit Bild- und optionalem Text-Part."""
    parts = [{"type": "image_url", "image_url": {"url": url or data_url()}}]
    if text is not None:
        parts.append({"type": "text", "text": text})
    return {"role": "user", "content": parts}


class _FakeRedactorClient:
    """httpx.AsyncClient-Ersatz, der /redact beantwortet."""

    calls = []
    status = 200
    body = REDACTED
    raise_on_post = None

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, **kwargs):
        type(self).calls.append((url, kwargs))
        if type(self).raise_on_post is not None:
            raise type(self).raise_on_post
        return _FakeResponse(type(self).status, type(self).body)


class _FakeResponse:
    def __init__(self, status, content):
        self.status_code = status
        self.content = content

    def raise_for_status(self):
        if self.status_code >= 400:
            raise dg.httpx.HTTPStatusError(f"HTTP {self.status_code}", request=None, response=None)


class _RedactorPatch:
    """Kontextmanager: httpx.AsyncClient gegen den Fake tauschen."""

    def __enter__(self):
        _FakeRedactorClient.calls = []
        _FakeRedactorClient.status = 200
        _FakeRedactorClient.body = REDACTED
        _FakeRedactorClient.raise_on_post = None
        self._orig = dg.httpx.AsyncClient
        dg.httpx.AsyncClient = _FakeRedactorClient  # type: ignore[assignment]
        return _FakeRedactorClient

    def __exit__(self, *a):
        dg.httpx.AsyncClient = self._orig  # type: ignore[assignment]
        return False


# ===========================================================================
# 1. Reine Hilfsfunktionen
# ===========================================================================
class TestDataUrlHelpers(unittest.TestCase):
    def test_roundtrip(self):
        mime, raw = dg._split_data_url(data_url())
        self.assertEqual(mime, "image/png")
        self.assertEqual(raw, PNG)
        self.assertEqual(dg._to_data_url(PNG, "image/png"), data_url())

    def test_external_url_is_not_data(self):
        mime, raw = dg._split_data_url("https://example.org/bild.png")
        self.assertIsNone(raw, "externe URL darf nicht als Daten durchgehen")

    def test_broken_base64_yields_none(self):
        mime, raw = dg._split_data_url("data:image/png;base64,!!!nicht-base64!!!")
        self.assertIsNone(raw)

    def test_part_url_both_shapes(self):
        self.assertEqual(dg._image_part_url({"image_url": {"url": "x"}}), "x")
        self.assertEqual(dg._image_part_url({"image_url": "y"}), "y")
        self.assertEqual(dg._image_part_url({}), "")


# ===========================================================================
# 2. Konstruktor / Policy-Auswahl
# ===========================================================================
class TestPolicyConfig(unittest.TestCase):
    def test_default_without_service_is_block(self):
        """Ohne Redactor-Dienst NIE stillschweigend durchlassen."""
        guard = dg.DatenschleuseGuardrail()
        self.assertEqual(guard.image_policy, "block")

    def test_default_with_service_is_redact(self):
        guard = dg.DatenschleuseGuardrail(image_redactor_url="http://redactor:3000")
        self.assertEqual(guard.image_policy, "redact")

    def test_redact_without_url_refuses_to_start(self):
        with self.assertRaises(ValueError):
            dg.DatenschleuseGuardrail(image_policy="redact")

    def test_unknown_policy_refuses_to_start(self):
        with self.assertRaises(ValueError):
            dg.DatenschleuseGuardrail(image_policy="vielleicht")


# ===========================================================================
# 3. Verhalten im pre_call_hook
# ===========================================================================
class TestImagePolicyInPreCall(unittest.IsolatedAsyncioTestCase):
    async def test_pass_leaves_image_untouched(self):
        """Das alte Verhalten — nur noch erreichbar, wenn man es ausdruecklich
        konfiguriert."""
        guard = dg.DatenschleuseGuardrail(image_policy="pass")
        original = data_url()
        data = {"messages": [image_message(url=original)]}
        out = await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="completion"
        )
        self.assertEqual(out["messages"][0]["content"][0]["image_url"]["url"], original)

    async def test_block_rejects_the_request(self):
        guard = dg.DatenschleuseGuardrail(image_policy="block")
        data = {"messages": [image_message()]}
        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data, call_type="completion"
            )

    async def test_redact_replaces_image_and_still_masks_text(self):
        """Der Bild-Pfad darf den Text-Pfad nicht verdraengen: beide Parts
        derselben Nachricht muessen behandelt werden."""
        guard = dg.DatenschleuseGuardrail(image_redactor_url="http://redactor:3000")

        async def fake_analyze(text):
            if "Mustermann" in text:
                return [{"entity_type": "PERSON", "start": 6, "end": 20, "score": 0.99}]
            return []

        guard._analyze = fake_analyze  # type: ignore[method-assign]

        with _RedactorPatch() as fake:
            data = {"messages": [image_message(text="Hallo Max Mustermann")]}
            out = await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data, call_type="completion"
            )

        # Sobald etwas maskiert wurde, schiebt der Guardrail den
        # Anonymisierungs-Hinweis als System-Message an Position 0 — die
        # User-Message deshalb ueber die Rolle suchen, nicht ueber den Index.
        user_msg = next(m for m in out["messages"] if m.get("role") == "user")
        parts = user_msg["content"]
        self.assertEqual(
            parts[0]["image_url"]["url"], dg._to_data_url(REDACTED, "image/png"),
            "Bild muss durch die geschwaerzte Fassung ersetzt sein",
        )
        self.assertNotIn("Mustermann", parts[1]["text"], "Text-Part muss weiterhin maskiert werden")
        self.assertTrue(fake.calls, "der Redactor muss aufgerufen worden sein")
        self.assertTrue(fake.calls[0][0].endswith("/redact"))

    async def test_redact_blocks_external_url(self):
        """Eine http-URL kann der Proxy nicht schwaerzen — das Modell wuerde sie
        serverseitig abrufen, also an uns vorbei."""
        guard = dg.DatenschleuseGuardrail(image_redactor_url="http://redactor:3000")
        data = {"messages": [image_message(url="https://example.org/scan.png")]}
        with self.assertRaises(dg.DatenschleuseBlocked):
            await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data, call_type="completion"
            )

    async def test_redactor_failure_is_fail_closed(self):
        guard = dg.DatenschleuseGuardrail(image_redactor_url="http://redactor:3000")
        with _RedactorPatch() as fake:
            fake.raise_on_post = dg.httpx.ConnectError("connection refused (simuliert)")
            with self.assertRaises(dg.DatenschleuseBlocked):
                await guard._redact_image(data_url())

    async def test_empty_redactor_response_is_fail_closed(self):
        guard = dg.DatenschleuseGuardrail(image_redactor_url="http://redactor:3000")
        with _RedactorPatch() as fake:
            fake.body = b""
            with self.assertRaises(dg.DatenschleuseBlocked):
                await guard._redact_image(data_url())


if __name__ == "__main__":
    unittest.main(verbosity=2)
