"""Unit-Tests fuer die Bild-Policy der Datenschleuse-Guardrail.

Hintergrund: multimodale Nachrichten transportieren Bild-Parts
(``{"type": "image_url", ...}``). Der Guardrail maskierte bisher ausschliesslich
``type == "text"``-Parts — ein Screenshot mit denselben Daten drauf lief also
unveraendert zum Modell. Diese Tests decken den neuen Pfad ab.

Laeuft OHNE laufenden Presidio-Container und OHNE installiertes litellm.

Ausfuehren (aus dem Repo-Root -- "test.test_image_policy" kollidiert mit dem
Python-Stdlib-Paket "test" und schlaegt dort fehl, siehe DATENSCHLE-62):
    python3 -m unittest discover -s ./test -p "test_image_policy.py" -v
    # oder aus dem test/-Ordner:
    python3 -m unittest test_image_policy -v
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

    def test_empty_payload_keeps_mime(self):
        """QA-Finding (Runde 2 zu Finding 5): eine data:-URL mit leerem
        Base64-Feld ('data:image/png;base64,') muss weiterhin ihr mime
        zurueckgeben, statt es wie eine externe URL zu behandeln. mime ist
        das einzige Signal, mit dem der Aufrufer 'gar keine data:-URL' von
        'data:-URL ohne Payload' unterscheiden kann."""
        mime, raw = dg._split_data_url("data:image/png;base64,")
        self.assertEqual(mime, "image/png", "mime darf bei leerem Payload nicht verloren gehen")
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

    async def test_redactor_http_error_status_is_fail_closed(self):
        """4xx/5xx vom Image-Redactor (z.B. Presidio-Dienst down oder 400 bei
        kaputtem Upload) muss ueber raise_for_status() zu DatenschleuseBlocked
        eskalieren -- bisher nur ad hoc verifiziert, nicht durch die Suite
        belegt (QA-Finding 3)."""
        guard = dg.DatenschleuseGuardrail(image_redactor_url="http://redactor:3000")
        with _RedactorPatch() as fake:
            fake.status = 500
            with self.assertRaises(dg.DatenschleuseBlocked):
                await guard._redact_image(data_url())

    async def test_redactor_http_client_error_status_is_fail_closed(self):
        """Auch ein 4xx (z.B. 400 Bad Request bei nicht dekodierbarem Bild
        auf Presidio-Seite) darf nie unmaskiert durchrutschen."""
        guard = dg.DatenschleuseGuardrail(image_redactor_url="http://redactor:3000")
        with _RedactorPatch() as fake:
            fake.status = 400
            with self.assertRaises(dg.DatenschleuseBlocked):
                await guard._redact_image(data_url())

    async def test_multiple_images_in_one_message_all_redacted(self):
        """Typischer multimodaler Fall: mehrere Bilder in derselben Nachricht
        muessen alle geschwaerzt werden, nicht nur das erste (QA-Finding 4)."""
        guard = dg.DatenschleuseGuardrail(image_redactor_url="http://redactor:3000")
        original_a = data_url(raw=b"bild-a")
        original_b = data_url(raw=b"bild-b")
        data = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "image_url", "image_url": {"url": original_a}},
                        {"type": "image_url", "image_url": {"url": original_b}},
                    ],
                }
            ]
        }
        with _RedactorPatch() as fake:
            out = await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data, call_type="completion"
            )
        parts = out["messages"][0]["content"]
        self.assertEqual(len(parts), 2)
        for part in parts:
            self.assertEqual(
                part["image_url"]["url"], dg._to_data_url(REDACTED, "image/png")
            )
        self.assertEqual(len(fake.calls), 2, "beide Bilder muessen den Redactor durchlaufen haben")

    async def test_multiple_messages_with_images_all_redacted(self):
        """Mehrere Nachrichten mit je einem Bild (z.B. laufende Konversation)
        muessen ebenfalls vollstaendig geschwaerzt werden (QA-Finding 4)."""
        guard = dg.DatenschleuseGuardrail(image_redactor_url="http://redactor:3000")
        original_1 = data_url(raw=b"nachricht-1")
        original_2 = data_url(raw=b"nachricht-2")
        data = {
            "messages": [
                image_message(url=original_1),
                # Leerer Content, damit dieser Zwischenschritt nicht zusaetzlich
                # den Presidio-Analyzer-Pfad (_analyze) beruehrt -- der ist hier
                # nicht Testgegenstand, nur die Bild-Redaktion ueber mehrere
                # Messages hinweg.
                {"role": "assistant", "content": ""},
                image_message(url=original_2),
            ]
        }
        with _RedactorPatch() as fake:
            out = await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data, call_type="completion"
            )
        image_messages = [
            m for m in out["messages"] if m.get("role") == "user"
        ]
        self.assertEqual(len(image_messages), 2)
        for msg in image_messages:
            self.assertEqual(
                msg["content"][0]["image_url"]["url"],
                dg._to_data_url(REDACTED, "image/png"),
            )
        self.assertEqual(len(fake.calls), 2, "beide Bild-Nachrichten muessen den Redactor durchlaufen haben")

    async def test_broken_base64_error_message_differs_from_external_url(self):
        """QA-Finding 5: eine data:-URL mit kaputtem Base64, eine data:-URL
        mit leerem Base64-Feld und eine externe http-URL landen alle drei
        fail-closed in DatenschleuseBlocked, aber mit DREI UNTERSCHIEDLICHEN,
        jeweils zutreffenden Meldungen -- vorher wurde in allen Faellen immer
        'externe URL' gemeldet, auch bei kaputten/leeren eingebetteten Daten
        (Runde 2: der Leer-Payload-Fall ging urspruenglich unter, weil
        _split_data_url dabei das mime-Signal verlor). Keine der Meldungen
        darf Bildinhalt/Base64-Fragmente enthalten."""
        guard = dg.DatenschleuseGuardrail(image_redactor_url="http://redactor:3000")

        broken = "data:image/png;base64,!!!nicht-base64!!!"
        with self.assertRaises(dg.DatenschleuseBlocked) as broken_ctx:
            await guard._redact_image(broken)
        broken_message = str(broken_ctx.exception)
        self.assertIn("Base64", broken_message)
        self.assertNotIn("!!!nicht-base64!!!", broken_message)

        empty = "data:image/png;base64,"
        with self.assertRaises(dg.DatenschleuseBlocked) as empty_ctx:
            await guard._redact_image(empty)
        empty_message = str(empty_ctx.exception)
        self.assertIn("ohne Payload", empty_message)
        self.assertNotIn("externe URL", empty_message)

        external = "https://example.org/scan.png"
        with self.assertRaises(dg.DatenschleuseBlocked) as external_ctx:
            await guard._redact_image(external)
        external_message = str(external_ctx.exception)
        self.assertIn("externe URL", external_message)

        messages = {broken_message, empty_message, external_message}
        self.assertEqual(
            len(messages), 3,
            "kaputtes Base64, leeres Payload und externe URL muessen drei "
            "unterscheidbare Meldungen liefern",
        )


# ===========================================================================
# 4. DATENSCHLE-83: Block-Meldung muss den Betreiber handlungsfaehig machen
# ===========================================================================
class TestBlockMessageGuidesOperator(unittest.IsolatedAsyncioTestCase):
    """Seit DATENSCHLE-83 ist der Image-Redactor NICHT mehr Teil des
    Standard-Stacks: er bringt allein 42 der 61 kritischen und 3847 der rund
    4344 Gesamtbefunde mit (CI-Run 32253275837). Er liegt jetzt hinter dem
    Compose-Profil ``images``, und die Standard-Policy ist ``block``.

    Damit veraendert sich, wer die Block-Meldung liest: vorher war ein Block
    die Ausnahme fuer bewusst reduzierte Setups, jetzt ist er der Normalfall
    fuer jeden, der ``docker compose up`` tippt und ein Bild schickt. Die
    Meldung muss deshalb nicht nur sagen DASS blockiert wurde, sondern WIE der
    Betreiber den Dienst einschaltet -- sonst steht er vor einer Sackgasse.

    Bewusst NICHT getestet: der genaue Wortlaut. Verankert ist der Befehl, den
    der Betreiber abtippen koennen muss."""

    ACTIVATION_HINT = "docker compose --profile images up"

    async def test_block_message_names_the_activation_command(self):
        """Die Meldung muss den konkreten Befehl enthalten, mit dem der
        Image-Redactor nachgestartet wird."""
        guard = dg.DatenschleuseGuardrail(image_policy="block")
        data = {"messages": [image_message()]}
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data, call_type="completion"
            )
        message = str(ctx.exception)
        self.assertIn(
            self.ACTIVATION_HINT, message,
            "Block-Meldung muss den Aktivierungsbefehl nennen, sonst ist der "
            "Betreiber in einer Sackgasse",
        )

    async def test_block_message_names_the_policy_switch(self):
        """Neben dem Profil muss auch die Stellschraube auftauchen, sonst
        sucht der Betreiber den Schalter im Compose-File statt in der .env."""
        guard = dg.DatenschleuseGuardrail(image_policy="block")
        data = {"messages": [image_message()]}
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data, call_type="completion"
            )
        message = str(ctx.exception)
        self.assertIn("DATENSCHLEUSE_IMAGE_POLICY", message)

    async def test_block_message_leaks_no_image_content(self):
        """Fail-closed heisst auch: die Meldung selbst darf nie Bilddaten
        transportieren. Sie geht an den Client zurueck und potenziell ins Log."""
        guard = dg.DatenschleuseGuardrail(image_policy="block")
        secret = b"streng-geheimes-bild-mit-pii"
        data = {"messages": [image_message(url=data_url(raw=secret))]}
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data, call_type="completion"
            )
        message = str(ctx.exception)
        self.assertNotIn("streng-geheimes", message)
        self.assertNotIn(
            base64.b64encode(secret).decode("ascii"), message,
            "Base64-Payload darf nie in der Fehlermeldung landen",
        )

    async def test_block_stays_fail_closed_not_a_crash(self):
        """Blocken heisst kontrolliert ablehnen. Ein anderer Fehlertyp (z.B.
        AttributeError/ValueError) waere ein Absturz und wuerde je nach
        LiteLLM-Version zu einer 500 statt einer sauberen Ablehnung fuehren."""
        guard = dg.DatenschleuseGuardrail(image_policy="block")
        data = {"messages": [image_message()]}
        try:
            await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data, call_type="completion"
            )
        except dg.DatenschleuseBlocked:
            pass
        except Exception as exc:  # pragma: no cover - Diagnose bei Regression
            self.fail(f"Block muss DatenschleuseBlocked sein, war {type(exc).__name__}: {exc}")
        else:
            self.fail("Bild-Part bei image_policy='block' muss abgelehnt werden")

    async def test_block_is_the_default_without_redactor_service(self):
        """Regressionsanker fuer die Compose-Aenderung: ohne konfigurierten
        Redactor-Dienst -- also im neuen Standard-Stack -- ist 'block' die
        Policy, und sie fuehrt zu einer handlungsleitenden Meldung."""
        guard = dg.DatenschleuseGuardrail()
        self.assertEqual(guard.image_policy, "block")
        data = {"messages": [image_message()]}
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data, call_type="completion"
            )
        self.assertIn(self.ACTIVATION_HINT, str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
