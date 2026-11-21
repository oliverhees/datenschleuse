"""Stable, machine-readable identification of a blocked request.

Background
----------
A request the guardrail refuses (``DatenschleuseBlocked``) reaches the client
through LiteLLM's generic exception path. Before this contract the response
was indistinguishable from any other proxy failure except by its free-text
message: HTTP 500, ``"type": "None"``, ``"code": "500"``. Clients that want to
tell "blocked on purpose, do not retry" apart from "upstream down, retry" had
to pattern-match German prose that changes with every new block reason.

The contract (docs/foundation/security-baseline.md, "Block-Antwort"):

* every block carries ``error.provider_specific_fields.datenschleuse`` with a
  fixed ``code`` (``datenschleuse_blocked``) and a ``reason`` from a closed
  set, plus the response header ``x-datenschleuse-error``;
* default mode ``compat`` keeps HTTP 500 and ``type "None"`` byte-for-byte,
  so existing clients that match on those keep working;
* opt-in mode ``strict`` (``DATENSCHLEUSE_BLOCK_RESPONSE=strict``) answers
  HTTP 422 with ``type "datenschleuse_blocked"``;
* an unknown mode refuses to start (same rule as ``image_policy``).

How LiteLLM turns the exception into a response is NOT re-implemented here.
These tests pin the attributes LiteLLM 1.97.0 reads in
``ProxyBaseLLMRequestProcessing._handle_llm_api_exception`` (``status_code``,
``type``, ``param``, ``message``, ``headers``, ``provider_specific_fields``).
The end-to-end shape against a real LiteLLM proxy is documented with the
measured responses in docs/foundation/security-baseline.md.

Runs without litellm and without a Presidio container.
"""

import os
import sys
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402
import sensitivity_classifier as sc  # noqa: E402

ENV = "DATENSCHLEUSE_BLOCK_RESPONSE"


def _raise_from(cause):
    try:
        try:
            raise cause
        except Exception as exc:
            raise dg.DatenschleuseBlocked(str(exc)) from exc
    except dg.DatenschleuseBlocked as blocked:
        return blocked


class TestContractConstants(unittest.TestCase):
    def test_code_is_fixed(self):
        self.assertEqual(dg.BLOCK_CODE, "datenschleuse_blocked")

    def test_reason_set_is_closed_and_documented(self):
        self.assertEqual(
            set(dg.BLOCK_REASONS),
            {
                "request_rejected",
                "sensitivity_tier_3",
                "sensitivity_tier_2_approval_required",
                "analyzer_unavailable",
                "custom_rules_incomplete",
            },
        )
        baseline = open(
            os.path.join(_HERE, "..", "docs", "foundation", "security-baseline.md"),
            encoding="utf-8",
        ).read()
        for reason in dg.BLOCK_REASONS:
            self.assertIn(f"`{reason}`", baseline, f"reason {reason} not documented")
        self.assertIn("`datenschleuse_blocked`", baseline)
        self.assertIn("x-datenschleuse-error", baseline)

    def test_modes(self):
        self.assertEqual(dg.BLOCK_RESPONSE_MODES, ("compat", "strict"))


class TestCompatModeKeepsTheOldWireShape(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop(ENV, None)

    def test_status_type_param_message_unchanged(self):
        exc = dg.DatenschleuseBlocked("Request blockiert (fail-closed).")
        self.assertEqual(exc.status_code, 500)
        # LiteLLM falls back to the string "None" for type/param -- the exact
        # value clients see today. It must stay that, not None and not a new name.
        self.assertEqual(getattr(exc, "type", "None"), "None")
        self.assertEqual(getattr(exc, "param", "None"), "None")
        self.assertEqual(getattr(exc, "message", str(exc)), "Request blockiert (fail-closed).")
        self.assertEqual(str(exc), "Request blockiert (fail-closed).")

    def test_machine_readable_fields(self):
        exc = dg.DatenschleuseBlocked("x")
        self.assertEqual(
            exc.provider_specific_fields,
            {"datenschleuse": {"code": "datenschleuse_blocked", "reason": "request_rejected"}},
        )
        self.assertEqual(exc.headers, {"x-datenschleuse-error": "datenschleuse_blocked"})

    def test_headers_and_fields_are_fresh_per_access(self):
        # LiteLLM calls headers.update(...) on what it gets -- a shared dict
        # would leak response headers from one request into the next.
        exc = dg.DatenschleuseBlocked("x")
        exc.headers["x-other"] = "1"
        exc.provider_specific_fields["datenschleuse"]["code"] = "tampered"
        self.assertEqual(exc.headers, {"x-datenschleuse-error": "datenschleuse_blocked"})
        self.assertEqual(exc.provider_specific_fields["datenschleuse"]["code"], "datenschleuse_blocked")

    def test_message_carries_no_new_text(self):
        # The stable code goes in its own field, never prepended to the message:
        # clients that show or log the message must not see a changed text.
        exc = dg.DatenschleuseBlocked("Original-Text")
        self.assertNotIn("datenschleuse_blocked", str(exc))


class TestReasons(unittest.TestCase):
    def setUp(self):
        os.environ.pop(ENV, None)

    def test_tier_3_is_derived_from_cause(self):
        exc = _raise_from(sc.Tier3Blocked("stufe 3"))
        self.assertEqual(exc.reason, "sensitivity_tier_3")
        self.assertEqual(exc.provider_specific_fields["datenschleuse"]["reason"], "sensitivity_tier_3")

    def test_tier_2_is_derived_from_cause(self):
        exc = _raise_from(sc.Tier2ApprovalRequired("stufe 2"))
        self.assertEqual(exc.reason, "sensitivity_tier_2_approval_required")

    def test_explicit_reason(self):
        exc = dg.DatenschleuseBlocked("x", reason="analyzer_unavailable")
        self.assertEqual(exc.reason, "analyzer_unavailable")

    def test_unknown_reason_is_a_programming_error(self):
        with self.assertRaises(ValueError):
            dg.DatenschleuseBlocked("x", reason="something_new")

    def test_other_cause_falls_back_to_request_rejected(self):
        exc = _raise_from(ValueError("kaputt"))
        self.assertEqual(exc.reason, "request_rejected")


class TestStrictMode(unittest.TestCase):
    def test_strict_changes_status_and_type_only(self):
        with mock.patch.dict(os.environ, {ENV: "strict"}):
            exc = dg.DatenschleuseBlocked("Text")
            self.assertEqual(exc.status_code, 422)
            self.assertEqual(exc.type, "datenschleuse_blocked")
            self.assertEqual(str(exc), "Text")
            self.assertEqual(exc.provider_specific_fields["datenschleuse"]["code"], "datenschleuse_blocked")
            self.assertEqual(exc.headers, {"x-datenschleuse-error": "datenschleuse_blocked"})

    def test_mode_value_is_normalised(self):
        with mock.patch.dict(os.environ, {ENV: "  STRICT "}):
            self.assertEqual(dg.DatenschleuseBlocked("x").status_code, 422)

    def test_unknown_mode_refuses_to_start(self):
        with mock.patch.dict(os.environ, {ENV: "vielleicht"}):
            with self.assertRaises(ValueError):
                dg.DatenschleuseGuardrail()

    def test_unknown_mode_at_runtime_stays_compat(self):
        # Construction refuses an unknown value; should the variable change
        # afterwards, the exception never invents a third shape.
        with mock.patch.dict(os.environ, {ENV: "vielleicht"}):
            exc = dg.DatenschleuseBlocked("x")
            self.assertEqual(exc.status_code, 500)
            self.assertEqual(getattr(exc, "type", "None"), "None")

    def test_known_modes_start(self):
        for mode in ("compat", "strict", ""):
            with self.subTest(mode=mode), mock.patch.dict(os.environ, {ENV: mode}):
                dg.DatenschleuseGuardrail()


class TestRaiseSitesTagTheirReason(unittest.IsolatedAsyncioTestCase):
    async def test_unreachable_analyzer_is_analyzer_unavailable(self):
        guard = dg.DatenschleuseGuardrail(presidio_analyzer_url="http://127.0.0.1:9", request_timeout=0.5)
        data = {"messages": [{"role": "user", "content": "Hallo"}]}
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data, call_type="completion"
            )
        self.assertEqual(ctx.exception.reason, "analyzer_unavailable")

    async def test_unchecked_field_is_request_rejected(self):
        guard = dg.DatenschleuseGuardrail(presidio_analyzer_url="http://127.0.0.1:9", request_timeout=0.5)
        data = {"messages": [{"role": "user", "content": "Hallo", "foo": "bar"}]}
        with self.assertRaises(dg.DatenschleuseBlocked) as ctx:
            await guard.async_pre_call_hook(
                user_api_key_dict=None, cache=None, data=data, call_type="completion"
            )
        self.assertEqual(ctx.exception.reason, "request_rejected")


if __name__ == "__main__":
    unittest.main()
