"""Hardening of the stopword loader and its wiring (DATENSCHLE-82 / -88).

Covers the audit findings F4 (loader must verify absolute anchoring and
``regex_flags == 0`` for EVERY entry), F5-QA (operator precedence must hold
for case variants, because Presidio's deny_list matches case-insensitively)
and F5-Sec (every Presidio payload, including the verification pass, must
carry the allow_list fields; no analyzer needed).

Only the file given via ``DATENSCHLEUSE_STOPWORDS_PATH`` / ``stopwords_path``
is attacker- or operator-controlled input here; the shipped file keeps its
format.
"""
import asyncio
import json
import os
import sys
import tempfile
import unittest

import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402
import de_stopwords as ds  # noqa: E402

_RECOGNIZERS = os.path.normpath(os.path.join(_HERE, "..", "presidio", "recognizers-config.yml"))
_SHIPPED = os.path.normpath(os.path.join(_HERE, "..", "presidio", "de-stopwords.yml"))


def _write(tmp, patterns, **overrides):
    doc = {
        "version": 2,
        "allow_list_match": "regex",
        "regex_flags": 0,
        "entries": [{"term": "t%d" % i, "pattern": p} for i, p in enumerate(patterns)],
    }
    doc.update(overrides)
    path = os.path.join(tmp, "de-stopwords.yml")
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(doc, fh, allow_unicode=True)
    return path


def _load(path):
    return ds.load(stopwords_path=path, recognizers_path=_RECOGNIZERS)


class TestLoaderRequiresAbsoluteAnchoring(unittest.TestCase):
    """F4: an entry like ``(?i:meier)`` would suppress every span that merely
    CONTAINS the word ('Herr Meier'), because the analyzer uses ``search``."""

    def test_unanchored_patterns_are_rejected(self):
        unanchored = [
            "(?i:meier)",                  # the audit repro
            "meier",
            "(?i:\\Ameier)",               # start only
            "(?i:meier\\z)",               # end only
            "^meier$",                     # line anchors, not absolute
            "(?i:\\Aabc\\z|meier)",        # anchored alternative + free one
            "\\Aabc\\z|meier",
            "\\Aabc|def\\z",               # looks anchored, alternation splits it
        ]
        for pattern in unanchored:
            with self.subTest(pattern=pattern), tempfile.TemporaryDirectory() as tmp:
                path = _write(tmp, ["(?i:\\Abestellnummer\\z)", pattern])
                with self.assertRaises(ds.StopwordConfigError) as ctx:
                    _load(path)
                self.assertIn(pattern, str(ctx.exception), "message must name the entry")

    def test_unanchored_pattern_via_env_path_is_rejected(self):
        # The path an operator actually uses: DATENSCHLEUSE_STOPWORDS_PATH.
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, ["(?i:meier)"])
            old = os.environ.get("DATENSCHLEUSE_STOPWORDS_PATH")
            os.environ["DATENSCHLEUSE_STOPWORDS_PATH"] = path
            try:
                with self.assertRaises(ds.StopwordConfigError):
                    ds.load(recognizers_path=_RECOGNIZERS)
            finally:
                if old is None:
                    del os.environ["DATENSCHLEUSE_STOPWORDS_PATH"]
                else:
                    os.environ["DATENSCHLEUSE_STOPWORDS_PATH"] = old

    def test_anchored_forms_are_accepted(self):
        for pattern in ("(?i:\\Abestellnummer\\z)", "\\Abestellnummer\\z", "(?i:\\A(?:a|b)\\z)"):
            with self.subTest(pattern=pattern), tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(len(_load(_write(tmp, [pattern]))), 1)

    def test_shipped_file_still_loads(self):
        self.assertGreater(len(ds.load(stopwords_path=_SHIPPED, recognizers_path=_RECOGNIZERS)), 0)

    def test_guardrail_refuses_to_start_with_unanchored_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, ["(?i:meier)"])
            with self.assertRaises(ds.StopwordConfigError):
                dg.DatenschleuseGuardrail(
                    presidio_analyzer_url="http://nicht-erreichbar:3000",
                    image_policy="block",
                    stopwords_path=path,
                    recognizers_path=_RECOGNIZERS,
                )


class TestLoaderRequiresZeroRegexFlags(unittest.TestCase):
    """F4: ``regex_flags`` must be exactly 0. Any other int (MULTILINE = 8,
    IGNORECASE = 2, the analyzer default 26 ...) changes what the anchors mean."""

    def test_nonzero_flags_are_rejected(self):
        for flags in (2, 8, 16, 26, -1):
            with self.subTest(flags=flags), tempfile.TemporaryDirectory() as tmp:
                path = _write(tmp, ["(?i:\\Abestellnummer\\z)"], regex_flags=flags)
                with self.assertRaises(ds.StopwordConfigError) as ctx:
                    _load(path)
                self.assertIn("regex_flags", str(ctx.exception))

    def test_zero_flags_are_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(len(_load(_write(tmp, ["(?i:\\Abestellnummer\\z)"], regex_flags=0))), 1)


class TestOperatorPrecedenceCaseVariants(unittest.TestCase):
    """F5-QA: Presidio's deny_list matches case-insensitively, so a
    case-sensitive stopword pattern collides with a deny_list term even when
    it does not match the term in its configured spelling."""

    def test_lowercase_pattern_against_titlecase_deny_term_is_rejected(self):
        # recognizers-config.yml has "Bürgermeister" in DE_BERUF's deny_list.
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, ["\\Abürgermeister\\z"], regex_flags=0)
            with self.assertRaises(ds.StopwordConfigError) as ctx:
                _load(path)
        self.assertIn("Bürgermeister", str(ctx.exception))

    def test_uppercase_pattern_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, ["\\ABÜRGERMEISTER\\z"], regex_flags=0)
            with self.assertRaises(ds.StopwordConfigError):
                _load(path)

    def test_case_variants_that_collide_with_nothing_still_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, ["\\Abestellnummer\\z"], regex_flags=0)
            self.assertEqual(len(_load(path)), 1)


# --------------------------------------------------------------------------
# F5-Sec: all payloads, including the verification pass, carry the list.
# --------------------------------------------------------------------------
class _Resp:
    status_code = 200

    def raise_for_status(self):
        return None

    def json(self):
        return []


class TestEveryPresidioPayloadCarriesTheAllowList(unittest.IsolatedAsyncioTestCase):
    """No analyzer needed: httpx is replaced and ALL /analyze payloads of one
    tool-call masking run are recorded. The run contains the masking pass AND
    the verification pass (``_verify_no_pii_left``)."""

    async def _payloads(self):
        seen = []

        class _Client:
            def __init__(self, *a, **k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, url, json=None, **kw):  # noqa: A002
                seen.append((url, json))
                return _Resp()

        guard = dg.DatenschleuseGuardrail(
            presidio_analyzer_url="http://nicht-erreichbar:3000", image_policy="block"
        )
        orig = dg.httpx.AsyncClient
        dg.httpx.AsyncClient = _Client  # type: ignore[assignment]
        try:
            args = json.dumps({"q": "bestellnummer"})
            await guard.async_pre_call_hook(
                user_api_key_dict=None,
                cache=None,
                call_type="completion",
                data={
                    "messages": [
                        {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "c1",
                                    "type": "function",
                                    "function": {"name": "lookup", "arguments": args},
                                }
                            ],
                        }
                    ]
                },
            )
        finally:
            dg.httpx.AsyncClient = orig  # type: ignore[assignment]
        return seen

    async def test_masking_and_verification_payloads_all_carry_the_list(self):
        seen = await self._payloads()
        analyze = [p for url, p in seen if url.endswith("/analyze")]
        # Masking pass sees the string value, verification pass the JSON string.
        texts = [p["text"] for p in analyze]
        self.assertIn("bestellnummer", texts, "masking pass did not run")
        self.assertTrue(
            any('"q"' in t for t in texts),
            "verification pass did not run (no payload carries the JSON string): %r" % texts,
        )
        for payload in analyze:
            with self.subTest(text=payload["text"]):
                self.assertTrue(payload.get("allow_list"), "allow_list missing")
                self.assertEqual(payload.get("allow_list_match"), "regex")
                self.assertEqual(payload.get("regex_flags"), 0)


if __name__ == "__main__":
    unittest.main()
