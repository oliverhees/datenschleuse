"""The published proxy image must not start without a usable master key.

Finding H1 (DATENSCHLE-105): without ``DATENSCHLEUSE_MASTER_KEY`` LiteLLM
logs a warning and then lets every request through as an internal user while
the image listens on 0.0.0.0. The compose files stop that with
``${DATENSCHLEUSE_MASTER_KEY:?...}``; ``docker run`` of the image did not.

Decision: the check lives in the guardrail constructor, switched on by
``DATENSCHLEUSE_REQUIRE_MASTER_KEY`` which the image sets. Reasons:
* the constructor runs inside every start of the proxy with this config, also
  with ``docker run`` and ``--entrypoint`` replaced by the operator's wrapper;
* an entrypoint wrapper would have to know the base image's entrypoint path
  (not verifiable without Docker) and is skipped by ``--entrypoint``;
* the check looks at the key LiteLLM actually resolved, so an operator's own
  config with a different key source is judged by the same rule.
The flag is off in the code default so unit tests and library use are not
affected; only an explicit ``-e DATENSCHLEUSE_REQUIRE_MASTER_KEY=false``
switches it off in the image.

Runs without litellm and without a Presidio container.
"""

import os
import pathlib
import sys
import types
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_LITELLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "litellm"))
if _LITELLM_DIR not in sys.path:
    sys.path.insert(0, _LITELLM_DIR)

import datenschleuse_guardrail as dg  # noqa: E402

ROOT = pathlib.Path(_HERE).parent
REQUIRE = "DATENSCHLEUSE_REQUIRE_MASTER_KEY"
KEY = "DATENSCHLEUSE_MASTER_KEY"
GOOD = "sk-" + "a1" * 16
_CLEAN = {REQUIRE: "", KEY: ""}


def _env(**values):
    env = dict(_CLEAN)
    env.update(values)
    return mock.patch.dict(os.environ, env)


class TestRequiredKey(unittest.TestCase):
    def test_missing_key_refuses_to_start(self):
        with _env(**{REQUIRE: "true"}):
            os.environ.pop(KEY, None)
            with self.assertRaises(ValueError) as ctx:
                dg.DatenschleuseGuardrail()
        self.assertIn(KEY, str(ctx.exception))

    def test_empty_and_blank_key_refuse_to_start(self):
        for value in ("", "   ", "\n"):
            with self.subTest(value=value), _env(**{REQUIRE: "true", KEY: value}):
                with self.assertRaises(ValueError):
                    dg.DatenschleuseGuardrail()

    def test_wrong_form_refuses_to_start_without_leaking_the_value(self):
        for value in ("hunter2-not-a-key", "SK-upper", "sk-", "sk-short", "sk-" + "a" * 15, "sk-" + "a" * 15 + " x", "xsk-" + "a" * 20, " " + GOOD):
            with self.subTest(value=value), _env(**{REQUIRE: "true", KEY: value}):
                with self.assertRaises(ValueError) as ctx:
                    dg.DatenschleuseGuardrail()
                if len(value.strip()) > 3:
                    self.assertNotIn(value.strip(), str(ctx.exception))
                self.assertIn("sk-", str(ctx.exception))

    def test_good_key_starts(self):
        with _env(**{REQUIRE: "true", KEY: GOOD}):
            dg.DatenschleuseGuardrail()

    def test_flag_off_starts_without_key(self):
        for value in ("", "false", "0", "no", "off", "False"):
            with self.subTest(flag=value), _env(**{REQUIRE: value}):
                os.environ.pop(KEY, None)
                dg.DatenschleuseGuardrail()

    def test_any_other_flag_value_means_required(self):
        # Fail closed: a typo must not switch the protection off.
        for value in ("true", "1", "yes", "ja", "tru"):
            with self.subTest(flag=value), _env(**{REQUIRE: value}):
                os.environ.pop(KEY, None)
                with self.assertRaises(ValueError):
                    dg.DatenschleuseGuardrail()


class TestResolvedKeyOfTheProxy(unittest.TestCase):
    """Under the proxy the key LiteLLM resolved is what counts."""

    def _proxy_module(self, master_key):
        return types.ModuleType("litellm.proxy.proxy_server"), master_key

    def test_resolved_key_wins_over_the_variable(self):
        mod, key = self._proxy_module(GOOD)
        mod.master_key = key
        with _env(**{REQUIRE: "true"}), mock.patch.dict(sys.modules, {"litellm.proxy.proxy_server": mod}):
            os.environ.pop(KEY, None)
            dg.DatenschleuseGuardrail()  # literal key in the operator's config

    def test_proxy_without_key_refuses_even_if_variable_is_set(self):
        # e.g. an own config.yaml that never reads the variable
        mod, key = self._proxy_module(None)
        mod.master_key = key
        with _env(**{REQUIRE: "true", KEY: GOOD}), mock.patch.dict(sys.modules, {"litellm.proxy.proxy_server": mod}):
            with self.assertRaises(ValueError):
                dg.DatenschleuseGuardrail()

    def test_proxy_key_of_wrong_form_refuses(self):
        mod, key = self._proxy_module("changeme")
        mod.master_key = key
        with _env(**{REQUIRE: "true"}), mock.patch.dict(sys.modules, {"litellm.proxy.proxy_server": mod}):
            with self.assertRaises(ValueError) as ctx:
                dg.DatenschleuseGuardrail()
        self.assertNotIn("changeme", str(ctx.exception))


class TestImageWiring(unittest.TestCase):
    def test_dockerfile_requires_the_key(self):
        text = (ROOT / "litellm" / "Dockerfile").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^ENV DATENSCHLEUSE_REQUIRE_MASTER_KEY=true$")

    def test_smoke_test_covers_the_missing_key(self):
        text = (ROOT / "test" / "smoke-images.sh").read_text(encoding="utf-8")
        self.assertIn("check_refuses_without_key", text)
        for case in ('"variable not set"', '"empty"', '"wrong form"'):
            self.assertIn(f"check_refuses_without_key {case}", text)
        self.assertIn('-e "DATENSCHLEUSE_MASTER_KEY="', text)
        self.assertIn("is missing, empty or malformed", text)

    def test_shipped_config_reads_the_variable(self):
        text = (ROOT / "litellm" / "config.yaml").read_text(encoding="utf-8")
        self.assertIn("master_key: os.environ/DATENSCHLEUSE_MASTER_KEY", text)


if __name__ == "__main__":
    unittest.main()
