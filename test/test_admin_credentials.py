"""No example credential may protect a running proxy (DATENSCHLE-106).

Finding M4 (security audit, DATENSCHLE-105 round 3): ``.env.example`` shipped
an admin UI password that passed the compose ``:?`` guard because the guard
only rejects an unset or empty value. Finding L6 (round 4): the code default
of the credential check was "off" whenever the switch variable was absent.

Decision (ADR-0007): the checks live in the guardrail constructor, next to the
master-key check, behind the same switch. The constructor runs on every start
path (compose files, ``docker run``, an operator's own wrapper); an entrypoint
wrapper would be skipped by ``--entrypoint`` and cannot be verified without
Docker.

LiteLLM 1.97.0 facts these tests rest on (source read, see ADR-0007):
* ``proxy/auth/login_utils.py:71-74``: ``UI_PASSWORD`` that is set but empty
  stays empty (``os.getenv`` returns ``""``, only ``None`` falls back to the
  master key).
* ``proxy/proxy_server.py:13898`` ``POST /login`` does not look at
  ``DISABLE_ADMIN_UI``; it needs ``DATABASE_URL`` (``login_utils.py:197``).
  So the login surface exists whenever a database is configured.

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
GOOD_KEY = "sk-" + "a1" * 16
GOOD_PASSWORD = "p4ssw0rd-" + "x9" * 8  # 25 characters
DB_URL = "postgresql://datenschleuse:{pw}@datenschleuse-db:5432/datenschleuse"
_NAMES = (REQUIRE, KEY, "UI_PASSWORD", "UI_USERNAME", "DISABLE_ADMIN_UI", "DATABASE_URL")


def _env(**values):
    """Clean slate for every variable the checks read, then ``values``."""
    patcher = mock.patch.dict(os.environ, {}, clear=False)
    patcher.start()
    for name in _NAMES:
        os.environ.pop(name, None)
    os.environ.update(values)
    return patcher


class _Env(unittest.TestCase):
    def setUp(self):
        self._patchers = []

    def tearDown(self):
        # reverse order: each patcher restores the snapshot it took at start
        for patcher in reversed(self._patchers):
            patcher.stop()

    def env(self, **values):
        patcher = _env(**values)
        self._patchers.append(patcher)

    def assertRefuses(self, *needles):
        with self.assertRaises(ValueError) as ctx:
            dg.DatenschleuseGuardrail()
        for needle in needles:
            self.assertIn(needle, str(ctx.exception))
        return str(ctx.exception)


class TestAdminUiPassword(_Env):
    """M4: reject missing, empty, short and publicly known UI passwords."""

    base = {REQUIRE: "true", KEY: GOOD_KEY, "DATABASE_URL": DB_URL.format(pw="Zq" * 12)}

    def test_good_password_starts(self):
        self.env(**self.base, UI_PASSWORD=GOOD_PASSWORD)
        dg.DatenschleuseGuardrail()

    def test_empty_and_blank_password_refuse_to_start(self):
        for value in ("", "   ", "\t"):
            with self.subTest(value=value):
                self.env(**self.base, UI_PASSWORD=value, DISABLE_ADMIN_UI="True")
                self.assertRefuses("UI_PASSWORD")

    def test_short_password_refuses_without_leaking_it(self):
        for value in ("a", "secret", "x" * 15):
            with self.subTest(value=value):
                self.env(**self.base, UI_PASSWORD=value)
                message = self.assertRefuses("UI_PASSWORD", "16")
                if len(value) > 3:
                    self.assertNotIn(value, message)

    def test_every_shipped_example_password_is_rejected_without_leaking_it(self):
        for value in dg.KNOWN_PLACEHOLDER_PASSWORDS:
            for variant in (value, value.upper(), f" {value} "):
                with self.subTest(value=variant):
                    self.env(**self.base, UI_PASSWORD=variant)
                    message = self.assertRefuses("UI_PASSWORD", "placeholder")
                    self.assertNotIn(value, message.lower())

    def test_surrounding_whitespace_does_not_count_towards_the_length(self):
        # Security audit S-3: 15 spaces plus one character used to pass.
        for value in (" " * 15 + "x", "x" + " " * 15, "\t" * 8 + "abcdefgh", "  " + "x" * 13 + "  "):
            with self.subTest(value=repr(value)):
                self.env(**self.base, UI_PASSWORD=value)
                self.assertRefuses("UI_PASSWORD", "16")

    def test_a_password_of_exactly_16_real_characters_with_padding_starts(self):
        self.env(**self.base, UI_PASSWORD="  " + "x9" * 8 + "  ")
        dg.DatenschleuseGuardrail()

    def test_the_empty_password_has_its_own_message(self):
        # QA audit 2: removing the "empty" branch was not noticed, because the
        # length check still refuses -- only the wording changed.
        for value in ("", "   ", "\t"):
            with self.subTest(value=repr(value)):
                self.env(**self.base, UI_PASSWORD=value)
                message = self.assertRefuses("UI_PASSWORD", "is empty")
                self.assertNotIn("shorter than", message)

    def test_missing_password_refuses_when_the_ui_is_enabled(self):
        for disable in (None, "False", "false", "1", "yes", ""):
            with self.subTest(disable=disable):
                extra = {} if disable is None else {"DISABLE_ADMIN_UI": disable}
                self.env(**self.base, **extra)
                self.assertRefuses("UI_PASSWORD")

    def test_missing_password_is_fine_when_the_ui_is_disabled(self):
        # LiteLLM then uses the (validated) master key as password.
        for disable in ("True", "true", " TRUE "):
            with self.subTest(disable=disable):
                self.env(**self.base, DISABLE_ADMIN_UI=disable)
                dg.DatenschleuseGuardrail()

    def test_disabled_ui_does_not_excuse_a_weak_password(self):
        # POST /login ignores DISABLE_ADMIN_UI (LiteLLM 1.97.0), so a weak
        # password is a risk whenever the database is there.
        self.env(**self.base, UI_PASSWORD="aendere-mich", DISABLE_ADMIN_UI="True")
        self.assertRefuses("UI_PASSWORD")

    def test_without_database_there_is_no_login_and_no_check(self):
        self.env(**{REQUIRE: "true", KEY: GOOD_KEY, "UI_PASSWORD": "aendere-mich"})
        dg.DatenschleuseGuardrail()

    def test_opt_out_switch_skips_the_check(self):
        self.env(**{**self.base, REQUIRE: "false"}, UI_PASSWORD="aendere-mich")
        dg.DatenschleuseGuardrail()

    def test_env_example_password_does_not_start(self):
        values = _env_example()
        self.env(**self.base, UI_PASSWORD=values["UI_PASSWORD"], UI_USERNAME=values["UI_USERNAME"])
        self.assertRefuses("UI_PASSWORD")


class TestDatabasePassword(_Env):
    """The example database password must not start the proxy either."""

    def test_every_shipped_example_password_in_the_url_is_rejected(self):
        for value in dg.KNOWN_PLACEHOLDER_PASSWORDS:
            with self.subTest(value=value):
                self.env(**{REQUIRE: "true", KEY: GOOD_KEY, "UI_PASSWORD": GOOD_PASSWORD, "DATABASE_URL": DB_URL.format(pw=value)})
                message = self.assertRefuses("DATENSCHLEUSE_DB_PASSWORD", "placeholder")
                self.assertNotIn(value, message.lower().replace("datenschleuse_db_password", ""))

    def test_own_password_starts(self):
        self.env(**{REQUIRE: "true", KEY: GOOD_KEY, "UI_PASSWORD": GOOD_PASSWORD, "DATABASE_URL": DB_URL.format(pw="Zq" * 12)})
        dg.DatenschleuseGuardrail()

    def test_a_known_password_as_query_parameter_is_rejected(self):
        # Security audit S-5. Whether Prisma reads ``?password=`` is not
        # verified; refusing a known value there costs nothing.
        base = "postgresql://datenschleuse@datenschleuse-db:5432/datenschleuse"
        for value in dg.KNOWN_PLACEHOLDER_PASSWORDS:
            for query in (f"?password={value}", f"?sslmode=disable&password={value}", f"?password={value.upper()}", f"?PASSWORD=%20{value}%20"):
                with self.subTest(query=query):
                    self.env(**{REQUIRE: "true", KEY: GOOD_KEY, "UI_PASSWORD": GOOD_PASSWORD, "DATABASE_URL": base + query})
                    message = self.assertRefuses("DATENSCHLEUSE_DB_PASSWORD", "placeholder")
                    self.assertNotIn(value, message.lower().replace("datenschleuse_db_password", ""))

    def test_a_percent_encoded_known_password_in_the_user_info_is_rejected(self):
        # QA audit 3, I-1: ``urlsplit(...).password`` keeps the percent
        # encoding, so ``%64atenschleuse`` is ``datenschleuse`` to the driver
        # but not to a plain comparison. ``unquote`` in
        # ``_database_password_candidates`` closes that.
        import urllib.parse

        for value in dg.KNOWN_PLACEHOLDER_PASSWORDS:
            encodings = {
                "first letter": "%" + format(ord(value[0]), "02X") + value[1:],
                "dash": value.replace("-", "%2D"),
                "everything": urllib.parse.quote(value, safe="").replace("a", "%61").replace("e", "%65"),
                "lower-case hex": "%" + format(ord(value[0]), "02x") + value[1:],
            }
            for label, encoded in encodings.items():
                if encoded == value:
                    continue  # this value has no dash to encode
                with self.subTest(value=value, encoding=label):
                    self.env(**{REQUIRE: "true", KEY: GOOD_KEY, "UI_PASSWORD": GOOD_PASSWORD, "DATABASE_URL": DB_URL.format(pw=encoded)})
                    message = self.assertRefuses("DATENSCHLEUSE_DB_PASSWORD", "placeholder")
                    self.assertNotIn(value, message.lower().replace("datenschleuse_db_password", ""))

    def test_an_encoded_own_password_in_the_user_info_starts(self):
        # Counter-case: decoding must not turn a good password into a refusal.
        self.env(**{REQUIRE: "true", KEY: GOOD_KEY, "UI_PASSWORD": GOOD_PASSWORD, "DATABASE_URL": DB_URL.format(pw="Zq%2Fx" * 5)})
        dg.DatenschleuseGuardrail()

    def test_an_own_password_as_query_parameter_starts(self):
        base = "postgresql://datenschleuse@datenschleuse-db:5432/datenschleuse"
        self.env(**{REQUIRE: "true", KEY: GOOD_KEY, "UI_PASSWORD": GOOD_PASSWORD, "DATABASE_URL": base + "?password=" + "Zq" * 12})
        dg.DatenschleuseGuardrail()
        self.env(**{REQUIRE: "true", KEY: GOOD_KEY, "UI_PASSWORD": GOOD_PASSWORD, "DATABASE_URL": base + "?sslmode=disable&application_name=datenschleuse"})
        dg.DatenschleuseGuardrail()

    def test_unparsable_url_never_leaks_and_does_not_crash(self):
        self.env(**{REQUIRE: "true", KEY: GOOD_KEY, "UI_PASSWORD": GOOD_PASSWORD, "DATABASE_URL": "not a url ::: [secret"})
        dg.DatenschleuseGuardrail()

    def test_env_example_database_password_is_not_a_usable_value(self):
        self.assertEqual(_env_example()["DATENSCHLEUSE_DB_PASSWORD"], "")


class TestSwitchDefaultByContext(_Env):
    """L6: under the proxy the check is ON when the switch is absent."""

    def _proxy_module(self, master_key=None):
        mod = types.ModuleType("litellm.proxy.proxy_server")
        mod.master_key = master_key
        return mock.patch.dict(sys.modules, {"litellm.proxy.proxy_server": mod})

    def test_absent_switch_under_the_proxy_requires_a_key(self):
        self.env()
        with self._proxy_module(None):
            self.assertRefuses(KEY)

    def test_empty_switch_under_the_proxy_requires_a_key(self):
        for value in ("", "  "):
            with self.subTest(value=value):
                self.env(**{REQUIRE: value})
                with self._proxy_module(None):
                    self.assertRefuses(KEY)

    def test_absent_switch_under_the_proxy_with_a_good_key_starts(self):
        self.env()
        with self._proxy_module(GOOD_KEY):
            dg.DatenschleuseGuardrail()

    def test_absent_switch_under_the_proxy_also_checks_the_ui_password(self):
        self.env(UI_PASSWORD="aendere-mich", DATABASE_URL=DB_URL.format(pw="Zq" * 12))
        with self._proxy_module(GOOD_KEY):
            self.assertRefuses("UI_PASSWORD")

    def test_explicit_opt_out_values_still_work_under_the_proxy(self):
        for value in ("false", "0", "no", "off", "False", " OFF ", "NO"):
            with self.subTest(value=value):
                self.env(**{REQUIRE: value})
                with self._proxy_module(None):
                    dg.DatenschleuseGuardrail()

    def test_any_other_value_means_required_under_the_proxy(self):
        for value in ("true", "1", "yes", "flase", "tru"):
            with self.subTest(value=value):
                self.env(**{REQUIRE: value})
                with self._proxy_module(None):
                    self.assertRefuses(KEY)

    def test_without_the_proxy_the_absent_switch_stays_off(self):
        # Unit tests and library use construct the guardrail without the
        # proxy server module; they need no key.
        self.env()
        with mock.patch.dict(sys.modules):
            sys.modules.pop("litellm.proxy.proxy_server", None)
            dg.DatenschleuseGuardrail()
            os.environ[REQUIRE] = ""
            dg.DatenschleuseGuardrail()

    def test_explicit_true_without_the_proxy_still_requires(self):
        self.env(**{REQUIRE: "true"})
        with mock.patch.dict(sys.modules):
            sys.modules.pop("litellm.proxy.proxy_server", None)
            self.assertRefuses(KEY)


def _env_example():
    values = {}
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            name, _, value = line.partition("=")
            values[name] = value
    return values


class TestEnvExampleShipsNoUsableSecret(unittest.TestCase):
    def test_every_secret_slot_is_empty_or_unusable(self):
        values = _env_example()
        self.assertEqual(values["DATENSCHLEUSE_MASTER_KEY"], "")
        self.assertEqual(values["UI_PASSWORD"], "")
        self.assertEqual(values["DATENSCHLEUSE_DB_PASSWORD"], "")

    def test_state_key_example_is_no_valid_fernet_key(self):
        # Harmless by construction: the QI store refuses to start with it.
        import qi_state

        with self.assertRaises(qi_state.QiStateError):
            qi_state.QiStateStore(db_path=":memory:", fernet_key=_env_example()["DATENSCHLEUSE_STATE_KEY"].encode())

    def test_upstream_key_example_authenticates_nothing_here(self):
        # EUROUTER_API_KEY is the key the proxy SENDS to the upstream; it is
        # not a credential for the proxy. The example is rejected upstream.
        self.assertEqual(_env_example()["EUROUTER_API_KEY"], "sk-dein-eurouter-key")
        self.assertIn("sk-dein-eurouter-key", dg.KNOWN_PLACEHOLDER_MASTER_KEYS)

    def test_comments_do_not_claim_a_default_that_is_not_there(self):
        text = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertNotIn("aendere-mich", text)
        self.assertRegex(text, r"(?s)UI_PASSWORD.{0,400}openssl rand -hex 32")


def _services(path):
    import yaml

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data.get("services") or {}


def _env_map(svc):
    env = svc.get("environment") or []
    if isinstance(env, dict):
        return {k: str(v) for k, v in env.items()}
    return {item.split("=", 1)[0]: item.split("=", 1)[1] for item in map(str, env) if "=" in item}


COMPOSE_FILES = (
    ROOT / "docker-compose.yml",
    ROOT / "deploy" / "coolify" / "docker-compose.yaml",
)


class TestComposeWiring(unittest.TestCase):
    """Every compose file that gives the proxy a database must refuse an
    empty admin or database password (``:?``), and no compose file may carry
    a default for either."""

    def test_proxy_with_a_database_requires_ui_and_db_password(self):
        checked = 0
        for path in COMPOSE_FILES:
            svc = _services(path)["datenschleuse"]
            env = _env_map(svc)
            with self.subTest(file=str(path.relative_to(ROOT))):
                self.assertIn("DATABASE_URL", env)
                checked += 1
                self.assertRegex(env["UI_PASSWORD"], r"^\$\{UI_PASSWORD:\?[^}]+\}$")
                self.assertRegex(env["DATABASE_URL"], r":\$\{DATENSCHLEUSE_DB_PASSWORD:\?[^}]+\}@")
        self.assertEqual(checked, 2)

    def test_database_container_requires_its_password(self):
        for path in COMPOSE_FILES:
            env = _env_map(_services(path)["datenschleuse-db"])
            with self.subTest(file=str(path.relative_to(ROOT))):
                self.assertRegex(env["POSTGRES_PASSWORD"], r"^\$\{DATENSCHLEUSE_DB_PASSWORD:\?[^}]+\}$")

    def test_no_compose_file_defaults_a_password(self):
        for path in sorted(ROOT.rglob("*compose*.y*ml")):
            if ".git" in path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            with self.subTest(file=str(path.relative_to(ROOT))):
                self.assertNotRegex(text, r"\$\{(DATENSCHLEUSE_DB_PASSWORD|UI_PASSWORD)[:]?-")

    def test_compose_still_refuses_an_empty_value_with_a_named_variable(self):
        # ``:?`` rejects unset AND empty; the message names the variable.
        for path in COMPOSE_FILES:
            text = path.read_text(encoding="utf-8")
            self.assertIn("UI_PASSWORD muss", text)
            self.assertIn("DATENSCHLEUSE_DB_PASSWORD muss", text)


SHIPPED_EXAMPLES = {
    # value ever shipped in the tree or the history (git log -S, 2026-11-21)
    # -> disposition
    "sk-datenschleuse-lokal": "rejected",
    "sk-dein-eurouter-key": "rejected",
    "sk-1234": "rejected",
    "sk-smoke-upstream-dummy": "rejected",
    "sk-e2e-local-ollama": "rejected",
    "aendere-mich": "rejected",
    "aendere-mich-starkes-passwort": "rejected",
    "datenschleuse": "rejected",
    "hier-einen-fernet-key-eintragen": "harmless",
}


class TestEveryShippedExampleIsAccountedFor(unittest.TestCase):
    def test_rejected_values_are_in_the_code_lists(self):
        for value, disposition in SHIPPED_EXAMPLES.items():
            if disposition != "rejected":
                continue
            with self.subTest(value=value):
                self.assertTrue(
                    value in dg.KNOWN_PLACEHOLDER_MASTER_KEYS or value in dg.KNOWN_PLACEHOLDER_PASSWORDS,
                    value,
                )

    def test_the_harmless_value_is_documented_with_its_reason(self):
        text = (ROOT / "docs" / "adr" / "0007-example-credentials-rejected.md").read_text(encoding="utf-8")
        for value, disposition in SHIPPED_EXAMPLES.items():
            if disposition == "harmless":
                self.assertIn(value, text)
        self.assertIn("Fernet", text)

    def test_the_database_user_and_name_are_not_secrets(self):
        # ``datenschleuse`` as user name and database name is a name, not a
        # credential; only its use as a PASSWORD is rejected.
        values = _env_example()
        self.assertEqual(values["DATENSCHLEUSE_DB_USER"], "datenschleuse")


class TestMessagesSurviveLiteLlmLogRedaction(_Env):
    """QA audit 2, F3: LiteLLM 1.97.0 scrubs log lines with ``redact_string``
    (``litellm/litellm_core_utils/secret_redaction.py``, line 83, the regex in
    ``_build_secret_patterns``, lines 47 to 50: ``<name>password`` followed by
    ``:`` or ``=`` and a word). The hint "Generate your own password: openssl
    ..." came out as "Generate your own REDACTED rand -hex 32". The start-up
    message must reach the log unchanged, so the same function is applied to
    every refusal message here."""

    def _redact(self):
        try:
            from litellm.litellm_core_utils.secret_redaction import redact_string
        except Exception as exc:  # litellm not installed
            if os.environ.get("DS_REQUIRE_LITELLM"):
                # CI installs the pinned version and sets this: a missing
                # import must not turn these tests into silent skips again.
                self.fail(f"DS_REQUIRE_LITELLM is set but litellm is not importable: {exc}")
            self.skipTest(f"litellm not importable: {exc}")
        return redact_string

    def _messages(self):
        good = {REQUIRE: "true", KEY: GOOD_KEY, "UI_PASSWORD": GOOD_PASSWORD, "DATABASE_URL": DB_URL.format(pw="Zq" * 12)}
        cases = [
            {**good, "UI_PASSWORD": "aendere-mich"},
            {**good, "UI_PASSWORD": ""},
            {**good, "UI_PASSWORD": "short"},
            {**good, "DATABASE_URL": DB_URL.format(pw="datenschleuse")},
            {**good, "DATABASE_URL": "postgresql://u@h/d?password=datenschleuse"},
            {k: v for k, v in good.items() if k != "UI_PASSWORD"},
            {**good, KEY: "sk-datenschleuse-lokal"},
            {**good, KEY: "changeme"},
        ]
        messages = []
        for case in cases:
            self.env(**case)
            with self.assertRaises(ValueError) as ctx:
                dg.DatenschleuseGuardrail()
            messages.append(str(ctx.exception))
        return messages

    def test_the_redaction_does_hit_the_old_wording(self):
        # Proves the check below can fail: the old hint is rewritten.
        redact = self._redact()
        old = "UI_PASSWORD is a publicly known placeholder: refusing to start. Generate your own password: openssl rand -hex 32. docs/DEPLOY.md."
        self.assertNotEqual(redact(old), old)
        self.assertIn("REDACTED", redact(old))

    def test_every_refusal_message_is_unchanged_by_the_redaction(self):
        redact = self._redact()
        for message in self._messages():
            with self.subTest(message=message[:60]):
                self.assertEqual(redact(message), message)
                self.assertNotIn("REDACTED", message)


class TestInitEnvScript(unittest.TestCase):
    """README quick start: a fresh user ends up with generated credentials."""

    script = ROOT / "tools" / "init-env.sh"

    def _run(self, workdir, *args):
        import subprocess

        return subprocess.run(["bash", str(self.script), *args], capture_output=True, text=True, cwd=workdir, timeout=60)

    def _prepare(self, tmp):
        import shutil

        root = pathlib.Path(tmp)
        (root / "tools").mkdir()
        shutil.copy(self.script, root / "tools" / "init-env.sh")
        shutil.copy(ROOT / ".env.example", root / ".env.example")
        return root

    def test_script_exists_and_is_executable(self):
        self.assertTrue(self.script.is_file())
        self.assertTrue(os.access(self.script, os.X_OK))

    def test_generates_credentials_that_the_proxy_accepts(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = self._prepare(tmp)
            result = subprocess_run(["bash", str(root / "tools" / "init-env.sh")], root)
            self.assertEqual(result.returncode, 0, result.stderr)
            env_file = root / ".env"
            self.assertTrue(env_file.is_file())
            self.assertEqual(env_file.stat().st_mode & 0o777, 0o600)
            values = {}
            for line in env_file.read_text(encoding="utf-8").splitlines():
                if line and not line.startswith("#") and "=" in line:
                    name, _, value = line.partition("=")
                    values[name] = value
            example = _env_example()
            self.assertEqual(set(values), set(example))
            # unchanged non-secret settings
            self.assertEqual(values["UI_USERNAME"], example["UI_USERNAME"])
            self.assertEqual(values["DATENSCHLEUSE_DB_USER"], example["DATENSCHLEUSE_DB_USER"])
            # generated, different from every shipped example, accepted by the checks
            for name in ("DATENSCHLEUSE_MASTER_KEY", "UI_PASSWORD", "DATENSCHLEUSE_DB_PASSWORD", "DATENSCHLEUSE_STATE_KEY"):
                self.assertNotEqual(values[name], example[name], name)
                self.assertNotIn(values[name].lower(), tuple(SHIPPED_EXAMPLES), name)
            self.assertEqual(len({values[n] for n in ("DATENSCHLEUSE_MASTER_KEY", "UI_PASSWORD", "DATENSCHLEUSE_DB_PASSWORD")}), 3)
            with mock.patch.dict(os.environ, {}, clear=False):
                for name in _NAMES:
                    os.environ.pop(name, None)
                os.environ.update(
                    {
                        REQUIRE: "true",
                        KEY: values["DATENSCHLEUSE_MASTER_KEY"],
                        "UI_PASSWORD": values["UI_PASSWORD"],
                        "DATABASE_URL": DB_URL.format(pw=values["DATENSCHLEUSE_DB_PASSWORD"]),
                    }
                )
                dg.DatenschleuseGuardrail()
            from cryptography.fernet import Fernet

            Fernet(values["DATENSCHLEUSE_STATE_KEY"].encode())
            # the secrets never appear on the console
            for name in ("DATENSCHLEUSE_MASTER_KEY", "UI_PASSWORD", "DATENSCHLEUSE_DB_PASSWORD", "DATENSCHLEUSE_STATE_KEY"):
                self.assertNotIn(values[name], result.stdout + result.stderr)
            # the one value the user must bring is named
            self.assertIn("EUROUTER_API_KEY", result.stdout)

    def test_never_overwrites_an_existing_env_file(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = self._prepare(tmp)
            (root / ".env").write_text("KEEP=me\n", encoding="utf-8")
            result = subprocess_run(["bash", str(root / "tools" / "init-env.sh")], root)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((root / ".env").read_text(encoding="utf-8"), "KEEP=me\n")
            self.assertIn(".env", result.stderr)

    def test_two_runs_produce_different_secrets(self):
        import tempfile

        values = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as tmp:
                root = self._prepare(tmp)
                self.assertEqual(subprocess_run(["bash", str(root / "tools" / "init-env.sh")], root).returncode, 0)
                values.append(dict(line.split("=", 1) for line in (root / ".env").read_text(encoding="utf-8").splitlines() if line and not line.startswith("#") and "=" in line))
        self.assertNotEqual(values[0]["DATENSCHLEUSE_MASTER_KEY"], values[1]["DATENSCHLEUSE_MASTER_KEY"])

    # --- failure handling (QA audit 2 F2, security audit S-1) -----------------

    def _shim(self, tmp, body):
        """A directory with an ``openssl`` that runs ``body`` (sh), put first
        on the PATH; ``REAL_OPENSSL`` points at the real one."""
        import shutil

        real = shutil.which("openssl")
        if real is None:
            self.skipTest("openssl not installed")
        bindir = pathlib.Path(tmp) / "shim-bin"
        bindir.mkdir()
        shim = bindir / "openssl"
        shim.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        shim.chmod(0o755)
        return {"PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}", "REAL_OPENSSL": real}

    def _run_with(self, root, extra_env):
        import subprocess

        env = dict(os.environ)
        env.update(extra_env)
        return subprocess.run(["bash", str(root / "tools" / "init-env.sh")], capture_output=True, text=True, cwd=root, timeout=60, env=env)

    def _assert_nothing_left(self, root):
        self.assertFalse((root / ".env").exists() or (root / ".env").is_symlink())
        self.assertEqual([p.name for p in root.glob(".env.*") if p.name != ".env.example"], [])

    def test_failing_openssl_exits_non_zero_and_leaves_no_env(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = self._prepare(tmp)
            result = self._run_with(root, self._shim(tmp, "exit 1\n"))
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("Erzeugt", result.stdout)
            self._assert_nothing_left(root)

    def test_failing_openssl_in_a_later_call_leaves_no_env(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = self._prepare(tmp)
            counter = pathlib.Path(tmp) / "count"
            body = (
                f'n=$(cat "{counter}" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "{counter}"\n'
                'if [ "$n" -ge 3 ]; then exit 1; fi\nexec "$REAL_OPENSSL" "$@"\n'
            )
            result = self._run_with(root, self._shim(tmp, body))
            self.assertNotEqual(result.returncode, 0)
            self._assert_nothing_left(root)

    def test_malformed_generated_values_are_refused_before_writing(self):
        import tempfile

        for output in ("", "abc", "g" * 64, "a" * 63, "a" * 65, "not base64 at all!"):
            with self.subTest(output=output), tempfile.TemporaryDirectory() as tmp:
                root = self._prepare(tmp)
                result = self._run_with(root, self._shim(tmp, f"printf '%s\\n' '{output}'\n"))
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Erzeugt", result.stdout)
                self._assert_nothing_left(root)

    def test_a_malformed_hex_value_is_refused_whichever_call_it_comes_from(self):
        # QA audit 3, L-2: the test above feeds ONE output to every call, so
        # the three hex form checks (master key, UI password, database
        # password) could be removed without a red test (the base64 check
        # alone caught everything). Here only `-hex` output is bad, `-base64`
        # is the real one, and each of the three hex calls is the bad one in
        # turn.
        import tempfile

        for bad_call in (1, 2, 3):
            for output in ("", "abc", "g" * 64, "a" * 63, "a" * 65):
                with self.subTest(bad_call=bad_call, output=output), tempfile.TemporaryDirectory() as tmp:
                    root = self._prepare(tmp)
                    counter = pathlib.Path(tmp) / "count"
                    body = (
                        f'n=$(cat "{counter}" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "{counter}"\n'
                        f'case "$*" in *-hex*) if [ "$n" -eq {bad_call} ]; then printf "%s\\n" "{output}"; exit 0; fi;; esac\n'
                        'exec "$REAL_OPENSSL" "$@"\n'
                    )
                    result = self._run_with(root, self._shim(tmp, body))
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("unerwartete Form", result.stderr)
                    self.assertNotIn("Erzeugt", result.stdout)
                    self._assert_nothing_left(root)

    def test_a_malformed_base64_value_is_refused_while_the_hex_values_are_good(self):
        import tempfile

        for output in ("", "abc", "x" * 43, "not base64 at all!", "a" * 44):
            with self.subTest(output=output), tempfile.TemporaryDirectory() as tmp:
                root = self._prepare(tmp)
                body = f'case "$*" in *-base64*) printf "%s\\n" "{output}"; exit 0;; esac\nexec "$REAL_OPENSSL" "$@"\n'
                result = self._run_with(root, self._shim(tmp, body))
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("State-Key", result.stderr)
                self._assert_nothing_left(root)

    def test_a_good_openssl_shim_still_works(self):
        # The shim machinery itself must not be what makes the tests red.
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = self._prepare(tmp)
            result = self._run_with(root, self._shim(tmp, 'exec "$REAL_OPENSSL" "$@"\n'))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / ".env").is_file())

    # --- never replace an existing target (security audit S-2, QA note) -------

    def test_an_env_created_while_the_script_runs_is_not_replaced(self):
        # The race: .env appears between the first check and the final step.
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = self._prepare(tmp)
            body = f'printf "KEEP=me\\n" > "{root}/.env"\nexec "$REAL_OPENSSL" "$@"\n'
            result = self._run_with(root, self._shim(tmp, body))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((root / ".env").read_text(encoding="utf-8"), "KEEP=me\n")
            self.assertEqual([p.name for p in root.glob(".env.*") if p.name != ".env.example"], [])

    def test_a_dangling_symlink_is_refused_not_replaced(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = self._prepare(tmp)
            (root / ".env").symlink_to(root / "nowhere" / "target.env")
            result = subprocess_run(["bash", str(root / "tools" / "init-env.sh")], root)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((root / ".env").is_symlink())
            self.assertEqual(os.readlink(root / ".env"), str(root / "nowhere" / "target.env"))
            self.assertFalse((root / "nowhere").exists())
            self.assertIn("Symlink", result.stderr)
            self.assertEqual([p.name for p in root.glob(".env.*") if p.name != ".env.example"], [])

    def test_a_symlink_to_an_existing_file_is_refused_and_the_file_untouched(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = self._prepare(tmp)
            real = root / "real.env"
            real.write_text("KEEP=me\n", encoding="utf-8")
            (root / ".env").symlink_to(real)
            result = subprocess_run(["bash", str(root / "tools" / "init-env.sh")], root)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(real.read_text(encoding="utf-8"), "KEEP=me\n")
            self.assertTrue((root / ".env").is_symlink())
            self.assertIn("Symlink", result.stderr)

    def test_shellcheck_clean_if_available(self):
        import shutil

        if shutil.which("shellcheck") is None:
            self.skipTest("shellcheck not installed")
        result = subprocess_run(["shellcheck", str(self.script)], ROOT)
        self.assertEqual(result.returncode, 0, result.stdout)


def subprocess_run(cmd, cwd):
    import subprocess

    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=60)


class TestDocsStayInStep(unittest.TestCase):
    """Audit round 4, info 1: one list of opt-out values everywhere."""

    def _text(self, *parts):
        return (ROOT.joinpath(*parts)).read_text(encoding="utf-8")

    def test_deploy_names_every_opt_out_value_and_the_precedence(self):
        text = self._text("docs", "DEPLOY.md")
        section = text.split("Beispiel-Zugangsdaten werden abgelehnt", 1)[1]
        for value in dg.OPT_OUT_VALUES:
            self.assertIn(f"`{value}`", section)
        self.assertIn("Gross-/Kleinschreibung", section.replace("Groß-/Kleinschreibung", "Gross-/Kleinschreibung"))
        self.assertIn("Shell", section)

    def test_adr_names_every_opt_out_value(self):
        text = self._text("docs", "adr", "0007-example-credentials-rejected.md")
        for value in dg.OPT_OUT_VALUES:
            self.assertIn(f"`{value}`", text)

    def test_adr_6_points_to_the_addendum(self):
        text = self._text("docs", "adr", "0006-veroeffentlichte-images-und-block-kennung.md")
        self.assertIn("ADR-0007", text)

    def test_deploy_update_table_has_the_new_rows(self):
        text = self._text("docs", "DEPLOY.md")
        update = text.split("Sichere Standards und was sich beim Update", 1)[1]
        self.assertRegex(update, r"(?m)^\| Admin-UI-Passwort \|")
        self.assertRegex(update, r"(?m)^\| Datenbank-Passwort \|")
        self.assertRegex(update, r"(?m)^\| Schalter .{0,60}REQUIRE_MASTER_KEY")

    def test_readme_quickstart_generates_credentials(self):
        readme = self._text("README.md")
        quick = readme.split("## 🚀 Quickstart", 1)[1].split("Deine Tools sprechen", 1)[0]
        self.assertIn("tools/init-env.sh", quick)
        self.assertNotRegex(quick, r"(?m)^cp \.env\.example \.env")

    def test_env_example_documents_the_switch_values(self):
        text = self._text(".env.example")
        self.assertIn("DATENSCHLEUSE_REQUIRE_MASTER_KEY", text)
        for value in dg.OPT_OUT_VALUES:
            self.assertIn(value, text.split("Zugangsdaten-Pruefung beim Start", 1)[1][:1200])
        self.assertRegex(text, r"(?m)^# DATENSCHLEUSE_REQUIRE_MASTER_KEY=")

    def test_coolify_template_describes_the_password_rules(self):
        import json

        variables = {v["key"]: v for v in json.loads(self._text("coolify-template.json"))["variables"]}
        self.assertIn("16", variables["UI_PASSWORD"]["description"])
        self.assertIn("Beispiel", variables["UI_PASSWORD"]["description"])
        self.assertIn("Beispiel", variables["DATENSCHLEUSE_DB_PASSWORD"]["description"])
        self.assertTrue(variables["UI_PASSWORD"]["required"])
        self.assertEqual(variables["UI_PASSWORD"]["generate"], "random_hex_32")


class TestDatabasePasswordChangeIsDocumentedPerInstallPath(unittest.TestCase):
    """QA audit 2, F1: the update steps for the database password must be
    right for every install path the document defines, not only for the
    compose file in the repository root."""

    HEADING = "#### Datenbank-Passwort in einer bestehenden Installation ändern"

    def setUp(self):
        self.text = (ROOT / "docs" / "DEPLOY.md").read_text(encoding="utf-8")
        self.assertIn(self.HEADING, self.text, "section for changing the database password is missing")
        self.section = self.text.split(self.HEADING, 1)[1].split("\n### ", 1)[0]

    def _blocks(self):
        """Label -> text, one block per ``**Weg X ...**`` paragraph."""
        import re

        parts = re.split(r"(?m)^(?=\*\*Weg [A-Z])", self.section)
        return {part.split("\n", 1)[0]: part for part in parts if part.startswith("**Weg ")}

    def test_every_install_path_of_the_document_has_its_own_block(self):
        import re

        defined = sorted(set(re.findall(r"(?m)^## Weg ([A-Z]) ", self.text)))
        self.assertGreaterEqual(len(defined), 3, defined)
        labels = list(self._blocks())
        for letter in defined:
            with self.subTest(path=f"Weg {letter}"):
                self.assertTrue(any(label.startswith(f"**Weg {letter}") for label in labels), labels)

    def test_weg_b_has_both_compose_files_and_the_coolify_file_uses_dash_f(self):
        labels = list(self._blocks())
        repo = [b for label, b in self._blocks().items() if "docker-compose.yml" in label]
        coolify = [b for label, b in self._blocks().items() if "deploy/coolify/docker-compose.yaml" in label]
        self.assertEqual(len(repo), 1, labels)
        self.assertEqual(len(coolify), 1, labels)
        for block in coolify:
            for command in ("exec", "down", "up"):
                self.assertRegex(block, rf"docker compose --env-file \.env -f deploy/coolify/docker-compose\.yaml {command}\b")

    def test_no_compose_command_in_a_block_addresses_the_wrong_file(self):
        import re

        for label, block in self._blocks().items():
            commands = [ln for ln in block.splitlines() if re.match(r"\s*(\S+=\S+ )?docker compose ", ln.strip()) and not ln.strip().startswith("#")]
            with self.subTest(label=label):
                if "deploy/coolify/docker-compose.yaml" in label:
                    self.assertTrue(commands)
                    for ln in commands:
                        self.assertIn("--env-file .env -f deploy/coolify/docker-compose.yaml", ln)
                elif "docker-compose.yml" in label:
                    self.assertTrue(commands)
                    for ln in commands:
                        self.assertNotIn(" -f ", ln)
                elif label.startswith("**Weg A"):
                    self.assertEqual(commands, [], "Coolify UI: no compose command against the repo files")
                elif label.startswith("**Weg C"):
                    for ln in commands:
                        self.assertIn(" -f ", ln)

    def test_containers_are_removed_before_the_volume_and_the_name_is_looked_up(self):
        import re

        for label, block in self._blocks().items():
            lines = [ln.strip() for ln in block.splitlines()]
            removal = [i for i, ln in enumerate(lines) if ln.startswith("docker volume rm")]
            with self.subTest(label=label):
                for i in removal:
                    earlier = "\n".join(lines[:i])
                    self.assertRegex(earlier, r"docker compose( --env-file \S+)?( -f \S+)? down|docker rm -f|docker compose( --env-file \S+)?( -f \S+)? rm", label)
                    self.assertIn("docker volume ls", earlier)
        self.assertNotIn("datenschleuse_datenschleuse-db-data", self.section)
        self.assertNotRegex(self.section, r"docker volume rm +datenschleuse")

    def test_the_coolify_ui_says_that_the_variable_alone_changes_nothing(self):
        block = next(b for label, b in self._blocks().items() if label.startswith("**Weg A"))
        self.assertRegex(block, r"(?s)Variable.{0,200}(allein|nicht).{0,200}Datenbank")

    def test_unverified_steps_are_marked_in_the_document(self):
        self.assertRegex(self.section, r"(?i)nicht (mit Docker )?(ausgeführt|verifiziert|geprüft)")

    def test_the_opt_out_is_said_to_disable_the_admin_password_check_too(self):
        # Security audit S-4.
        section = self.text.split("**Der Schalter**", 1)[1].split("**Wenn du ein Beispiel-Passwort", 1)[0]
        self.assertRegex(section, r"(?s)Opt-out|abgeschaltet")
        self.assertRegex(section, r"(?s)auch.{0,80}(Admin-UI-Passwort|UI_PASSWORD)")
        self.assertRegex(section, r"(?s)(Beispiel|bekannt).{0,60}(angenommen|nicht mehr abgelehnt|startet)")


class TestContributingUsesTheHelperScript(unittest.TestCase):
    def test_quick_start_generates_the_credentials(self):
        text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        local = text.split("## Lokal entwickeln", 1)[1].split("\n## ", 1)[0]
        self.assertIn("tools/init-env.sh", local)
        self.assertNotRegex(local, r"(?m)^cp \.env\.example \.env")


if __name__ == "__main__":
    unittest.main()
