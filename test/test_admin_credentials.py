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
        for patcher in self._patchers:
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


if __name__ == "__main__":
    unittest.main()
