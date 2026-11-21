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
Without the proxy server module (unit tests, library use) the code default is
off; under the proxy it is on when the variable is absent (L6, ADR-0007). The
compose files set the switch themselves (QA audit 2, F1),
because `up -d` does not rebuild an existing image; only an explicit ``-e DATENSCHLEUSE_REQUIRE_MASTER_KEY=false``
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
GOOD = "sk-" + "a1" * 16  # 32 characters after the prefix
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
        for value in ("hunter2-not-a-key", "SK-upper", "sk-", "sk-short", "sk-" + "a" * 31, "sk-" + "a" * 31 + " x", "xsk-" + "a" * 20, " " + GOOD):
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


class TestPlaceholdersAndLength(unittest.TestCase):
    """Finding M3 (DATENSCHLE-105, round 2): the placeholder that ships in the
    public repository passed the first form check (``sk-`` + 16 characters)
    and so did every other short value. A publicly known key is no
    authentication."""

    def test_every_shipped_placeholder_is_known(self):
        for value in ("sk-datenschleuse-lokal", "sk-dein-eurouter-key", "sk-1234", "sk-smoke-upstream-dummy", "sk-e2e-local-ollama"):
            self.assertIn(value, dg.KNOWN_PLACEHOLDER_MASTER_KEYS)

    def test_known_placeholders_refuse_to_start_without_leaking_them(self):
        for value in dg.KNOWN_PLACEHOLDER_MASTER_KEYS:
            for variant in (value, value.upper(), f" {value} "):
                with self.subTest(value=variant), _env(**{REQUIRE: "true", KEY: variant}):
                    with self.assertRaises(ValueError) as ctx:
                        dg.DatenschleuseGuardrail()
                    self.assertIn("placeholder", str(ctx.exception))
                    self.assertNotIn(value, str(ctx.exception).lower())

    def test_placeholder_is_rejected_also_if_the_proxy_resolved_it(self):
        mod = types.ModuleType("litellm.proxy.proxy_server")
        mod.master_key = "sk-datenschleuse-lokal"
        with _env(**{REQUIRE: "true"}), mock.patch.dict(sys.modules, {"litellm.proxy.proxy_server": mod}):
            with self.assertRaises(ValueError) as ctx:
                dg.DatenschleuseGuardrail()
        self.assertIn("placeholder", str(ctx.exception))

    def test_random_part_needs_32_characters(self):
        with _env(**{REQUIRE: "true", KEY: "sk-" + "a1" * 15 + "a"}):
            with self.assertRaises(ValueError):
                dg.DatenschleuseGuardrail()
        with _env(**{REQUIRE: "true", KEY: "sk-" + "a1" * 16}):
            dg.DatenschleuseGuardrail()

    def test_message_names_the_required_length(self):
        with _env(**{REQUIRE: "true", KEY: "sk-short"}):
            with self.assertRaises(ValueError) as ctx:
                dg.DatenschleuseGuardrail()
        self.assertIn("32", str(ctx.exception))
        self.assertNotIn("at least 16", str(ctx.exception))

    def test_documented_generators_produce_accepted_keys(self):
        # The command documented in .env.example, README and DEPLOY.md.
        import re
        import shutil
        import subprocess

        command = 'echo "sk-$(openssl rand -hex 32)"'
        for doc in (".env.example", "README.md", "docs/DEPLOY.md"):
            self.assertIn(command, (ROOT / doc).read_text(encoding="utf-8"), doc)
        if shutil.which("openssl") is None:
            self.skipTest("openssl not installed")
        out = subprocess.run(["bash", "-c", command], capture_output=True, text=True, check=True).stdout.strip()
        self.assertRegex(out, r"sk-[0-9a-f]{64}")
        with _env(**{REQUIRE: "true", KEY: out}):
            dg.DatenschleuseGuardrail()
        # Coolify generator "random_hex_32" (+ prefix "sk-"): we do not know
        # whether that means 32 or 64 hex characters; both pass the rule.
        with _env(**{REQUIRE: "true", KEY: "sk-" + "0f" * 16}):
            dg.DatenschleuseGuardrail()


class TestNoPublicPlaceholderShips(unittest.TestCase):
    def test_env_example_leaves_the_master_key_empty(self):
        text = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^DATENSCHLEUSE_MASTER_KEY=$")

    def test_env_example_copied_as_is_does_not_start(self):
        # A user who only runs ``cp .env.example .env`` must be stopped.
        values = {}
        for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#") and "=" in line:
                name, _, value = line.partition("=")
                values[name] = value
        with _env(**{REQUIRE: "true", KEY: values["DATENSCHLEUSE_MASTER_KEY"]}):
            with self.assertRaises(ValueError):
                dg.DatenschleuseGuardrail()

    def test_no_shipped_file_contains_a_known_placeholder_as_a_default(self):
        skip = {"ISA.md", "datenschleuse_guardrail.py", "test_master_key_guard.py", "0006-veroeffentlichte-images-und-block-kennung.md", "0007-example-credentials-rejected.md", "test_admin_credentials.py", "DEPLOY.md", "smoke-images.sh"}
        for path in ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts or path.name in skip or path.suffix in (".pyc", ".png"):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for value in ("sk-datenschleuse-lokal",):
                self.assertNotIn(value, text, str(path.relative_to(ROOT)))

    def test_anonymisation_script_requires_the_key(self):
        import subprocess

        script = ROOT / "test" / "test-anonymisierung.sh"
        self.assertNotRegex(script.read_text(encoding="utf-8"), r"MASTER_KEY:-sk-")
        env = {k: v for k, v in os.environ.items() if k != KEY}
        result = subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DATENSCHLEUSE_MASTER_KEY", result.stderr)

    def test_smoke_test_covers_the_known_placeholder(self):
        text = (ROOT / "test" / "smoke-images.sh").read_text(encoding="utf-8")
        self.assertIn('check_refuses_without_key "known placeholder"', text)
        self.assertIn('-e "DATENSCHLEUSE_MASTER_KEY=sk-datenschleuse-lokal"', text)

    def test_upgrade_note_and_adr(self):
        deploy = (ROOT / "docs" / "DEPLOY.md").read_text(encoding="utf-8")
        self.assertIn("sk-datenschleuse-lokal", deploy)
        self.assertRegex(deploy, r"(?s)Platzhalter.{0,600}startet nach dem Update nicht mehr")
        adr = (ROOT / "docs" / "adr" / "0006-veroeffentlichte-images-und-block-kennung.md").read_text(encoding="utf-8")
        self.assertIn("Platzhalter", adr)
        self.assertIn("32", adr)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        quick = readme.split("## 🚀 Quickstart", 1)[1].split("Deine Tools sprechen", 1)[0]
        self.assertIn("openssl rand -hex 32", quick)


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


def _compose_files():
    """Every compose file in the repository (tracked layout, no .git)."""
    found = []
    for pattern in ("*compose*.yml", "*compose*.yaml"):
        for path in ROOT.rglob(pattern):
            if ".git" in path.parts or "node_modules" in path.parts:
                continue
            found.append(path)
    return sorted(set(found))


PROXY_IMAGE = "ghcr.io/oliverhees/datenschleuse"


def _is_proxy_service(svc):
    """A service starts the Datenschleuse proxy when it is built from
    litellm/Dockerfile, runs LiteLLM with ``--config``, or mounts the
    guardrail module or the litellm/ directory (which holds config.yaml).
    The image name plays no part: a digest-only reference or another
    registry must not hide a proxy (audit round 4, info 2). The published
    proxy image (``ghcr.io/oliverhees/datenschleuse``, tag and/or digest, but
    not ``-analyzer``) counts too: its CMD carries the config (S-6)."""
    build = svc.get("build")
    dockerfile = build.get("dockerfile", "") if isinstance(build, dict) else ""
    if dockerfile.endswith("litellm/Dockerfile"):
        return True
    image = str(svc.get("image") or "")
    repository = image.split("@", 1)[0]
    if ":" in repository.rsplit("/", 1)[-1]:  # strip the tag, not a registry port
        repository = repository.rsplit(":", 1)[0]
    if repository == PROXY_IMAGE:
        return True
    command = svc.get("command") or []
    if isinstance(command, str):
        command = command.split()
    if "--config" in [str(part) for part in command]:
        return True
    for volume in svc.get("volumes") or []:
        source = volume.get("source", "") if isinstance(volume, dict) else str(volume).split(":", 1)[0]
        source = source.rstrip("/")
        if source.endswith("/datenschleuse_guardrail.py") or source.endswith("/litellm") or source.endswith("litellm/config.yaml"):
            return True
    return False


def _proxy_services(compose_path):
    """Services of a compose file that start the Datenschleuse proxy."""
    import yaml

    data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    return [(name, svc) for name, svc in (data.get("services") or {}).items() if _is_proxy_service(svc)]


def _env_entries(svc):
    env = svc.get("environment") or []
    if isinstance(env, dict):
        return [f"{k}={v}" for k, v in env.items()]
    return [str(item) for item in env]


def _switch_problems(svc):
    """What is wrong with the switch in a proxy service's environment."""
    entries = [e for e in _env_entries(svc) if e.startswith(REQUIRE + "=")]
    if len(entries) != 1:
        return [f"{REQUIRE} must be set exactly once (found {len(entries)})"]
    value = entries[0].split("=", 1)[1]
    if value not in ("true", "${%s:-true}" % REQUIRE):
        return [f"{REQUIRE} must default to true, found {value!r}"]
    return []


class TestComposeWiring(unittest.TestCase):
    """QA audit 2, F1: the switch must not depend on the image's ENV.

    ``docker compose up -d`` does not rebuild an existing image, and the
    repository compose mounts the NEW guardrail code over an OLD image that
    has no ``ENV DATENSCHLEUSE_REQUIRE_MASTER_KEY``. So the compose files set
    it themselves (default on, explicit opt-out via the same variable)."""

    def test_every_compose_file_that_starts_the_proxy_sets_the_switch(self):
        checked = 0
        for path in _compose_files():
            for name, svc in _proxy_services(path):
                checked += 1
                with self.subTest(file=str(path.relative_to(ROOT)), service=name):
                    self.assertEqual(_switch_problems(svc), [])
        # repo compose, Coolify compose and the e2e stack
        self.assertGreaterEqual(checked, 3)

    def test_update_docs_rebuild_the_image(self):
        text = (ROOT / "docs" / "DEPLOY.md").read_text(encoding="utf-8")
        section = text.split("**Master-Key: Platzhalter werden abgelehnt.**", 1)[1]
        section = section.split("**Nutzer-ID und eigene Regeln.**", 1)[0]
        self.assertIn("docker compose up -d --build", section)
        self.assertIn("deploy/coolify/docker-compose.yaml", section)
        self.assertNotRegex(section, r"(?m)^docker compose up -d$")


def _write_compose(tmp, services):
    import yaml

    path = pathlib.Path(tmp) / "docker-compose.extra.yml"
    path.write_text(yaml.safe_dump({"services": services}), encoding="utf-8")
    return path


class TestProxyDetectionIsNotTiedToImageNames(unittest.TestCase):
    """Audit round 4, info 2: ``_proxy_services`` knew three image names. A
    future service that runs the proxy under another image name (digest only,
    other registry) would have escaped the wiring test. A proxy service is now
    recognised by what it does: it is built from litellm/Dockerfile, or it
    runs ``--config`` for LiteLLM, or it mounts the guardrail or the litellm
    directory."""

    def _services(self, services):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            return [name for name, _ in _proxy_services(_write_compose(tmp, services))]

    def test_unknown_image_with_a_config_command_is_a_proxy(self):
        found = self._services({"gw": {"image": "registry.example/x/gw@sha256:" + "0" * 64, "command": ["--config", "/app/config.yaml", "--port", "4000"]}})
        self.assertEqual(found, ["gw"])

    def test_unknown_image_with_the_guardrail_mounted_is_a_proxy(self):
        found = self._services({"gw": {"image": "example/gw:1", "volumes": ["./litellm/datenschleuse_guardrail.py:/app/datenschleuse_guardrail.py:ro"]}})
        self.assertEqual(found, ["gw"])

    def test_unknown_image_with_the_litellm_directory_mounted_is_a_proxy(self):
        found = self._services({"gw": {"image": "example/gw:1", "volumes": ["../../litellm:/mnt/litellm-src:ro"]}})
        self.assertEqual(found, ["gw"])

    def test_published_proxy_image_name_is_a_proxy_even_without_command_or_mounts(self):
        # Security audit S-6: image CMD, no command, no mounts.
        for image in (
            "ghcr.io/oliverhees/datenschleuse:1.0.0",
            "ghcr.io/oliverhees/datenschleuse@sha256:" + "2" * 64,
            "ghcr.io/oliverhees/datenschleuse:1.0.0@sha256:" + "2" * 64,
            "ghcr.io/oliverhees/datenschleuse",
        ):
            with self.subTest(image=image):
                self.assertEqual(self._services({"gw": {"image": image}}), ["gw"])

    def test_counter_example_other_published_images_are_not_proxies(self):
        found = self._services(
            {
                "analyzer": {"image": "ghcr.io/oliverhees/datenschleuse-analyzer:1.0.0"},
                "analyzer-md": {"image": "ghcr.io/oliverhees/datenschleuse-analyzer:1.0.0-md"},
                "other": {"image": "ghcr.io/oliverhees/datenschleuse-tools@sha256:" + "3" * 64},
                "foreign": {"image": "example.org/oliverhees/datenschleuse:1"},
            }
        )
        self.assertEqual(found, [])

    def test_a_published_proxy_image_without_the_switch_fails_the_wiring_check(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = _write_compose(tmp, {"gw": {"image": "ghcr.io/oliverhees/datenschleuse:1.0.0", "environment": ["DATENSCHLEUSE_MASTER_KEY=x"]}})
            ((name, svc),) = _proxy_services(path)
        self.assertEqual(name, "gw")
        self.assertTrue(_switch_problems(svc))

    def test_string_command_form_is_recognised(self):
        found = self._services({"gw": {"image": "example/gw:1", "command": "--config /app/config.yaml --port 4000"}})
        self.assertEqual(found, ["gw"])

    def test_unrelated_services_are_not_proxies(self):
        found = self._services(
            {
                "db": {"image": "postgres:16-alpine@sha256:" + "1" * 64, "volumes": ["data:/var/lib/postgresql/data"]},
                "tap": {"image": "python:3.12-slim", "command": ["python", "-u", "/app/tap.py"]},
                "analyzer": {"image": "example/analyzer:1", "volumes": ["../../presidio:/mnt/presidio-src:ro"]},
            }
        )
        self.assertEqual(found, [])

    def test_counter_example_a_detected_proxy_without_the_switch_fails_the_wiring_check(self):
        svc = {"image": "example/gw:1", "command": ["--config", "/app/config.yaml"], "environment": ["DATENSCHLEUSE_MASTER_KEY=x"]}
        self.assertTrue(_switch_problems(svc))
        good = dict(svc, environment=svc["environment"] + ["DATENSCHLEUSE_REQUIRE_MASTER_KEY=${DATENSCHLEUSE_REQUIRE_MASTER_KEY:-true}"])
        self.assertEqual(_switch_problems(good), [])
        off = dict(svc, environment=svc["environment"] + ["DATENSCHLEUSE_REQUIRE_MASTER_KEY=false"])
        self.assertTrue(_switch_problems(off))
        twice = dict(good, environment=good["environment"] + ["DATENSCHLEUSE_REQUIRE_MASTER_KEY=true"])
        self.assertTrue(_switch_problems(twice))

    def test_the_shipped_files_still_yield_every_known_proxy(self):
        names = {(str(p.relative_to(ROOT)), n) for p in _compose_files() for n, _ in _proxy_services(p)}
        self.assertIn(("docker-compose.yml", "datenschleuse"), names)
        self.assertIn(("deploy/coolify/docker-compose.yaml", "datenschleuse"), names)
        self.assertIn(("test/e2e/docker-compose.e2e.yml", "ds-e2e-litellm"), names)
        # nothing else, in particular none of the helper services
        self.assertEqual(len(names), 3, names)


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
        self.assertIn("a publicly known placeholder", text)

    def test_shipped_config_reads_the_variable(self):
        text = (ROOT / "litellm" / "config.yaml").read_text(encoding="utf-8")
        self.assertIn("master_key: os.environ/DATENSCHLEUSE_MASTER_KEY", text)


if __name__ == "__main__":
    unittest.main()
