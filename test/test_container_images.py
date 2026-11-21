"""Static guards for the two container images and the compose defaults.

What the images promise (README "Fertige Images", docs/DEPLOY.md):

* proxy (litellm/Dockerfile) and analyzer (presidio/Dockerfile.analyzer) run
  as non-root, can run with a read-only root filesystem (only /tmp and the QI
  state directory writable), carry a HEALTHCHECK, fetch nothing from the
  network at start, and need no mount to run;
* the proxy image installs no Python package (versions are checked against
  litellm/runtime-pins.txt), the analyzer installs exactly one language model,
  chosen by build argument and pinned by sha256;
* the analyzer's gunicorn runs without its control socket.

And the compose defaults (docker-compose.yml, deploy/coolify/):

* ports only on 127.0.0.1, no --detailed_debug, no set_verbose,
* the unused Presidio anonymizer is not part of the default stack,
* build context is the repository root, and secrets stay out of it
  (.dockerignore).

Nothing here builds an image (no Docker daemon in the test environment). A
real build and start run in .github/workflows/release.yml (job ``smoke``,
script test/smoke-images.sh) before any tag is set.
"""
import importlib.util
import pathlib
import re
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROXY_DF = ROOT / "litellm" / "Dockerfile"
ANALYZER_DF = ROOT / "presidio" / "Dockerfile.analyzer"
COMPOSE = ROOT / "docker-compose.yml"
COOLIFY = ROOT / "deploy" / "coolify" / "docker-compose.yaml"


def _read(path):
    return path.read_text(encoding="utf-8")


def _instructions(path):
    """Dockerfile instructions without comments, continuation lines joined."""
    lines = [l for l in _read(path).splitlines() if not l.lstrip().startswith("#")]
    text = "\n".join(lines).replace("\\\n", " ")
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            keyword, _, rest = line.partition(" ")
            out.append((keyword.upper(), rest.strip()))
    return out


def _compose(path):
    return yaml.safe_load(_read(path))


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CommonImageRules(unittest.TestCase):
    def _check(self, path, expected_user):
        ins = _instructions(path)
        users = [rest for kw, rest in ins if kw == "USER"]
        self.assertTrue(users, f"{path.name}: no USER")
        self.assertEqual(users[-1], expected_user, f"{path.name}: final USER")
        self.assertNotIn(users[-1].split(":")[0], ("root", "0"))
        self.assertTrue(any(kw == "HEALTHCHECK" for kw, _ in ins), f"{path.name}: no HEALTHCHECK")
        envs = dict(rest.split("=", 1) for kw, rest in ins if kw == "ENV" and "=" in rest)
        self.assertEqual(envs.get("HOME"), "/tmp", f"{path.name}: HOME must be the writable /tmp")
        for kw, rest in ins:
            if kw == "COPY":
                src = rest.split()[0]
                self.assertFalse(src.startswith("--"), f"{path.name}: COPY flags break the layout test")
                self.assertTrue((ROOT / src).is_file(), f"{path.name}: COPY source {src} missing (context = repo root)")

    def test_proxy(self):
        self._check(PROXY_DF, "65532:65532")

    def test_analyzer(self):
        self._check(ANALYZER_DF, "1001")


class ProxyImage(unittest.TestCase):
    def setUp(self):
        self.ins = _instructions(PROXY_DF)
        self.text = " ".join(rest for _, rest in self.ins)

    def test_no_pip_and_no_download(self):
        for word in ("ensurepip", "pip install", "curl ", "wget "):
            self.assertNotIn(word, self.text)

    def test_pins_are_checked_at_build(self):
        self.assertIn("check_runtime_pins.py /opt/datenschleuse/runtime-pins.txt", self.text)

    def test_runs_without_mounts(self):
        envs = dict(rest.split("=", 1) for kw, rest in self.ins if kw == "ENV")
        copies = {rest.split()[-1] for kw, rest in self.ins if kw == "COPY"}
        for key in ("SENSITIVITY_KEYWORDS_PATH", "DATENSCHLEUSE_STOPWORDS_PATH", "DATENSCHLEUSE_RECOGNIZERS_PATH"):
            self.assertIn(envs[key], copies, f"{key} points at a file the image does not contain")
        self.assertIn("/app/config.yaml", copies)
        self.assertEqual(envs["DATENSCHLEUSE_IMAGE_POLICY"], "block")

    def test_secure_runtime_defaults(self):
        envs = dict(rest.split("=", 1) for kw, rest in self.ins if kw == "ENV")
        self.assertEqual(envs["LITELLM_LOCAL_MODEL_COST_MAP"], "True")
        self.assertEqual(envs["NO_DOCS"], "True")
        self.assertEqual(envs["NO_REDOC"], "True")
        self.assertEqual(envs["NO_OPENAPI"], "True")
        self.assertEqual(envs["DISABLE_ADMIN_UI"], "True")
        cmd = [rest for kw, rest in self.ins if kw == "CMD"][-1]
        self.assertNotIn("detailed_debug", cmd)
        self.assertNotIn("--debug", cmd)

    def test_state_dir_writable_for_any_uid(self):
        self.assertIn("chmod 1777 /app/state", self.text)

    def test_state_dir_mode_is_a_decision_not_an_oversight(self):
        # Security finding L4: 1777 is world-writable inside the container. It
        # stays, because the repository compose runs the proxy under the host
        # user's UID (default 1000, not the image's 65532) and a NEW named
        # volume inherits the image directory's owner and mode; owner-only
        # (0700, 65532) would lock that default out. The only process in the
        # container is the proxy and the content is Fernet-encrypted. The
        # comment in the Dockerfile must say so, and this test breaks when the
        # compose default and the image user stop differing (then tighten).
        compose_user = yaml.safe_load(_read(COMPOSE))["services"]["datenschleuse"]["user"]
        self.assertNotEqual(compose_user.split(":")[0], "${DATENSCHLEUSE_UID:-65532}")
        raw = _read(PROXY_DF)  # self.text has the comments stripped
        self.assertRegex(raw, r"(?m)^USER 65532:65532$")
        self.assertIn("${DATENSCHLEUSE_UID:-1000}", compose_user)
        self.assertRegex(raw, r"(?s)world-writable.*Fernet")
        self.assertIn("owner-only", raw)

    def test_smoke_test_does_not_claim_nothing_is_pushed_yet(self):
        # Security finding L3: the digests are pushed (untagged) before the
        # smoke test runs; the comment must not say otherwise.
        text = _read(ROOT / "test" / "smoke-images.sh")
        self.assertNotIn("before anything is pushed", text)
        self.assertIn("untagged", text)


class RuntimePins(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module("check_runtime_pins", ROOT / "litellm" / "check_runtime_pins.py")
        self.pins = self.mod.read_pins(ROOT / "litellm" / "runtime-pins.txt")

    def test_every_runtime_requirement_is_pinned(self):
        reqs = {}
        for raw in _read(ROOT / "litellm" / "requirements-guardrail.txt").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                name = re.split(r"[<>=!~]", line, maxsplit=1)[0].strip()
                reqs[name.lower()] = line[len(name):]
        self.assertEqual({k.lower() for k in self.pins}, set(reqs))

    def test_pins_satisfy_ranges(self):
        def as_tuple(v):
            return tuple(int(x) for x in v.split("."))

        reqs = {}
        for raw in _read(ROOT / "litellm" / "requirements-guardrail.txt").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                name = re.split(r"[<>=!~]", line, maxsplit=1)[0].strip()
                reqs[name.lower()] = [c.strip() for c in line[len(name):].split(",")]
        for name, version in self.pins.items():
            for cond in reqs[name.lower()]:
                op, bound = re.match(r"(>=|<=|==|<|>)\s*(.+)", cond).groups()
                v, b = as_tuple(version), as_tuple(bound)
                ok = {">=": v >= b, "<=": v <= b, "==": v == b, "<": v < b, ">": v > b}[op]
                self.assertTrue(ok, f"{name}=={version} violates {cond}")

    def test_checker_detects_mismatch_and_absence(self):
        found = {"httpx": "0.28.1"}

        def version_of(name):
            if name not in found:
                raise self.mod.metadata.PackageNotFoundError(name)
            return found[name]

        self.assertEqual(self.mod.mismatches({"httpx": "0.28.1"}, version_of), [])
        self.assertEqual(len(self.mod.mismatches({"httpx": "0.28.2"}, version_of)), 1)
        self.assertIn("not installed", self.mod.mismatches({"regex": "1"}, version_of)[0])

    def test_checker_rejects_ranges(self):
        tmp = ROOT / "test" / ".pins-test.tmp"
        try:
            tmp.write_text("httpx>=0.27\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                self.mod.read_pins(tmp)
        finally:
            tmp.unlink(missing_ok=True)


class AnalyzerImage(unittest.TestCase):
    def setUp(self):
        self.ins = _instructions(ANALYZER_DF)
        self.text = " ".join(rest for _, rest in self.ins)

    def test_model_is_build_arg_with_sha256(self):
        args = dict(rest.split("=", 1) for kw, rest in self.ins if kw == "ARG" and "=" in rest)
        self.assertEqual(args["SPACY_MODEL"], "de_core_news_lg")
        self.assertEqual(args["SPACY_MODEL_VERSION"], "3.8.0")
        table = dict(re.findall(r"(de_core_news_\w+)@3\.8\.0\) sha=([0-9a-f]{64})", self.text))
        self.assertEqual(set(table), {"de_core_news_lg", "de_core_news_md"})
        self.assertIn("sha256sum -c -", self.text)
        self.assertIn("--no-index", self.text)
        self.assertNotIn("spacy download", self.text)

    def test_default_model_matches_repo_nlp_config(self):
        # Coolify mounts presidio/ over /conf; that nlp-config must name the
        # model the image installs by default, or Presidio downloads at start.
        cfg = yaml.safe_load(_read(ROOT / "presidio" / "nlp-config.yml"))
        self.assertEqual(cfg["models"][0]["model_name"], "de_core_news_lg")

    def test_configuration_is_baked_in(self):
        envs = dict(rest.split("=", 1) for kw, rest in self.ins if kw == "ENV")
        self.assertEqual(envs["NLP_CONF_FILE"], "/conf/nlp-config.yml")
        self.assertIn("> /conf/nlp-config.yml", self.text)
        copies = {rest.split()[-1] for kw, rest in self.ins if kw == "COPY"}
        self.assertIn(envs["ANALYZER_CONF_FILE"], copies)
        self.assertIn(envs["RECOGNIZER_REGISTRY_CONF_FILE"], copies)

    def test_no_control_socket_and_start_script(self):
        cmd = [rest for kw, rest in self.ins if kw == "CMD"][-1]
        self.assertIn("datenschleuse-analyzer-start", cmd)
        start = _read(ROOT / "presidio" / "analyzer-start.sh")
        self.assertIn("exec gunicorn --no-control-socket", start)
        self.assertIn("TLDEXTRACT_CACHE", start)

    def test_public_suffix_list_is_prepared_offline(self):
        self.assertIn("warm_tldextract.py", self.text)
        envs = dict(rest.split("=", 1) for kw, rest in self.ins if kw == "ENV")
        self.assertTrue(envs["TLDEXTRACT_CACHE"].startswith("/tmp/"))


class ComposeDefaults(unittest.TestCase):
    def setUp(self):
        self.doc = _compose(COMPOSE)
        self.svc = self.doc["services"]

    def test_ports_only_on_loopback(self):
        for name, svc in self.svc.items():
            for port in svc.get("ports") or []:
                with self.subTest(service=name, port=port):
                    self.assertTrue(
                        str(port).startswith("127.0.0.1:") or str(port).startswith("${DATENSCHLEUSE_BIND:-127.0.0.1}:"),
                        f"{name}: {port} is published on all interfaces",
                    )

    def test_no_debug_logging_by_default(self):
        self.assertNotIn("--detailed_debug", self.svc["datenschleuse"]["command"])
        cfg = yaml.safe_load(_read(ROOT / "litellm" / "config.yaml"))
        self.assertFalse(cfg["litellm_settings"].get("set_verbose", False))

    def test_anonymizer_not_in_default_stack(self):
        self.assertEqual(self.svc["presidio-anonymizer"].get("profiles"), ["anonymizer"])
        for name, svc in self.svc.items():
            self.assertNotIn("presidio-anonymizer", svc.get("depends_on") or {}, name)
        self.assertNotIn("presidio-anonymizer", _compose(COOLIFY)["services"])
        for path in (COMPOSE, COOLIFY):
            self.assertNotIn("PRESIDIO_ANONYMIZER_API_BASE", _read(path))

    def test_build_contexts_are_repo_root(self):
        for path, base in ((COMPOSE, "."), (COOLIFY, "../..")):
            doc = _compose(path)["services"]
            for name, dockerfile in (("datenschleuse", "litellm/Dockerfile"), ("presidio-analyzer", "presidio/Dockerfile.analyzer")):
                with self.subTest(file=path.name, service=name):
                    self.assertEqual(doc[name]["build"]["context"], base)
                    self.assertEqual(doc[name]["build"]["dockerfile"], dockerfile)

    def test_analyzer_read_only_and_healthy_dependency(self):
        for path in (COMPOSE, COOLIFY):
            doc = _compose(path)["services"]
            with self.subTest(file=path.name):
                self.assertIs(doc["presidio-analyzer"].get("read_only"), True)
                self.assertEqual(
                    doc["datenschleuse"]["depends_on"]["presidio-analyzer"]["condition"], "service_healthy"
                )

    def test_nlp_config_not_mounted_in_local_compose(self):
        vols = self.svc["presidio-analyzer"].get("volumes") or []
        self.assertFalse(any("nlp-config" in v for v in vols))

    def test_admin_ui_stays_available_where_documented(self):
        for path in (COMPOSE, COOLIFY):
            self.assertIn("DISABLE_ADMIN_UI=${DATENSCHLEUSE_DISABLE_ADMIN_UI:-False}", _read(path))

    def test_api_doc_pages_off(self):
        for path in (COMPOSE, COOLIFY):
            text = _read(path)
            for flag in ("NO_DOCS=True", "NO_REDOC=True", "NO_OPENAPI=True"):
                self.assertIn(flag, text, f"{path.name}: {flag}")

    def test_block_response_mode_is_passed_through(self):
        for path in (COMPOSE, COOLIFY):
            self.assertIn("DATENSCHLEUSE_BLOCK_RESPONSE=${DATENSCHLEUSE_BLOCK_RESPONSE:-compat}", _read(path))

    def test_proxy_runs_as_rules_owner(self):
        self.assertEqual(self.svc["datenschleuse"]["user"], "${DATENSCHLEUSE_UID:-1000}:${DATENSCHLEUSE_GID:-1000}")

    def test_root_fallback_is_marked_temporary(self):
        # Security audit, Info: DATENSCHLEUSE_UID=0 is an emergency exit only.
        deploy = _read(ROOT / "docs" / "DEPLOY.md")
        i = deploy.index("`DATENSCHLEUSE_UID=0`")
        window = deploy[i - 400 : i + 600]
        self.assertIn("nur vorübergehend", window)
        self.assertIn("Fehler", window)


class DockerIgnore(unittest.TestCase):
    def test_secrets_never_in_build_context(self):
        lines = {l.strip() for l in _read(ROOT / ".dockerignore").splitlines()}
        for entry in (".env", "rules/custom-rules.yml", "rules/.custom-rules-*.tmp", ".git"):
            self.assertIn(entry, lines)


if __name__ == "__main__":
    unittest.main()


class DocsMatchTheImages(unittest.TestCase):
    """The docs may promise images only 'from the first published version'."""

    def test_readme_and_deploy_name_images_and_their_status(self):
        readme = " ".join(_read(ROOT / "README.md").split())
        deploy = " ".join(_read(ROOT / "docs" / "DEPLOY.md").split())
        for name in ("ghcr.io/oliverhees/datenschleuse", "ghcr.io/oliverhees/datenschleuse-analyzer"):
            self.assertIn(name, readme)
            self.assertIn(name, deploy)
        self.assertIn("Ab der ersten veröffentlichten Version", readme)
        self.assertIn("Bis dahin existieren diese Images nicht**", deploy)
        self.assertIn("das erste Release steht aus", readme)

    def test_deploy_documents_upgrade_traps(self):
        deploy = _read(ROOT / "docs" / "DEPLOY.md")
        for needle in ("DATENSCHLEUSE_UID", "datenschleuse-qi-state", "DATENSCHLEUSE_BIND", "--profile anonymizer"):
            self.assertIn(needle, deploy)
        self.assertNotIn("compose down", deploy.split("## Sichere Standards", 1)[1].split("### Fehlersuche", 1)[0])
