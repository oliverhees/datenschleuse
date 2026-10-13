"""Regression guard for the optional image redactor (DATENSCHLE-83 / -89).

Pins the three properties that keep `docker compose up` free of the redactor
(and its CVE surface) while keeping the fail-closed default:

  1. the redactor service sits behind the compose profile `images`,
  2. the `datenschleuse` service has no `depends_on` on the redactor,
  3. the image policy defaults to `block`.

Also pins the operator docs (README, DEPLOY.md, .env.example) and the honesty
of the supply-chain claims. Only PyYAML, no Docker needed.
"""
import pathlib
import re
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
REDACTOR = "presidio-image-redactor"


def _compose():
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


class TestComposeImageProfile(unittest.TestCase):
    def test_redactor_is_behind_images_profile(self):
        svc = _compose()["services"][REDACTOR]
        self.assertEqual(svc.get("profiles"), ["images"])

    def test_datenschleuse_does_not_depend_on_redactor(self):
        deps = _compose()["services"]["datenschleuse"].get("depends_on", {})
        names = list(deps.keys()) if isinstance(deps, dict) else list(deps)
        self.assertNotIn(REDACTOR, names)

    def test_no_default_service_depends_on_redactor(self):
        # Both depends_on forms (list and dict), for every service: a
        # dependency on a profile-gated service breaks `docker compose up`.
        for name, svc in _compose()["services"].items():
            if name == REDACTOR:
                continue
            deps = svc.get("depends_on") or {}
            names = list(deps.keys()) if isinstance(deps, dict) else list(deps)
            self.assertNotIn(REDACTOR, names, f"{name} depends on the redactor")

    def test_depends_on_check_detects_both_forms(self):
        # Self-check of the detection logic against synthetic mutations.
        for deps in ([REDACTOR], {REDACTOR: {"condition": "service_started"}}):
            names = list(deps.keys()) if isinstance(deps, dict) else list(deps)
            self.assertIn(REDACTOR, names)

    def test_policy_default_is_block(self):
        env = _compose()["services"]["datenschleuse"]["environment"]
        entries = env if isinstance(env, list) else [f"{k}={v}" for k, v in env.items()]
        self.assertIn(
            "DATENSCHLEUSE_IMAGE_POLICY=${DATENSCHLEUSE_IMAGE_POLICY:-block}", entries
        )

    def test_redactor_container_name_matches_upgrade_hint(self):
        name = _compose()["services"][REDACTOR]["container_name"]
        self.assertIn(f"docker rm -f {name}", _read("docs/DEPLOY.md"))


class TestImageDocs(unittest.TestCase):
    def test_readme_describes_profile_and_policy(self):
        readme = _read("README.md")
        self.assertIn("--profile images", readme)
        self.assertIn("DATENSCHLEUSE_IMAGE_POLICY", readme)
        self.assertNotIn("Default mit Dienst", readme)
        self.assertNotIn("Default ohne Dienst", readme)

    def test_deploy_doc_covers_policy_profile_coolify_and_upgrade(self):
        deploy = _read("docs/DEPLOY.md")
        self.assertIn("--profile images", deploy)
        self.assertIn("DATENSCHLEUSE_IMAGE_POLICY", deploy)
        self.assertIn(f"docker compose --profile images rm -sf {REDACTOR}", deploy)
        self.assertIn("`down` stoppt den GANZEN Stack", deploy)
        self.assertNotIn("--profile images down", deploy)
        self.assertIn("Nicht verifiziert (kein Docker-Test)", deploy)
        self.assertIn("redact", deploy)
        self.assertIn("standardmaessig blockiert", deploy)

    def test_eigene_muster_does_not_recommend_block_as_switch(self):
        text = " ".join(_read("docs/EIGENE-MUSTER.md").split())
        self.assertNotIn("setzt `DATENSCHLEUSE_IMAGE_POLICY=block`", text)
        self.assertIn("`block` ist der Standard", text)

    def test_env_example_documents_policy(self):
        self.assertIn("DATENSCHLEUSE_IMAGE_POLICY", _read(".env.example"))


class TestSupplyChainHonesty(unittest.TestCase):
    def test_dockerfile_does_not_claim_built_image_is_scanned(self):
        text = _read("presidio/Dockerfile.analyzer")
        flat = " ".join(
            l.lstrip().lstrip("#").strip()
            for l in text.splitlines()
            if l.lstrip().startswith("#")
        )
        flat = " ".join(flat.split())
        self.assertIn("gebaute Image wird derzeit NICHT in der CI gescannt", flat)
        self.assertIn("bis dahin ist Drift nicht gemessen", flat)
        self.assertNotIn("Ergebnis wird in CI gescannt", flat)
        self.assertNotIn("Ergebnis wird in der CI gescannt", flat)
        self.assertNotIn("Drift wird gemessen", flat)

    def test_compose_totals_are_scoped_to_scanned_upstream_images(self):
        text = " ".join(
            l.lstrip().lstrip("#").strip()
            for l in _read("docker-compose.yml").splitlines()
            if l.lstrip().startswith("#")
        )
        text = " ".join(text.split())
        self.assertIn("4346 Gesamtbefunde der gescannten Upstream-Images", text)
        self.assertNotIn("ausgelieferten Stacks", text)

    def test_supply_chain_states_built_image_not_scanned(self):
        text = _read("docs/foundation/supply-chain.md")
        self.assertIn("gebaute Image wird derzeit nicht gescannt", text)


class TestAnalyzerDockerfile(unittest.TestCase):
    def _lines(self):
        return _read("presidio/Dockerfile.analyzer").splitlines()

    def test_last_user_is_not_root_and_after_root_layer(self):
        users = [
            (i, l.split()[1])
            for i, l in enumerate(self._lines())
            if re.match(r"\s*USER\s+\S+", l)
        ]
        root_idx = [i for i, u in users if u in ("root", "0")]
        self.assertTrue(root_idx, "expected a USER root layer")
        last_i, last_u = users[-1]
        self.assertNotIn(last_u, ("root", "0"))
        self.assertGreater(last_i, max(root_idx))

    def test_apt_upgrade_is_noninteractive_without_env(self):
        text = _read("presidio/Dockerfile.analyzer")
        self.assertNotRegex(text, r"(?m)^\s*ENV\s+DEBIAN_FRONTEND")
        m = re.search(r"(?m)^RUN\b(?:[^\n]*\\\n)*[^\n]*", text[text.index("USER root"):])
        self.assertIsNotNone(m)
        run = m.group(0)
        self.assertIn("apt-get upgrade", run)
        self.assertIn("DEBIAN_FRONTEND=noninteractive", run)


if __name__ == "__main__":
    unittest.main()
