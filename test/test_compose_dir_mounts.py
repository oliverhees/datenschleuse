"""Coolify compose: every host bind mount must be a DIRECTORY (DATENSCHLE-88, Sec-L2).

Rule (header comment of deploy/coolify/docker-compose.yaml, docs/DEPLOY.md):
only directory bind mounts. Single-file bind mounts hit a race in Coolify's
checkout copy step. Named volumes are ignored. Host paths are resolved
relative to the compose file and must satisfy ``is_dir()``.

LIMIT: paths containing ``$`` (env interpolation) cannot be resolved
statically and fail the test on purpose; the short and the long volume syntax
are both understood, other exotic forms are not.
"""
import pathlib
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
COMPOSE = ROOT / "deploy" / "coolify" / "docker-compose.yaml"


def bind_sources(compose_doc):
    """Yield (service, host_source) for every bind mount of the document."""
    for name, svc in (compose_doc.get("services") or {}).items():
        for vol in svc.get("volumes") or []:
            if isinstance(vol, str):
                src = vol.split(":", 1)[0]
                if src.startswith((".", "/", "~")):
                    yield name, src
            elif isinstance(vol, dict) and vol.get("type") == "bind":
                yield name, str(vol.get("source", ""))


def non_directory_binds(compose_doc, base_dir):
    bad = []
    for service, src in bind_sources(compose_doc):
        if "$" in src or not (pathlib.Path(base_dir) / src).resolve().is_dir():
            bad.append((service, src))
    return bad


class TestCoolifyBindMountsAreDirectories(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))

    def test_there_are_bind_mounts_to_check(self):
        self.assertGreaterEqual(len(list(bind_sources(self.doc))), 3)

    def test_every_host_bind_mount_is_a_directory(self):
        self.assertEqual(non_directory_binds(self.doc, COMPOSE.parent), [])

    def test_detector_flags_a_single_file_mount(self):
        mutated = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
        svc = next(n for n, s in mutated["services"].items()
                   if any(str(v).startswith("../../litellm") for v in s.get("volumes") or []))
        mutated["services"][svc]["volumes"].append(
            "../../presidio/de-stopwords.yml:/app/config/de-stopwords.yml:ro"
        )
        bad = non_directory_binds(mutated, COMPOSE.parent)
        self.assertEqual([s for _, s in bad], ["../../presidio/de-stopwords.yml"])

    def test_detector_flags_long_syntax_file_mount(self):
        doc = {"services": {"x": {"volumes": [
            {"type": "bind", "source": "../../presidio/de-stopwords.yml", "target": "/a"}]}}}
        self.assertEqual(len(non_directory_binds(doc, COMPOSE.parent)), 1)

    def test_named_volumes_are_ignored(self):
        doc = {"services": {"x": {"volumes": ["datenschleuse-qi-state:/app/state"]}}}
        self.assertEqual(non_directory_binds(doc, COMPOSE.parent), [])


if __name__ == "__main__":
    unittest.main()
