"""coolify-template.json must offer what the Coolify compose file reads.

QA finding L2 (DATENSCHLE-105): ``DATENSCHLEUSE_BLOCK_RESPONSE`` is read by
both compose files and documented in .env.example, but Coolify users did not
find the switch in the variable list.
"""
import json
import pathlib
import re
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "coolify-template.json"
COMPOSE = ROOT / "deploy" / "coolify" / "docker-compose.yaml"


class CoolifyTemplate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.variables = {v["key"]: v for v in json.loads(TEMPLATE.read_text(encoding="utf-8"))["variables"]}

    def test_block_response_is_offered_with_the_compose_default(self):
        var = self.variables["DATENSCHLEUSE_BLOCK_RESPONSE"]
        self.assertEqual(var["default"], "compat")
        self.assertFalse(var.get("required", False))
        self.assertIn("strict", var["description"])
        self.assertIn("422", var["description"])
        compose = COMPOSE.read_text(encoding="utf-8")
        self.assertIn("DATENSCHLEUSE_BLOCK_RESPONSE=${DATENSCHLEUSE_BLOCK_RESPONSE:-compat}", compose)

    def test_disable_admin_ui_is_offered_with_the_compose_default(self):
        var = self.variables["DATENSCHLEUSE_DISABLE_ADMIN_UI"]
        self.assertEqual(var["default"], "False")
        self.assertFalse(var.get("required", False))
        self.assertIn("/ui", var["description"])
        # LiteLLM 1.97.0 reads the flag with str_to_bool: only true/false are
        # recognised (secret_managers/main.py:115-135); anything else leaves
        # the UI on. The description must say so.
        self.assertIn("nur", var["description"])
        self.assertIn("True", var["description"])
        self.assertIn("False", var["description"])
        env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertRegex(env_example, r"(?s)Admin-UI unter /ui abschalten[^\n]*\n(#[^\n]*\n)*# DATENSCHLEUSE_DISABLE_ADMIN_UI=False")
        self.assertIn("nur True oder False", env_example)
        compose = COMPOSE.read_text(encoding="utf-8")
        self.assertIn("DISABLE_ADMIN_UI=${DATENSCHLEUSE_DISABLE_ADMIN_UI:-False}", compose)
        self.assertIn("DATENSCHLEUSE_DISABLE_ADMIN_UI", (ROOT / ".env.example").read_text(encoding="utf-8"))

    def test_every_required_compose_variable_is_in_the_template(self):
        text = COMPOSE.read_text(encoding="utf-8")
        required = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*):\?", text))
        self.assertTrue(required)
        self.assertLessEqual(required, set(self.variables), required - set(self.variables))

    def test_template_is_valid_and_points_at_the_compose_file(self):
        data = json.loads(TEMPLATE.read_text(encoding="utf-8"))
        self.assertTrue((ROOT / data["compose"]).is_file())
        yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
