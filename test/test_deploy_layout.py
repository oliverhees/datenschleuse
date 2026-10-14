"""Deploy-layout guard for the guardrail service (DATENSCHLE-82 / -88, F1 + F3).

Why this exists
---------------
The guardrail imports ``de_stopwords`` at module level and loads two YAML files
at construction time. A unit test running from the repo checkout cannot see
whether the *container* has all of that: in the image ``/app`` is flat, there
is no sibling ``presidio/`` directory, and only what the Dockerfile COPYs or
what compose mounts exists. A missing COPY line means ``ModuleNotFoundError``
and a service that never starts, with a fully green unit suite.

What is verified, and what is not
---------------------------------
Nothing here builds an image or starts a container (there is no Docker daemon
in the test environment). Instead the container filesystem is *simulated* from
the repo files themselves:

* the COPY / RUN mkdir lines of ``litellm/Dockerfile``,
* the host-path volume mounts of the compose service (files and directories),
* the ``environment`` entries of that service (``${VAR:-default}`` resolved,
  required variables replaced by dummy values),

then the guardrail is imported AND constructed from the compose service's own
``config.yaml`` ``litellm_params`` in a subprocess whose only PYTHONPATH is the
simulated ``/app``. This proves the wiring in the files is complete. It does
not prove that Docker accepts the mounts, that file permissions are right, or
that LiteLLM itself loads the class. A real ``docker compose up`` remains the
final proof and was NOT executed here.

Boundaries per target
---------------------
* ``docker-compose.yml``: image built from ``litellm/Dockerfile``.
* ``deploy/coolify/docker-compose.yaml``: image built from the same Dockerfile
  (``build.context`` = ``../../litellm``); modules come from the image, the
  YAML files from the directory mounts ``/mnt/*-src``.
* ``test/e2e/docker-compose.e2e.yml``: uses the locally built image
  ``datenschleuse-datenschleuse:latest``. That the tag was built from
  ``litellm/Dockerfile`` is an ASSUMPTION (documented in the file), the test
  simulates exactly that. The Presidio analyzer there is the external
  production one and cannot be derived from the file.
"""
import ast
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
LITELLM = ROOT / "litellm"

TARGETS = {
    "compose": (ROOT / "docker-compose.yml", "datenschleuse"),
    "coolify": (ROOT / "deploy" / "coolify" / "docker-compose.yaml", "datenschleuse"),
    "e2e": (ROOT / "test" / "e2e" / "docker-compose.e2e.yml", "ds-e2e-litellm"),
}
DOCKERFILE = LITELLM / "Dockerfile"


# ---------------------------------------------------------------- helpers
def _load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _service(target):
    path, name = TARGETS[target]
    return path, _load(path)["services"][name]


def _env_dict(svc, dummies=None):
    """Resolve the compose ``environment`` entries to a plain dict."""
    raw = svc.get("environment") or []
    if isinstance(raw, dict):
        items = [f"{k}={'' if v is None else v}" for k, v in raw.items()]
    else:
        items = list(raw)
    out = {}
    for item in items:
        if "=" not in item:
            continue  # bare variable (e.g. SERVICE_FQDN_...), no value
        key, value = item.split("=", 1)
        out[key] = _subst(value, dummies or {})
    return out


_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?[-?]([^}]*))?\}")


def _subst(value, dummies):
    def repl(m):
        name, rest = m.group(1), m.group(2)
        if name in dummies:
            return dummies[name]
        if ":-" in m.group(0) and rest is not None:
            return rest
        return "dummy-" + name.lower()

    return _VAR.sub(repl, value)


def _volumes(path, svc):
    """Yield (host_path or None, container_path) for each volume entry."""
    for entry in svc.get("volumes") or []:
        if not isinstance(entry, str):
            continue
        parts = entry.split(":")
        host, cont = parts[0], parts[1]
        if host.startswith("."):
            yield (path.parent / host).resolve(), cont
        else:
            yield None, cont  # named volume


def _resolve_host(path, svc, container_path):
    """Host file behind a container path (longest mount prefix wins)."""
    best = None
    for host, cont in _volumes(path, svc):
        if host is None:
            continue
        if container_path == cont or container_path.startswith(cont.rstrip("/") + "/"):
            if best is None or len(cont) > len(best[1]):
                best = (host, cont)
    if best is None:
        return None
    host, cont = best
    rel = container_path[len(cont):].lstrip("/")
    return (host / rel).resolve() if rel else host


def _dockerfile_ops():
    """(copies {dst: src}, mkdirs [path], env {k: v}) from litellm/Dockerfile."""
    text = DOCKERFILE.read_text(encoding="utf-8").replace("\\\n", " ")
    copies, mkdirs, env = {}, [], {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("COPY "):
            toks = line.split()[1:]
            copies[toks[-1]] = toks[0]
        elif line.startswith("RUN ") and "mkdir -p" in line:
            for seg in line.split("&&"):
                if "mkdir -p" in seg:
                    mkdirs.extend(seg.split("mkdir -p", 1)[1].split())
        elif line.startswith("ENV "):
            k, _, v = line[4:].strip().partition("=")
            env[k] = v
    return copies, mkdirs, env


def _build_root(target, dummies):
    """Simulate the container filesystem. Returns (root, env)."""
    path, svc = _service(target)
    root = pathlib.Path(tempfile.mkdtemp(prefix="ds-layout-"))
    copies, mkdirs, df_env = _dockerfile_ops()
    for d in mkdirs:
        (root / d.lstrip("/")).mkdir(parents=True, exist_ok=True)
    for dst, src in copies.items():
        target_file = root / dst.lstrip("/")
        target_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(LITELLM / src, target_file)

    mounts = sorted(_volumes(path, svc), key=lambda m: m[1].count("/"))
    for host, cont in mounts:
        dest = root / cont.lstrip("/")
        if host is None:
            dest.mkdir(parents=True, exist_ok=True)
        elif host.is_dir():
            if dest.exists():
                shutil.rmtree(dest) if dest.is_dir() else dest.unlink()
            shutil.copytree(host, dest, ignore=shutil.ignore_patterns("__pycache__"))
        elif host.is_file():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(host, dest)
        else:  # docker would create an empty directory for a missing host path
            dest.mkdir(parents=True, exist_ok=True)

    env = dict(df_env)
    env.update(_env_dict(svc, dummies))
    mapped = {}
    for k, v in env.items():
        if v.startswith("/"):
            mapped[k] = str(root) + v
            parent = pathlib.Path(mapped[k]).parent
            parent.mkdir(parents=True, exist_ok=True)
        else:
            mapped[k] = v
    mapped["PYTHONPATH"] = str(root / "app")
    return root, svc, mapped


_SCRIPT = r"""
import sys, yaml, importlib
cfg = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
params = dict(next(g for g in cfg["guardrails"]
                   if g["guardrail_name"] == "datenschleuse-reid")["litellm_params"])
modpath = params.pop("guardrail")
for k in ("mode", "default_on"):
    params.pop(k, None)
mod, cls = modpath.rsplit(".", 1)
g = getattr(importlib.import_module(mod), cls)(guardrail_name="datenschleuse-reid", **params)
assert len(g.allow_list) > 0
print("OK", len(g.allow_list))
"""


def _fernet_key():
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode()


def _simulate(target):
    dummies = {
        "DATENSCHLEUSE_STATE_KEY": _fernet_key(),
        "DS_E2E_STATE_KEY": _fernet_key(),
    }
    root, svc, env = _build_root(target, dummies)
    try:
        cmd = svc.get("command") or []
        cfg_container = cmd[cmd.index("--config") + 1]
        cfg_file = str(root) + cfg_container
        work = root / "work"
        work.mkdir()
        run_env = {"PATH": os.environ.get("PATH", ""), "HOME": str(work)}
        run_env.update(env)
        return subprocess.run(
            [sys.executable, "-c", _SCRIPT, cfg_file],
            cwd=work,
            env=run_env,
            capture_output=True,
            text=True,
            timeout=120,
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)


# --------------------------------------------------- (a) simulation tests
class TestGuardrailStartsInSimulatedLayout(unittest.TestCase):
    def _check(self, target):
        res = _simulate(target)
        self.assertEqual(
            res.returncode,
            0,
            f"{target}: guardrail does not import/construct in the simulated "
            f"container layout.\nstdout: {res.stdout[-400:]}\nstderr: {res.stderr[-1200:]}",
        )
        self.assertIn("OK", res.stdout)

    def test_docker_compose_layout(self):
        self._check("compose")

    def test_coolify_layout(self):
        self._check("coolify")

    def test_e2e_layout(self):
        self._check("e2e")


# ------------------------------------------------------ (b) static tests
def _local_modules():
    return {p.stem for p in LITELLM.glob("*.py")}


def _transitive_imports(start="datenschleuse_guardrail"):
    local = _local_modules()
    seen, todo = set(), [start]
    while todo:
        mod = todo.pop()
        if mod in seen:
            continue
        seen.add(mod)
        tree = ast.parse((LITELLM / f"{mod}.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):  # includes lazy imports inside functions
            names = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module.split(".")[0]]
            todo.extend(n for n in names if n in local)
    return seen


def _path_env_names():
    """Every ``*_PATH`` variable the guardrail modules read via getenv."""
    names = set()
    for mod in _transitive_imports():
        tree = ast.parse((LITELLM / f"{mod}.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if re.fullmatch(r"[A-Z][A-Z0-9_]*_PATH", node.value):
                    names.add(node.value)
    return names


class TestStaticDeployConsistency(unittest.TestCase):
    def test_every_local_import_is_copied_or_mounted(self):
        copies, _, _ = _dockerfile_ops()
        copied = {pathlib.PurePosixPath(dst).stem for dst in copies}
        for target in TARGETS:
            path, svc = _service(target)
            mounted = {
                pathlib.PurePosixPath(cont).stem
                for host, cont in _volumes(path, svc)
                if host is not None and cont.startswith("/app/") and cont.endswith(".py")
            }
            for mod in sorted(_transitive_imports()):
                self.assertTrue(
                    mod in copied or mod in mounted,
                    f"{target}: local module {mod}.py is imported by the guardrail "
                    f"but neither COPYed in litellm/Dockerfile nor mounted",
                )

    def test_every_path_env_is_set_in_every_compose_target(self):
        names = _path_env_names()
        # Sanity: the scan must actually see the four known variables.
        self.assertTrue(
            {
                "DATENSCHLEUSE_STOPWORDS_PATH",
                "DATENSCHLEUSE_RECOGNIZERS_PATH",
                "DATENSCHLEUSE_CUSTOM_RULES_PATH",
                "SENSITIVITY_KEYWORDS_PATH",
            }
            <= names,
            f"scan found only {sorted(names)}",
        )
        for target in TARGETS:
            _, svc = _service(target)
            env = _env_dict(svc)
            for name in sorted(names):
                self.assertIn(name, env, f"{target}: {name} is not set")

    def test_path_env_values_point_into_a_mount_or_the_image(self):
        # A value pointing nowhere is the failure the simulation also catches;
        # here it is named per variable for a readable message.
        for target in TARGETS:
            path, svc = _service(target)
            env = _env_dict(svc)
            for name in sorted(_path_env_names()):
                value = env.get(name)
                if not value:
                    continue
                if name == "DATENSCHLEUSE_CUSTOM_RULES_PATH":
                    continue  # optional file by design, directory mount only
                host = _resolve_host(path, svc, value)
                self.assertIsNotNone(host, f"{target}: {name}={value} is not under any host mount")
                self.assertTrue(host.is_file(), f"{target}: {name}={value} -> {host} is not a file")


# ------------------------------------------- F3: same recognizers file
class TestRecognizersSameHostSource(unittest.TestCase):
    """The operator-precedence check reads recognizers-config.yml inside the
    guardrail container; the analyzer loads its own copy. Both must be the
    SAME host file, otherwise the check verifies a file the analyzer never
    reads."""

    def _analyzer_source(self, compose_path, name="presidio-analyzer"):
        svc = _load(compose_path)["services"][name]
        env = _env_dict(svc)
        value = env.get("RECOGNIZER_REGISTRY_CONF_FILE")
        self.assertIsNotNone(value, "analyzer: RECOGNIZER_REGISTRY_CONF_FILE is not set")
        return _resolve_host(compose_path, svc, value)

    def _guardrail_source(self, target):
        path, svc = _service(target)
        env = _env_dict(svc)
        value = env.get("DATENSCHLEUSE_RECOGNIZERS_PATH")
        self.assertIsNotNone(value, f"{target}: DATENSCHLEUSE_RECOGNIZERS_PATH is not set")
        return _resolve_host(path, svc, value)

    def test_compose_guardrail_and_analyzer_share_the_host_file(self):
        path, _ = TARGETS["compose"]
        self.assertEqual(self._guardrail_source("compose"), self._analyzer_source(path))
        self.assertEqual(
            self._guardrail_source("compose"), (ROOT / "presidio" / "recognizers-config.yml").resolve()
        )

    def test_coolify_guardrail_and_analyzer_share_the_host_file(self):
        path, _ = TARGETS["coolify"]
        self.assertEqual(self._guardrail_source("coolify"), self._analyzer_source(path))
        self.assertEqual(
            self._guardrail_source("coolify"), (ROOT / "presidio" / "recognizers-config.yml").resolve()
        )

    def test_e2e_guardrail_reads_the_repo_recognizers_file(self):
        # Boundary: the analyzer of the e2e stack is the external production
        # one (not derivable from the file). The most that can be pinned is
        # that the guardrail reads the repo file the production analyzer mounts.
        self.assertEqual(
            self._guardrail_source("e2e"), (ROOT / "presidio" / "recognizers-config.yml").resolve()
        )


if __name__ == "__main__":
    unittest.main()
