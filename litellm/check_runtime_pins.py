"""Fail the image build if an installed package differs from runtime-pins.txt.

Usage (litellm/Dockerfile): python check_runtime_pins.py runtime-pins.txt

Reads `name==version` lines, compares each with importlib.metadata in the
interpreter that runs the proxy. Stdlib only -- the image has no pip.
"""
import importlib.metadata as metadata
import sys


def read_pins(path):
    pins = {}
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            name, sep, version = line.partition("==")
            if not sep or not name.strip() or not version.strip():
                raise ValueError(f"not a name==version pin: {raw.rstrip()!r}")
            pins[name.strip()] = version.strip()
    if not pins:
        raise ValueError(f"{path}: no pins found")
    return pins


def mismatches(pins, version_of=metadata.version):
    problems = []
    for name, wanted in sorted(pins.items()):
        try:
            found = version_of(name)
        except metadata.PackageNotFoundError:
            problems.append(f"{name}: not installed (pinned {wanted})")
            continue
        if found != wanted:
            problems.append(f"{name}: installed {found}, pinned {wanted}")
    return problems


def main(argv):
    if len(argv) != 2:
        print("usage: check_runtime_pins.py <runtime-pins.txt>", file=sys.stderr)
        return 2
    pins = read_pins(argv[1])
    problems = mismatches(pins)
    for problem in problems:
        print(f"runtime pin mismatch: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"runtime pins OK ({len(pins)} packages)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
