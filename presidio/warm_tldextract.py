"""Build tldextract's Public Suffix List cache WITHOUT network access.

Runs once at image build time (presidio/Dockerfile.analyzer) with
TLDEXTRACT_CACHE pointing at the directory to fill. Every HTTP request is
refused, so tldextract falls back to the snapshot bundled with the pinned
package version and caches that result under the same key it uses at runtime.
The result is reproducible: it depends only on the installed tldextract.
"""
import logging
import os
import sys

import requests


def _refuse(self, *args, **kwargs):
    raise requests.exceptions.ConnectionError("offline build: bundled snapshot only")


def main() -> int:
    if not os.environ.get("TLDEXTRACT_CACHE"):
        print("TLDEXTRACT_CACHE must be set", file=sys.stderr)
        return 2
    requests.Session.get = _refuse  # type: ignore[method-assign]
    # tldextract logs every refused URL with a full traceback; expected here.
    logging.disable(logging.CRITICAL)
    import tldextract

    result = tldextract.extract("max@example.co.uk")
    if (result.domain, result.suffix) != ("example", "co.uk"):
        print(f"unexpected tldextract result: {result!r}", file=sys.stderr)
        return 1
    print(f"tldextract cache ready in {os.environ['TLDEXTRACT_CACHE']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
