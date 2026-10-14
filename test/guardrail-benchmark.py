#!/usr/bin/env python3
"""guardrail-benchmark.py — misst denselben Korpus durch den AUSGELIEFERTEN Pfad.

WOFUER
======
``test/corpus-benchmark.py`` schickt jeden Korpus-Text direkt an
``POST /analyze``. Das misst, was der Analyzer kann. Es misst NICHT, was der
Dienst tut: Der Guardrail baut sein Payload selbst, und bis DATENSCHLE-82 hat
er die ``allow_list`` schlicht nie mitgesendet. Die Zahl aus dem Benchmark
beschrieb damit den erreichbaren, nicht den ausgelieferten Zustand -- genau der
Unterschied, der DATENSCHLE-82 ausgeloest hat.

Dieses Skript schliesst die Luecke von der anderen Seite: Es fuehrt denselben
Korpus durch ``async_pre_call_hook`` -> ``_analyze`` -> ``_presidio_analyze``
gegen denselben echten Analyzer und wertet mit DERSELBEN Matching- und
Aggregationslogik aus. Weichen die Zahlen voneinander ab, ist das kein
Messfehler, sondern der wichtigste denkbare Befund: Dann tut der Dienst etwas
anderes als das Messwerkzeug.

WARUM KEINE ZWEITE MATCHING-IMPLEMENTIERUNG
===========================================
``match_case``/``aggregate``/``load_corpus`` werden aus ``corpus-benchmark.py``
importiert und NICHT nachgebaut. Zwei Implementierungen desselben Vergleichs
waeren die naheliegendste Art, den Vergleich wertlos zu machen: Eine Differenz
zwischen den Laeufen liesse sich dann nicht mehr dem Transport zuordnen. Der
Transport ist die einzige Variable, die dieses Skript aendert.

WAS GEMESSEN WIRD
=================
Pro Korpus-Fall wird ``async_pre_call_hook`` mit einer echten User-Nachricht
aufgerufen. Abgegriffen werden die Detektionen, auf die der Guardrail
tatsaechlich reagiert hat:

* ``--layer presidio`` (Vorgabe): die Rueckgabe von ``_presidio_analyze`` --
  Presidio allein, direkt vergleichbar mit ``corpus-benchmark.py``.
* ``--layer alle``: die Rueckgabe von ``_analyze`` -- Presidio PLUS die eigenen
  Regeln (custom_rules.py). Das ist die vollstaendige Wahrheit des Dienstes;
  fuer den Vergleich mit dem Benchmark ist sie unfair, weil der Benchmark diese
  Schicht nicht kennt.

Nutzung:

    PYTHONPATH=litellm python3 test/guardrail-benchmark.py
    PYTHONPATH=litellm python3 test/guardrail-benchmark.py --layer alle
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_HERE = Path(__file__).resolve().parent
_BENCHMARK_PATH = _HERE / "corpus-benchmark.py"


def _lade_benchmark():
    """Laedt corpus-benchmark.py als Modul (der Dateiname hat einen Bindestrich)."""
    spec = importlib.util.spec_from_file_location("corpus_benchmark", str(_BENCHMARK_PATH))
    if spec is None or spec.loader is None:
        raise SystemExit(f"FEHLER: {_BENCHMARK_PATH} nicht ladbar.")
    module = importlib.util.module_from_spec(spec)
    sys.modules["corpus_benchmark"] = module
    spec.loader.exec_module(module)
    return module


cb = _lade_benchmark()


class GuardrailBenchmarkError(Exception):
    """Messfehler. Wird nie verschluckt -- eine halbe Messung ist wertlos."""


def _import_guardrail():
    try:
        import datenschleuse_guardrail as dg
    except ImportError as exc:  # pragma: no cover - Bedienfehler
        raise GuardrailBenchmarkError(
            f"datenschleuse_guardrail nicht importierbar ({exc}). "
            f"Mit PYTHONPATH=litellm starten."
        ) from exc
    return dg


class _Mitschnitt:
    """Greift die Detektionen ab, auf die der Guardrail wirklich reagiert hat.

    Kein Nachbau des Payloads und kein zweiter Analyzer-Aufruf: Es wird die
    ECHTE Methode umschlossen und ihre Rueckgabe mitgeschnitten. Damit kann die
    Messung nicht versehentlich an der Verdrahtung vorbeimessen -- was der
    ganze Anlass dieser Aufgabe war.

    Nur Aufrufe mit dem unveraenderten Fall-Text werden gewertet. Der Guardrail
    ruft ``_analyze`` im Verifikationsdurchlauf ein zweites Mal auf, dann aber
    mit dem bereits MASKIERTEN Text; dessen Treffer sind eine andere Frage und
    wuerden die Kennzahl verfaelschen.
    """

    def __init__(self, guard: Any, methode: str, text: str) -> None:
        self._guard = guard
        self._methode = methode
        self._text = text
        self._original = getattr(guard, methode)
        self.treffer: List[List[Dict[str, Any]]] = []

    async def _wrapper(self, text: str, *args: Any, **kwargs: Any):
        ergebnis = await self._original(text, *args, **kwargs)
        if text == self._text:
            self.treffer.append(list(ergebnis))
        return ergebnis

    def __enter__(self) -> "_Mitschnitt":
        setattr(self._guard, self._methode, self._wrapper)
        return self

    def __exit__(self, *_exc: Any) -> bool:
        setattr(self._guard, self._methode, self._original)
        return False


_LAYER_METHODE = {"presidio": "_presidio_analyze", "alle": "_analyze"}


async def _detektionen_fuer(guard: Any, text: str, methode: str) -> List[Dict[str, Any]]:
    """Faehrt EINEN Korpus-Text durch den ausgelieferten Pfad."""
    data = {"messages": [{"role": "user", "content": text}]}
    with _Mitschnitt(guard, methode, text) as mit:
        await guard.async_pre_call_hook(
            user_api_key_dict=None, cache=None, data=data, call_type="completion"
        )
    if not mit.treffer:
        raise GuardrailBenchmarkError(
            f"Der Guardrail hat {methode} nie mit dem unveraenderten Text "
            f"aufgerufen ({text[:60]!r}). Damit misst dieses Skript nicht mehr "
            f"den ausgelieferten Pfad -- lieber abbrechen als eine Zahl "
            f"melden, die niemand nachvollziehen kann."
        )
    return mit.treffer[0]


def _als_predictions(entities: List[Dict[str, Any]], text: str) -> list:
    """Presidio-Dicts -> ``PredictedEntity`` des Benchmarks (dessen Parser)."""
    return cb.parse_presidio_entities(entities, context=f"Text {text[:60]!r}")


async def _lauf(cases: list, analyzer_url: str, methode: str, overlap: float) -> list:
    dg = _import_guardrail()
    guard = dg.DatenschleuseGuardrail(
        presidio_analyzer_url=analyzer_url, image_policy="block"
    )
    matches = []
    for case in cases:
        entities = await _detektionen_fuer(guard, case.text, methode)
        predictions = _als_predictions(entities, case.text)
        matches.append(cb.match_case(case, predictions, overlap))
    return matches


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Recall/Precision/Stoerquote durch den ausgelieferten Guardrail-Pfad."
    )
    p.add_argument("--corpus", type=Path, default=cb.DEFAULT_CORPUS_PATH)
    p.add_argument(
        "--url",
        default=os.environ.get("PRESIDIO_ANALYZER_URL", "http://localhost:5001"),
    )
    p.add_argument(
        "--layer",
        choices=sorted(_LAYER_METHODE),
        default="presidio",
        help="presidio = nur Presidio (vergleichbar mit corpus-benchmark.py); "
        "alle = inklusive eigener Regeln.",
    )
    p.add_argument("--overlap-ratio", type=float, default=0.5)
    p.add_argument("--output", type=Path, default=None)
    return p.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)
    timestamp = datetime.now(timezone.utc).isoformat()
    methode = _LAYER_METHODE[args.layer]

    try:
        cases = cb.load_corpus(args.corpus)
        matches = asyncio.run(_lauf(cases, args.url, methode, args.overlap_ratio))
    except (GuardrailBenchmarkError, cb.BenchmarkError) as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 2

    result = cb.aggregate(matches, args.overlap_ratio)

    print()
    print("=" * 78)
    print("  GUARDRAIL-PFAD (async_pre_call_hook -> _analyze -> echter Analyzer)")
    print(f"  Schicht: {args.layer}  ({methode})")
    print("=" * 78)
    cb.render_stdout_report(
        result,
        corpus_path=args.corpus,
        presidio_url=args.url,
        overlap_min_ratio=args.overlap_ratio,
        case_count=len(cases),
        timestamp=timestamp,
        stopwords_path="(durch den Guardrail gesendet)",
    )

    if args.output:
        report = cb.build_json_report(
            result,
            corpus_path=args.corpus,
            presidio_url=args.url,
            overlap_min_ratio=args.overlap_ratio,
            case_count=len(cases),
            timestamp=timestamp,
            stopwords_path="(durch den Guardrail gesendet)",
        )
        report["transport"] = "guardrail:async_pre_call_hook"
        report["layer"] = args.layer
        cb.write_json_report(report, args.output)
        print(f"  JSON-Report geschrieben: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
