#!/usr/bin/env python3
"""corpus-benchmark.py — Recall/Precision-Benchmark für den deutschen PII-Testkorpus.

Schickt den Ground-Truth-Korpus (``test/corpus/de-pii-testkorpus.yaml``) gegen
einen laufenden Presidio-Analyzer und misst, wie gut die Erkennung ist.

Gemessen wird getrennt:

  * ``must_detect``-Entitäten (Haupt-Recall/Precision, gesamt und pro Entity-Typ)
  * ``known_gap``-Entitäten (bekannte, akzeptierte Lücken — separat ausgewiesen,
    NICHT in die Haupt-Recall-Zahl eingerechnet, damit Fortschritt über die Zeit
    sichtbar wird, ohne den Score zu beschönigen)
  * False Positives aus den Negativ-Fällen (Cases mit ``entities: []``)

Ausgabe: lesbarer Report auf stdout PLUS strukturierter JSON-Report nach
``test/corpus/benchmark-results.json`` (mit UTC-Timestamp), damit sich Läufe über
die Zeit vergleichen lassen.

Wichtige Design-Entscheidung zur Precision (bewusst, ehrlich dokumentiert):
Der Korpus annotiert pro Positiv-Fall nur die *fokussierten* Entitäten, nicht
jede PII im Text (z.B. nennt ``location-002`` nur die Orte, obwohl "Frau Vogt"
auch eine Person ist). Würde man jede nicht-gematchte Presidio-Detektion in
Positiv-Fällen als False Positive zählen, käme eine irreführend niedrige
Precision heraus — man würde echte, nur nicht-annotierte PII bestrafen. Deshalb
speist sich die Precision-FP-Menge ausschließlich aus den Negativ-Fällen (dort
garantiert der Korpus, dass KEINE PII vorhanden ist). Zusätzliche Detektionen in
Positiv-Fällen werden trotzdem erfasst und im Report unter
``positive_case_unmatched_detections`` ausgewiesen (nichts wird verschluckt) —
sie fließen aber bewusst nicht in die Precision-Kennzahl ein.

Exit-Codes:
  0  Benchmark sauber durchgelaufen (unabhängig vom Score-Ergebnis).
  2  Technischer Fehler (Presidio nicht erreichbar, YAML kaputt, unerwartetes
     Response-Format, Korpus-Inkonsistenz, …) — mit klarer Fehlermeldung auf stderr.

Aufruf:
    python3 test/corpus-benchmark.py
    PRESIDIO_ANALYZER_URL=http://host:5001 python3 test/corpus-benchmark.py
    python3 test/corpus-benchmark.py --url http://localhost:5001 --output /pfad/report.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError:  # pragma: no cover - Abhängigkeit fehlt
    print(
        "FEHLER: PyYAML ist nicht installiert. Bitte `pip install -r test/requirements.txt` ausführen.",
        file=sys.stderr,
    )
    sys.exit(2)

try:
    import requests
except ImportError:  # pragma: no cover - Abhängigkeit fehlt
    print(
        "FEHLER: `requests` ist nicht installiert. Bitte `pip install -r test/requirements.txt` ausführen.",
        file=sys.stderr,
    )
    sys.exit(2)


# --------------------------------------------------------------------------- #
# Konfiguration / Defaults
# --------------------------------------------------------------------------- #

# Pfade werden relativ zum Skript-Verzeichnis aufgelöst — kein Hardcoding von
# Pfaden außerhalb des Projekts.
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CORPUS_PATH = SCRIPT_DIR / "corpus" / "de-pii-testkorpus.yaml"
DEFAULT_OUTPUT_PATH = SCRIPT_DIR / "corpus" / "benchmark-results.json"

DEFAULT_PRESIDIO_URL = "http://localhost:5001"

# Wie viel Überlappung ein Presidio-Span mit dem Ground-Truth-Span mindestens
# haben muss, um als Treffer zu gelten. "Deutlicher Overlap" laut Spec: der
# Schnitt muss mindestens diesen Anteil des kürzeren der beiden Spans abdecken.
DEFAULT_OVERLAP_MIN_RATIO = 0.5

# Netzwerk-Timeout für einen einzelnen /analyze-Request (Sekunden).
DEFAULT_TIMEOUT_SECONDS = 30.0

# Gültige Werte für `expected_recall` im Korpus.
VALID_EXPECTED_RECALL = {"must_detect", "known_gap"}


class BenchmarkError(Exception):
    """Technischer Fehler, der zu Exit-Code 2 mit klarer Meldung führt."""


# --------------------------------------------------------------------------- #
# Datenmodelle
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class GroundTruthEntity:
    """Eine erwartete Entität aus dem Korpus, inkl. berechneter Offsets."""

    case_id: str
    entity_type: str
    value: str
    expected_recall: str
    start: int
    end: int
    occurrences: int  # wie oft `value` im Text vorkommt (>1 => Offset-Unschärfe)

    @property
    def ambiguous_offset(self) -> bool:
        return self.occurrences > 1


@dataclass(frozen=True)
class PredictedEntity:
    """Eine von Presidio zurückgelieferte Entität."""

    entity_type: str
    start: int
    end: int
    score: Optional[float]


@dataclass
class Case:
    """Ein Testfall aus dem Korpus."""

    case_id: str
    text: str
    ground_truth: list[GroundTruthEntity]

    @property
    def is_negative(self) -> bool:
        """Negativ-Fall = explizit leere Entitätsliste (False-Positive-Köder)."""
        return len(self.ground_truth) == 0


@dataclass
class Tally:
    """Zähler für einen Aggregations-Eimer (gesamt oder pro Typ)."""

    tp: int = 0
    fn: int = 0
    fp: int = 0

    @property
    def support(self) -> int:
        """Anzahl Ground-Truth-Entitäten (TP + FN)."""
        return self.tp + self.fn

    @property
    def recall(self) -> Optional[float]:
        denom = self.tp + self.fn
        if denom == 0:
            return None
        return self.tp / denom

    @property
    def precision(self) -> Optional[float]:
        denom = self.tp + self.fp
        if denom == 0:
            return None
        return self.tp / denom


# --------------------------------------------------------------------------- #
# Korpus laden & Offsets berechnen
# --------------------------------------------------------------------------- #


def load_corpus(path: Path) -> list[Case]:
    """Lädt und validiert den YAML-Korpus, berechnet Ground-Truth-Offsets.

    Wirft ``BenchmarkError`` bei jeder Inkonsistenz (kaputtes YAML, fehlende
    Felder, Value nicht im Text auffindbar, unbekanntes expected_recall).
    """
    if not path.is_file():
        raise BenchmarkError(f"Korpus-Datei nicht gefunden: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise BenchmarkError(f"YAML-Korpus konnte nicht geparst werden: {exc}") from exc

    if not isinstance(raw, dict) or "cases" not in raw:
        raise BenchmarkError(
            "Korpus-Struktur unerwartet: erwartet ein Mapping mit Schlüssel 'cases'."
        )

    raw_cases = raw["cases"]
    if not isinstance(raw_cases, list) or not raw_cases:
        raise BenchmarkError("Korpus enthält keine (oder keine gültige) 'cases'-Liste.")

    cases: list[Case] = []
    seen_ids: set[str] = set()

    for index, raw_case in enumerate(raw_cases):
        if not isinstance(raw_case, dict):
            raise BenchmarkError(f"Case #{index} ist kein Mapping: {raw_case!r}")

        case_id = raw_case.get("id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise BenchmarkError(f"Case #{index} hat keine gültige 'id'.")
        if case_id in seen_ids:
            raise BenchmarkError(f"Doppelte Case-id im Korpus: {case_id!r}")
        seen_ids.add(case_id)

        text = raw_case.get("text")
        if not isinstance(text, str) or not text.strip():
            raise BenchmarkError(f"Case {case_id!r} hat keinen gültigen 'text'.")

        raw_entities = raw_case.get("entities", [])
        if raw_entities is None:
            raw_entities = []
        if not isinstance(raw_entities, list):
            raise BenchmarkError(
                f"Case {case_id!r}: 'entities' muss eine Liste sein (auch leer erlaubt)."
            )

        ground_truth = [
            _build_ground_truth_entity(case_id, text, raw_entity)
            for raw_entity in raw_entities
        ]

        cases.append(Case(case_id=case_id, text=text, ground_truth=ground_truth))

    return cases


def _build_ground_truth_entity(
    case_id: str, text: str, raw_entity: Any
) -> GroundTruthEntity:
    """Validiert eine einzelne Ground-Truth-Entität und berechnet ihre Offsets."""
    if not isinstance(raw_entity, dict):
        raise BenchmarkError(f"Case {case_id!r}: Entität ist kein Mapping: {raw_entity!r}")

    entity_type = raw_entity.get("type")
    if not isinstance(entity_type, str) or not entity_type.strip():
        raise BenchmarkError(f"Case {case_id!r}: Entität ohne gültiges 'type'-Feld.")

    value = raw_entity.get("value")
    if not isinstance(value, str) or value == "":
        raise BenchmarkError(
            f"Case {case_id!r}: Entität {entity_type!r} ohne gültiges 'value'-Feld."
        )

    expected_recall = raw_entity.get("expected_recall")
    if expected_recall not in VALID_EXPECTED_RECALL:
        raise BenchmarkError(
            f"Case {case_id!r}: Entität {value!r} hat ungültiges expected_recall "
            f"{expected_recall!r} (erlaubt: {sorted(VALID_EXPECTED_RECALL)})."
        )

    # Offset per str.find() — exaktes erstes Vorkommen. Mehrfachvorkommen wird
    # als potenzielle Unschärfe im Report vermerkt (occurrences > 1).
    start = text.find(value)
    if start == -1:
        raise BenchmarkError(
            f"Case {case_id!r}: Ground-Truth-Value {value!r} kommt im Text nicht vor. "
            "Der Value muss ein exakter Teilstring des (YAML-gefolteten) Textes sein."
        )
    occurrences = text.count(value)

    return GroundTruthEntity(
        case_id=case_id,
        entity_type=entity_type,
        value=value,
        expected_recall=expected_recall,
        start=start,
        end=start + len(value),
        occurrences=occurrences,
    )


# --------------------------------------------------------------------------- #
# Presidio-Analyzer ansprechen
# --------------------------------------------------------------------------- #


def analyze_text(
    session: requests.Session, base_url: str, text: str, timeout: float
) -> list[PredictedEntity]:
    """Schickt einen Text an POST {base_url}/analyze und parst die Antwort.

    Wirft ``BenchmarkError`` bei Verbindungsfehlern, HTTP-Fehlern oder
    unerwartetem Response-Format — es gibt KEIN stilles Verschlucken.
    """
    endpoint = base_url.rstrip("/") + "/analyze"
    payload = {"text": text, "language": "de"}

    try:
        response = session.post(endpoint, json=payload, timeout=timeout)
    except requests.exceptions.RequestException as exc:
        raise BenchmarkError(
            f"Presidio nicht erreichbar unter {endpoint}: {exc}. "
            "Läuft der Analyzer? (`docker compose up presidio-analyzer`)"
        ) from exc

    if response.status_code != 200:
        body_preview = response.text[:500]
        raise BenchmarkError(
            f"Presidio /analyze antwortete mit HTTP {response.status_code}: {body_preview!r}"
        )

    try:
        data = response.json()
    except ValueError as exc:
        raise BenchmarkError(
            f"Presidio /analyze lieferte kein gültiges JSON: {response.text[:500]!r}"
        ) from exc

    return parse_presidio_entities(data, context=f"Text {text[:60]!r}")


def parse_presidio_entities(data: Any, context: str) -> list[PredictedEntity]:
    """Parst die Presidio-Analyze-Antwort defensiv in ``PredictedEntity``-Objekte.

    Erwartet eine Liste von Entity-Objekten. Feldnamen werden mit sinnvollen
    Fallbacks abgeklopft (``entity_type``/``type``, ``start``, ``end``,
    ``score``), aber bei fehlenden Pflichtfeldern wird ein klarer Fehler
    geworfen statt still ein falsches Ergebnis zu produzieren.
    """
    if not isinstance(data, list):
        raise BenchmarkError(
            f"Unerwartetes Presidio-Response-Format ({context}): erwartet eine JSON-Liste "
            f"von Entitäten, bekommen {type(data).__name__}: {str(data)[:200]!r}"
        )

    entities: list[PredictedEntity] = []
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise BenchmarkError(
                f"Presidio-Entität #{index} ({context}) ist kein Objekt: {item!r}"
            )

        entity_type = _first_present(item, ("entity_type", "type", "entityType"))
        if not isinstance(entity_type, str) or not entity_type:
            raise BenchmarkError(
                f"Presidio-Entität #{index} ({context}) ohne erkennbaren 'entity_type': {item!r}"
            )

        start = _first_present(item, ("start", "start_index", "startIndex"))
        end = _first_present(item, ("end", "end_index", "endIndex"))
        if not isinstance(start, int) or not isinstance(end, int):
            raise BenchmarkError(
                f"Presidio-Entität #{index} ({context}) ohne gültige int-Offsets "
                f"(start={start!r}, end={end!r}): {item!r}"
            )
        if end < start:
            raise BenchmarkError(
                f"Presidio-Entität #{index} ({context}) hat end < start "
                f"(start={start}, end={end}): {item!r}"
            )

        raw_score = _first_present(item, ("score", "confidence"))
        score: Optional[float]
        if raw_score is None:
            score = None
        elif isinstance(raw_score, (int, float)):
            score = float(raw_score)
        else:
            # Score ist optional/informativ — bei unparsbarem Typ lieber None als crashen.
            score = None

        entities.append(
            PredictedEntity(entity_type=entity_type, start=start, end=end, score=score)
        )

    return entities


def _first_present(item: dict[str, Any], keys: tuple[str, ...]) -> Any:
    """Gibt den Wert des ersten vorhandenen Schlüssels zurück, sonst None."""
    for key in keys:
        if key in item:
            return item[key]
    return None


# --------------------------------------------------------------------------- #
# Matching-Logik
# --------------------------------------------------------------------------- #


def _overlap_length(a_start: int, a_end: int, b_start: int, b_end: int) -> int:
    """Länge des Schnitts zweier Spans [start, end); 0 wenn disjunkt."""
    return max(0, min(a_end, b_end) - max(a_start, b_start))


def _is_match(
    gt: GroundTruthEntity, pred: PredictedEntity, overlap_min_ratio: float
) -> bool:
    """True, wenn Typ gleich UND der Overlap 'deutlich' ist.

    'Deutlich' = der Schnitt deckt mindestens ``overlap_min_ratio`` des kürzeren
    der beiden Spans ab (nicht zwingend exakt gleicher Start/End).
    """
    if gt.entity_type != pred.entity_type:
        return False
    overlap = _overlap_length(gt.start, gt.end, pred.start, pred.end)
    if overlap <= 0:
        return False
    shorter = min(gt.end - gt.start, pred.end - pred.start)
    if shorter <= 0:
        return False
    return (overlap / shorter) >= overlap_min_ratio


@dataclass
class CaseMatch:
    """Ergebnis des Matchings eines einzelnen Cases."""

    case_id: str
    is_negative: bool
    matched_gt_indices: dict[int, int]  # gt-index -> pred-index
    unmatched_pred_indices: list[int]
    ground_truth: list[GroundTruthEntity]
    predictions: list[PredictedEntity]


def match_case(
    case: Case, predictions: list[PredictedEntity], overlap_min_ratio: float
) -> CaseMatch:
    """Greedy-1:1-Matching zwischen Ground Truth und Presidio-Detektionen.

    Jede Ground-Truth-Entität matcht höchstens eine Presidio-Entität und
    umgekehrt. Bei mehreren Kandidaten gewinnt der höchste Overlap-Anteil.
    """
    candidates: list[tuple[float, int, int, int]] = []
    for gi, gt in enumerate(case.ground_truth):
        for pi, pred in enumerate(predictions):
            if not _is_match(gt, pred, overlap_min_ratio):
                continue
            overlap = _overlap_length(gt.start, gt.end, pred.start, pred.end)
            shorter = min(gt.end - gt.start, pred.end - pred.start)
            ratio = overlap / shorter if shorter > 0 else 0.0
            candidates.append((ratio, overlap, gi, pi))

    # Bester Kandidat zuerst (höchste Ratio, dann größter absoluter Overlap).
    candidates.sort(key=lambda c: (c[0], c[1]), reverse=True)

    matched_gt: dict[int, int] = {}
    matched_pred_indices: set[int] = set()
    for _ratio, _overlap, gi, pi in candidates:
        if gi in matched_gt or pi in matched_pred_indices:
            continue
        matched_gt[gi] = pi
        matched_pred_indices.add(pi)

    unmatched_pred = [pi for pi in range(len(predictions)) if pi not in matched_pred_indices]

    return CaseMatch(
        case_id=case.case_id,
        is_negative=case.is_negative,
        matched_gt_indices=matched_gt,
        unmatched_pred_indices=unmatched_pred,
        ground_truth=case.ground_truth,
        predictions=predictions,
    )


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #


@dataclass
class BenchmarkResult:
    """Vollständiges Benchmark-Ergebnis, bereit für Report + JSON."""

    must_detect_overall: Tally = field(default_factory=Tally)
    must_detect_by_type: dict[str, Tally] = field(default_factory=dict)
    known_gap_overall: Tally = field(default_factory=Tally)
    known_gap_by_type: dict[str, Tally] = field(default_factory=dict)
    negative_fp_by_type: dict[str, int] = field(default_factory=dict)
    negative_fp_total: int = 0

    # Informativ (fließt NICHT in Precision):
    positive_case_unmatched: list[dict[str, Any]] = field(default_factory=list)
    ambiguities: list[dict[str, Any]] = field(default_factory=list)
    known_gap_detail: list[dict[str, Any]] = field(default_factory=list)
    case_details: list[dict[str, Any]] = field(default_factory=list)


def _tally_for(bucket: dict[str, Tally], entity_type: str) -> Tally:
    if entity_type not in bucket:
        bucket[entity_type] = Tally()
    return bucket[entity_type]


def aggregate(matches: list[CaseMatch], overlap_min_ratio: float) -> BenchmarkResult:
    """Aggregiert alle Case-Matches zu Recall/Precision-Kennzahlen."""
    result = BenchmarkResult()

    # Precision-FP kommt ausschließlich aus Negativ-Fällen (siehe Modul-Docstring).
    negative_fp_by_type: dict[str, int] = {}

    for match in matches:
        # --- Ground-Truth-Seite: TP / FN pro Entität ---
        for gi, gt in enumerate(match.ground_truth):
            detected = gi in match.matched_gt_indices

            if gt.ambiguous_offset:
                result.ambiguities.append(
                    {
                        "case_id": gt.case_id,
                        "entity_type": gt.entity_type,
                        "value": gt.value,
                        "occurrences": gt.occurrences,
                        "note": "Value kommt mehrfach im Text vor — erster Offset verwendet.",
                    }
                )

            if gt.expected_recall == "must_detect":
                overall = result.must_detect_overall
                per_type = _tally_for(result.must_detect_by_type, gt.entity_type)
                if detected:
                    overall.tp += 1
                    per_type.tp += 1
                else:
                    overall.fn += 1
                    per_type.fn += 1
            elif gt.expected_recall == "known_gap":
                overall = result.known_gap_overall
                per_type = _tally_for(result.known_gap_by_type, gt.entity_type)
                if detected:
                    overall.tp += 1
                    per_type.tp += 1
                else:
                    overall.fn += 1
                    per_type.fn += 1

                # Zusätzliches Fortschritts-Signal: hat IRGENDEINE Presidio-Entität
                # (egal welcher Typ) den known_gap-Span überlappt?
                any_overlap = any(
                    _overlap_length(gt.start, gt.end, pred.start, pred.end) > 0
                    for pred in match.predictions
                )
                result.known_gap_detail.append(
                    {
                        "case_id": gt.case_id,
                        "entity_type": gt.entity_type,
                        "value": gt.value,
                        "detected_same_type": detected,
                        "any_overlap_detected": any_overlap,
                    }
                )

        # --- Presidio-Seite: unmatched Detektionen ---
        for pi in match.unmatched_pred_indices:
            pred = match.predictions[pi]
            if match.is_negative:
                # Negativ-Fall: JEDE Detektion ist ein False Positive.
                result.negative_fp_total += 1
                negative_fp_by_type[pred.entity_type] = (
                    negative_fp_by_type.get(pred.entity_type, 0) + 1
                )
            else:
                # Positiv-Fall: informativ ausweisen, aber NICHT als FP zählen
                # (Korpus ist nicht erschöpfend annotiert).
                result.positive_case_unmatched.append(
                    {
                        "case_id": match.case_id,
                        "entity_type": pred.entity_type,
                        "start": pred.start,
                        "end": pred.end,
                        "score": pred.score,
                    }
                )

    result.negative_fp_by_type = negative_fp_by_type

    # Precision-FP in die must_detect-Tallies einspeisen (gesamt + pro Typ).
    result.must_detect_overall.fp = result.negative_fp_total
    for entity_type, fp_count in negative_fp_by_type.items():
        # Auch Typen, die nur als FP in Negativ-Fällen auftauchen, sollen in der
        # Per-Typ-Tabelle sichtbar sein (TP/FN=0, aber FP>0 => Precision 0.0).
        _tally_for(result.must_detect_by_type, entity_type).fp += fp_count

    return result


# --------------------------------------------------------------------------- #
# Report-Ausgabe (stdout)
# --------------------------------------------------------------------------- #


def _fmt_rate(rate: Optional[float]) -> str:
    return "  n/a " if rate is None else f"{rate * 100:5.1f}%"


def render_stdout_report(
    result: BenchmarkResult,
    *,
    corpus_path: Path,
    presidio_url: str,
    overlap_min_ratio: float,
    case_count: int,
    timestamp: str,
) -> None:
    """Druckt einen lesbaren Report auf stdout."""
    line = "=" * 74
    print(line)
    print("  DATENSCHLEUSE — PII-KORPUS-BENCHMARK")
    print(line)
    print(f"  Zeitpunkt (UTC) : {timestamp}")
    print(f"  Presidio        : {presidio_url}")
    print(f"  Korpus          : {corpus_path}")
    print(f"  Cases           : {case_count}")
    print(f"  Overlap-Schwelle: {overlap_min_ratio:.2f} (Anteil des kürzeren Spans)")
    print(line)

    # --- must_detect gesamt ---
    md = result.must_detect_overall
    print()
    print("  MUST_DETECT — GESAMT")
    print(f"    TP={md.tp}  FN={md.fn}  FP={md.fp} (FP nur aus Negativ-Fällen)")
    print(f"    Recall   : {_fmt_rate(md.recall)}")
    print(f"    Precision: {_fmt_rate(md.precision)}")

    # --- must_detect pro Typ ---
    print()
    print("  MUST_DETECT — PRO ENTITY-TYP")
    _print_type_table(result.must_detect_by_type)

    # --- known_gap ---
    kg = result.known_gap_overall
    print()
    print("  KNOWN_GAP (separat, NICHT in Haupt-Recall eingerechnet)")
    if kg.support == 0:
        print("    (keine known_gap-Entitäten im Korpus)")
    else:
        print(f"    TP={kg.tp}  FN={kg.fn}")
        print(f"    Recall (gleicher Typ): {_fmt_rate(kg.recall)}")
        detected_overlap = sum(
            1 for d in result.known_gap_detail if d["any_overlap_detected"]
        )
        print(
            f"    Info: {detected_overlap}/{len(result.known_gap_detail)} known_gap-Spans "
            "wurden von IRGENDEINER Presidio-Entität überlappt."
        )

    # --- Negativ-Fälle / False Positives ---
    print()
    print("  NEGATIV-FÄLLE — FALSE POSITIVES")
    if result.negative_fp_total == 0:
        print("    0 False Positives — sauber. ✅")
    else:
        print(f"    {result.negative_fp_total} False Positive(s):")
        for entity_type, count in sorted(result.negative_fp_by_type.items()):
            print(f"      - {entity_type}: {count}")

    # --- Positiv-Fall-Extra-Detektionen (informativ) ---
    print()
    print("  ZUSÄTZLICHE DETEKTIONEN IN POSITIV-FÄLLEN (informativ, NICHT als FP gezählt)")
    if not result.positive_case_unmatched:
        print("    keine")
    else:
        print(f"    {len(result.positive_case_unmatched)} Detektion(en) ohne Ground-Truth-Match:")
        for item in result.positive_case_unmatched:
            print(
                f"      - [{item['case_id']}] {item['entity_type']} "
                f"@ {item['start']}..{item['end']} (score={item['score']})"
            )

    # --- Offset-Unschärfen ---
    if result.ambiguities:
        print()
        print("  OFFSET-UNSCHÄRFEN (Value kommt mehrfach im Text vor)")
        for item in result.ambiguities:
            print(
                f"    - [{item['case_id']}] {item['entity_type']} {item['value']!r} "
                f"×{item['occurrences']}"
            )

    print()
    print(line)


def _print_type_table(by_type: dict[str, Tally]) -> None:
    if not by_type:
        print("    (keine)")
        return
    header = f"    {'TYP':<26} {'TP':>4} {'FN':>4} {'FP':>4} {'RECALL':>8} {'PRECISION':>10}"
    print(header)
    print("    " + "-" * (len(header) - 4))
    for entity_type in sorted(by_type):
        t = by_type[entity_type]
        print(
            f"    {entity_type:<26} {t.tp:>4} {t.fn:>4} {t.fp:>4} "
            f"{_fmt_rate(t.recall):>8} {_fmt_rate(t.precision):>10}"
        )


# --------------------------------------------------------------------------- #
# JSON-Report
# --------------------------------------------------------------------------- #


def _tally_to_dict(tally: Tally) -> dict[str, Any]:
    return {
        "tp": tally.tp,
        "fn": tally.fn,
        "fp": tally.fp,
        "support": tally.support,
        "recall": None if tally.recall is None else round(tally.recall, 4),
        "precision": None if tally.precision is None else round(tally.precision, 4),
    }


def build_json_report(
    result: BenchmarkResult,
    *,
    corpus_path: Path,
    presidio_url: str,
    overlap_min_ratio: float,
    case_count: int,
    timestamp: str,
) -> dict[str, Any]:
    """Baut den strukturierten JSON-Report."""
    return {
        "timestamp_utc": timestamp,
        "presidio_url": presidio_url,
        "corpus_path": str(corpus_path),
        "case_count": case_count,
        "overlap_min_ratio": overlap_min_ratio,
        "precision_note": (
            "Precision-FP stammt ausschließlich aus Negativ-Fällen (entities: []). "
            "Zusätzliche Detektionen in Positiv-Fällen sind unter "
            "'positive_case_unmatched_detections' gelistet, fließen aber bewusst "
            "nicht in die Precision ein, da der Korpus nicht erschöpfend annotiert ist."
        ),
        "must_detect": {
            "overall": _tally_to_dict(result.must_detect_overall),
            "by_type": {
                etype: _tally_to_dict(tally)
                for etype, tally in sorted(result.must_detect_by_type.items())
            },
        },
        "known_gap": {
            "overall": _tally_to_dict(result.known_gap_overall),
            "by_type": {
                etype: _tally_to_dict(tally)
                for etype, tally in sorted(result.known_gap_by_type.items())
            },
            "detail": result.known_gap_detail,
        },
        "negative_cases": {
            "false_positives_total": result.negative_fp_total,
            "false_positives_by_type": dict(sorted(result.negative_fp_by_type.items())),
        },
        "positive_case_unmatched_detections": result.positive_case_unmatched,
        "offset_ambiguities": result.ambiguities,
    }


def write_json_report(report: dict[str, Any], output_path: Path) -> None:
    """Schreibt den JSON-Report; wirft BenchmarkError bei IO-Fehlern."""
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        raise BenchmarkError(f"JSON-Report konnte nicht geschrieben werden ({output_path}): {exc}") from exc


# --------------------------------------------------------------------------- #
# CLI / main
# --------------------------------------------------------------------------- #


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recall/Precision-Benchmark für den deutschen PII-Testkorpus gegen Presidio.",
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("PRESIDIO_ANALYZER_URL", DEFAULT_PRESIDIO_URL),
        help="Basis-URL des Presidio-Analyzers "
        "(Default: $PRESIDIO_ANALYZER_URL oder http://localhost:5001).",
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS_PATH,
        help=f"Pfad zum YAML-Korpus (Default: {DEFAULT_CORPUS_PATH}).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Pfad für den JSON-Report (Default: {DEFAULT_OUTPUT_PATH}).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("PRESIDIO_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)),
        help=f"Netzwerk-Timeout pro Request in Sekunden (Default: {DEFAULT_TIMEOUT_SECONDS}).",
    )
    parser.add_argument(
        "--overlap-ratio",
        type=float,
        default=float(os.environ.get("OVERLAP_MIN_RATIO", DEFAULT_OVERLAP_MIN_RATIO)),
        help="Mindest-Overlap-Anteil (0..1) für einen Treffer "
        f"(Default: {DEFAULT_OVERLAP_MIN_RATIO}).",
    )
    return parser.parse_args(argv)


def run_benchmark(args: argparse.Namespace) -> tuple[BenchmarkResult, int]:
    """Führt den kompletten Benchmark aus und gibt (Ergebnis, Anzahl Cases) zurück."""
    if not (0.0 < args.overlap_ratio <= 1.0):
        raise BenchmarkError(
            f"--overlap-ratio muss in (0, 1] liegen, bekommen: {args.overlap_ratio}"
        )
    if args.timeout <= 0:
        raise BenchmarkError(f"--timeout muss > 0 sein, bekommen: {args.timeout}")

    cases = load_corpus(args.corpus)

    matches: list[CaseMatch] = []
    with requests.Session() as session:
        for case in cases:
            predictions = analyze_text(session, args.url, case.text, args.timeout)
            matches.append(match_case(case, predictions, args.overlap_ratio))

    return aggregate(matches, args.overlap_ratio), len(cases)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        result, case_count = run_benchmark(args)
    except BenchmarkError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 2

    render_stdout_report(
        result,
        corpus_path=args.corpus,
        presidio_url=args.url,
        overlap_min_ratio=args.overlap_ratio,
        case_count=case_count,
        timestamp=timestamp,
    )

    report = build_json_report(
        result,
        corpus_path=args.corpus,
        presidio_url=args.url,
        overlap_min_ratio=args.overlap_ratio,
        case_count=case_count,
        timestamp=timestamp,
    )
    try:
        write_json_report(report, args.output)
    except BenchmarkError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 2

    print(f"  JSON-Report geschrieben: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
