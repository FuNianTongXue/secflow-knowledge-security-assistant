from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score Semgrep results against path-and-rule labeled ground truth.")
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--path-marker", default="")
    parser.add_argument("--min-accuracy", type=float, default=0.0)
    parser.add_argument("--max-fpr", type=float, default=1.0)
    parser.add_argument("--max-fnr", type=float, default=1.0)
    parser.add_argument(
        "--min-positive-cases",
        type=int,
        default=598,
        help="Minimum labeled vulnerable cases required for qualification (598 supports a <0.5%% zero-event upper bound at 95%% confidence).",
    )
    parser.add_argument(
        "--min-negative-cases",
        type=int,
        default=598,
        help="Minimum labeled safe cases required for qualification (598 supports a <0.5%% zero-event upper bound at 95%% confidence).",
    )
    return parser.parse_args()


def ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def binomial_upper_bound(error_count: int, sample_count: int, *, confidence: float = 0.95) -> float | None:
    if sample_count <= 0:
        return None
    if error_count <= 0:
        return round(1 - math.pow(1 - confidence, 1 / sample_count), 6)
    if error_count >= sample_count:
        return 1.0
    alpha = 1 - confidence
    lower = error_count / sample_count
    upper = 1.0
    for _ in range(80):
        midpoint = (lower + upper) / 2
        if _binomial_cdf(error_count, sample_count, midpoint) > alpha:
            lower = midpoint
        else:
            upper = midpoint
    return round(upper, 6)


def zero_event_upper_bound(sample_count: int, *, confidence: float = 0.95) -> float | None:
    return binomial_upper_bound(0, sample_count, confidence=confidence)


def _binomial_cdf(max_errors: int, sample_count: int, probability: float) -> float:
    if probability <= 0:
        return 1.0
    if probability >= 1:
        return 0.0
    logs = [
        math.lgamma(sample_count + 1)
        - math.lgamma(index + 1)
        - math.lgamma(sample_count - index + 1)
        + index * math.log(probability)
        + (sample_count - index) * math.log1p(-probability)
        for index in range(max_errors + 1)
    ]
    peak = max(logs)
    return math.exp(peak) * sum(math.exp(value - peak) for value in logs)


def normalize_rule(value: str) -> str:
    marker = "secflow."
    return marker + value.split(marker, 1)[1] if marker in value else value


def normalize_path(value: str, marker: str) -> str:
    normalized = value.replace("\\", "/")
    return normalized.split(marker, 1)[-1].lstrip("/") if marker and marker in normalized else normalized.lstrip("./")


def main() -> int:
    args = parse_args()
    expected: list[dict[str, Any]] = json.loads(args.expected.read_text(encoding="utf-8"))
    payload = json.loads(args.results.read_text(encoding="utf-8"))
    detected = {
        (normalize_path(str(item.get("path") or ""), args.path_marker), normalize_rule(str(item.get("check_id") or "")))
        for item in payload.get("results") or []
    }
    expected_keys = [(str(item["file"]), str(item["rule"])) for item in expected]
    if len(expected_keys) != len(set(expected_keys)):
        raise SystemExit("Ground truth contains duplicate file/rule labels")
    unlabeled_detections = sorted(detected - set(expected_keys))
    matrix: Counter[str] = Counter()
    cases: list[dict[str, Any]] = []
    for item in expected:
        matched = (str(item["file"]), str(item["rule"])) in detected
        outcome = "TP" if item["vulnerable"] and matched else "FN" if item["vulnerable"] else "FP" if matched else "TN"
        matrix[outcome] += 1
        cases.append({**item, "detected": matched, "outcome": outcome})
    total = sum(matrix.values())
    metrics = {
        "tp": matrix["TP"],
        "fp": matrix["FP"],
        "tn": matrix["TN"],
        "fn": matrix["FN"],
        "accuracy": ratio(matrix["TP"] + matrix["TN"], total),
        "precision": ratio(matrix["TP"], matrix["TP"] + matrix["FP"]),
        "recall": ratio(matrix["TP"], matrix["TP"] + matrix["FN"]),
        "false_positive_rate": ratio(matrix["FP"], matrix["FP"] + matrix["TN"]),
        "false_negative_rate": ratio(matrix["FN"], matrix["FN"] + matrix["TP"]),
    }
    point_estimate_passed = (
        metrics["accuracy"] >= args.min_accuracy
        and metrics["false_positive_rate"] <= args.max_fpr
        and metrics["false_negative_rate"] <= args.max_fnr
    )
    positive_cases = matrix["TP"] + matrix["FN"]
    negative_cases = matrix["TN"] + matrix["FP"]
    sample_size_passed = positive_cases >= args.min_positive_cases and negative_cases >= args.min_negative_cases
    labels_complete = not unlabeled_detections
    fnr_upper = binomial_upper_bound(matrix["FN"], positive_cases)
    fpr_upper = binomial_upper_bound(matrix["FP"], negative_cases)
    confidence_passed = (
        fnr_upper is not None
        and fpr_upper is not None
        and fnr_upper <= args.max_fnr
        and fpr_upper <= args.max_fpr
    )
    passed = point_estimate_passed and sample_size_passed and labels_complete and confidence_passed
    report = {
        "methodology": {
            "ground_truth": str(args.expected),
            "matching": "exact normalized path and exact SecFlow rule id",
            "case_count": total,
            "thresholds": {
                "min_accuracy": args.min_accuracy,
                "max_false_positive_rate": args.max_fpr,
                "max_false_negative_rate": args.max_fnr,
                "min_positive_cases": args.min_positive_cases,
                "min_negative_cases": args.min_negative_cases,
            },
        },
        "metrics": metrics,
        "qualification": {
            "point_estimate_passed": point_estimate_passed,
            "sample_size_passed": sample_size_passed,
            "labels_complete": labels_complete,
            "confidence_passed": confidence_passed,
            "positive_cases": positive_cases,
            "negative_cases": negative_cases,
            "unlabeled_detection_count": len(unlabeled_detections),
            "false_negative_rate_upper_95": fnr_upper,
            "false_positive_rate_upper_95": fpr_upper,
            "note": "Bounds are one-sided exact Clopper-Pearson binomial bounds; point estimates alone do not qualify production accuracy.",
        },
        "passed": passed,
        "unlabeled_detections": [
            {"file": file_name, "rule": rule}
            for file_name, rule in unlabeled_detections
        ],
        "cases": cases,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metrics, ensure_ascii=False))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
