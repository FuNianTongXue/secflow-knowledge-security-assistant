from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score Semgrep JSON against OWASP BenchmarkJava ground truth.")
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--flow-results", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--partition", choices=["all", "diagnostic", "holdout"], default="all")
    parser.add_argument("--diagnostic-percent", type=int, default=70)
    return parser.parse_args()


def cwes_for_result(result: dict[str, Any]) -> set[int]:
    metadata = (result.get("extra") or {}).get("metadata") or {}
    values = metadata.get("cwe") or metadata.get("cwes") or []
    if isinstance(values, str):
        values = [values]
    return {
        int(match.group(1))
        for value in values
        for match in re.finditer(r"CWE[-_ ]?(\d+)", str(value), flags=re.IGNORECASE)
    }


def cwes_for_flow_result(result: dict[str, Any]) -> set[int]:
    return {
        int(match.group(1))
        for value in result.get("cwes") or []
        for match in re.finditer(r"CWE[-_ ]?(\d+)", str(value), flags=re.IGNORECASE)
    }


def metric(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def matrix_metrics(matrix: Counter[str]) -> dict[str, Any]:
    tp = matrix["TP"]
    fp = matrix["FP"]
    tn = matrix["TN"]
    fn = matrix["FN"]
    precision = metric(tp, tp + fp)
    recall = metric(tp, tp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "false_positive_rate": metric(fp, fp + tn),
        "false_negative_rate": metric(fn, fn + tp),
        "precision": precision,
        "recall": recall,
        "f1": metric(2 * precision * recall, precision + recall),
    }


def benchmark_partition(test: str, cwe: int, diagnostic_percent: int = 70) -> str:
    if not 1 <= diagnostic_percent <= 99:
        raise ValueError("diagnostic_percent must be between 1 and 99")
    digest = hashlib.sha256(f"{test}|CWE-{cwe}".encode("utf-8")).hexdigest()
    return "diagnostic" if int(digest[:8], 16) % 100 < diagnostic_percent else "holdout"


def main() -> int:
    args = parse_args()
    if not 1 <= args.diagnostic_percent <= 99:
        raise SystemExit("--diagnostic-percent must be between 1 and 99")
    expected: list[dict[str, Any]] = []
    with args.expected.open(newline="", encoding="utf-8") as stream:
        for row in csv.reader(stream):
            if not row or row[0].startswith("#"):
                continue
            item = {
                "test": row[0],
                "category": row[1],
                "vulnerable": row[2].strip().lower() == "true",
                "cwe": int(row[3]),
            }
            item["partition"] = benchmark_partition(item["test"], item["cwe"], args.diagnostic_percent)
            if args.partition == "all" or item["partition"] == args.partition:
                expected.append(item)

    payload = json.loads(args.results.read_text(encoding="utf-8"))
    findings_by_test: dict[str, set[int]] = defaultdict(set)
    rule_counts: Counter[str] = Counter()
    unmatched_paths: list[str] = []
    for finding in payload.get("results") or []:
        path = str(finding.get("path") or "")
        match = re.search(r"(BenchmarkTest\d+)", path)
        if not match:
            unmatched_paths.append(path)
            continue
        findings_by_test[match.group(1)].update(cwes_for_result(finding))
        rule_counts[str(finding.get("check_id") or "")] += 1

    flow_finding_count = 0
    if args.flow_results:
        flow_payload = json.loads(args.flow_results.read_text(encoding="utf-8"))
        for finding in flow_payload.get("findings") or []:
            if (
                str(finding.get("confidence") or "").lower() != "high"
                or int(finding.get("analysis_depth") or 0) < 1
            ):
                continue
            sink = finding.get("sink") or {}
            match = re.search(r"(BenchmarkTest\d+)", str(sink.get("file") or ""))
            if not match:
                continue
            findings_by_test[match.group(1)].update(cwes_for_flow_result(finding))
            rule_counts[str(finding.get("rule_id") or "cross-method-path")] += 1
            flow_finding_count += 1

    overall: Counter[str] = Counter()
    category_matrices: dict[str, Counter[str]] = defaultdict(Counter)
    wrong_cwe_findings = 0
    for item in expected:
        detected_cwes = findings_by_test.get(item["test"], set())
        detected = item["cwe"] in detected_cwes
        if detected_cwes and not detected:
            wrong_cwe_findings += 1
        outcome = "TP" if item["vulnerable"] and detected else "FN" if item["vulnerable"] else "FP" if detected else "TN"
        overall[outcome] += 1
        category_matrices[item["category"]][outcome] += 1

    report = {
        "methodology": {
            "ground_truth": str(args.expected),
            "matching": "Benchmark test id and expected CWE must both match",
            "other_cwe_in_same_file": "reported separately and not counted as a category hit",
            "flow_results": str(args.flow_results) if args.flow_results else "not provided",
            "flow_filter": "high-confidence unique cross-method paths only",
            "partition": args.partition,
            "diagnostic_percent": args.diagnostic_percent,
            "partition_method": "sha256(test id and expected CWE), stable across runs",
        },
        "test_count": len(expected),
        "raw_findings": len(payload.get("results") or []),
        "high_confidence_flow_findings": flow_finding_count,
        "files_with_findings": len(findings_by_test),
        "files_with_only_other_cwe": wrong_cwe_findings,
        "errors": len(payload.get("errors") or []),
        "overall": matrix_metrics(overall),
        "categories": {
            category: matrix_metrics(matrix)
            for category, matrix in sorted(category_matrices.items())
        },
        "rule_counts": dict(rule_counts.most_common()),
        "unmatched_paths": sorted(set(unmatched_paths)),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["overall"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
