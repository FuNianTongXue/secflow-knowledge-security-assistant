#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.java_flow_analyzer import analyze_java_interprocedural  # noqa: E402


DEFAULT_CONFIG = ROOT / "config/evaluation/java-finance-native-labeled-v1.json"
DEFAULT_OUTPUT = ROOT / "docs/java-finance-native-labeled-results.json"
DEFAULT_MARKDOWN = ROOT / "docs/java-finance-native-labeled-results.md"
TARGET_SCENARIOS = {
    "idempotency_missing",
    "funds_transaction_boundary",
    "funds_state_transition_race",
}


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    template: str
    variant: int
    expected_positive: bool
    predicted_positive: bool
    scenarios: tuple[str, ...]
    risk_kinds: tuple[str, ...]
    finding_count: int
    cfg_node_count: int
    cfg_edge_count: int
    dfg_edge_count: int


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate native Java finance CFG/DFG analysis on labeled fixtures.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--variants", type=int, default=64, help="Deterministic variants per labeled template.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--markdown", type=Path, default=DEFAULT_MARKDOWN)
    parser.add_argument("--require-accuracy", type=float, default=0.95)
    parser.add_argument("--max-fpr", type=float, default=0.005)
    parser.add_argument("--max-fnr", type=float, default=0.005)
    args = parser.parse_args()

    config = json.loads(args.config.read_text(encoding="utf-8"))
    templates = _load_templates(config)
    variants = max(1, min(args.variants, 100))
    template_results = [_evaluate(path, expected, 0) for path, expected in templates]
    expanded_results = [
        _evaluate(path, expected, variant)
        for path, expected in templates
        for variant in range(variants)
    ]
    template_metrics = _metrics(template_results)
    expanded_metrics = _metrics(expanded_results)
    thresholds = {
        "accuracy": args.require_accuracy,
        "false_positive_rate": args.max_fpr,
        "false_negative_rate": args.max_fnr,
    }
    passes = (
        expanded_metrics["accuracy"] >= args.require_accuracy
        and expanded_metrics["false_positive_rate"] <= args.max_fpr
        and expanded_metrics["false_negative_rate"] <= args.max_fnr
    )
    payload: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "engine": "java-native-finance",
        "config": str(args.config.relative_to(ROOT)),
        "methodology": {
            "ground_truth": "Manual labels in separate positive/negative fixture directories.",
            "template_count": len(templates),
            "expanded_variant_count": len(expanded_results),
            "variants_per_template": variants,
            "independent_unit_count": len(templates),
            "limitation": (
                "Deterministic symbol/format variants exercise parser and data-flow stability but are correlated. "
                "Their rates are regression results, not a real-world prevalence or production accuracy guarantee."
            ),
        },
        "thresholds": thresholds,
        "thresholds_passed_on_expanded_regression": passes,
        "template_metrics": template_metrics,
        "expanded_regression_metrics": expanded_metrics,
        "template_results": [asdict(item) for item in template_results],
        "expanded_failures": [
            asdict(item)
            for item in expanded_results
            if item.expected_positive != item.predicted_positive
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    args.markdown.write_text(_markdown(payload), encoding="utf-8")
    print(json.dumps({
        "thresholds_passed": passes,
        "template_metrics": template_metrics,
        "expanded_regression_metrics": expanded_metrics,
        "output": str(args.output),
    }, ensure_ascii=False, indent=2))
    return 0 if passes else 1


def _load_templates(config: dict[str, Any]) -> list[tuple[Path, bool]]:
    result: list[tuple[Path, bool]] = []
    for key, expected in (("positive_directory", True), ("negative_directory", False)):
        directory = ROOT / str(config[key])
        for path in sorted(directory.glob("*.java")):
            result.append((path, expected))
    if not result:
        raise RuntimeError("No labeled Java finance fixtures were found.")
    return result


def _evaluate(path: Path, expected_positive: bool, variant: int) -> CaseResult:
    source = _variant(path.read_text(encoding="utf-8"), variant)
    file_name = f"src/main/java/{path.stem}_v{variant}.java"
    analysis = analyze_java_interprocedural([{"file_name": file_name, "content": source}])
    findings = [
        item
        for item in analysis.get("findings") or []
        if item.get("engine") == "java-native-finance" and item.get("scenario") in TARGET_SCENARIOS
    ]
    scenarios = tuple(sorted({str(item.get("scenario") or "") for item in findings}))
    risk_kinds = tuple(sorted({
        str((item.get("semantic_proof") or {}).get("risk_kind") or "")
        for item in findings
    }))
    return CaseResult(
        case_id=f"{path.parent.name}/{path.stem}#v{variant}",
        template=f"{path.parent.name}/{path.name}",
        variant=variant,
        expected_positive=expected_positive,
        predicted_positive=bool(findings),
        scenarios=scenarios,
        risk_kinds=risk_kinds,
        finding_count=len(findings),
        cfg_node_count=int(analysis.get("cfg_node_count") or 0),
        cfg_edge_count=int(analysis.get("cfg_edge_count") or 0),
        dfg_edge_count=int(analysis.get("dfg_edge_count") or 0),
    )


def _variant(source: str, variant: int) -> str:
    if variant == 0:
        return source
    declared = re.findall(r"\bclass\s+([A-Za-z_$][\w$]*)", source)
    for name in sorted(set(declared), key=len, reverse=True):
        source = re.sub(rf"\b{re.escape(name)}\b", f"{name}V{variant}", source)
    source = re.sub(r"\brequest\b", f"command{variant}", source)
    source = re.sub(r"\bevent\b", f"message{variant}", source)
    padding = "\n" * (variant % 3)
    return f"// deterministic labeled variant {variant}{padding}\n{source}\nclass BenignNoiseV{variant} {{ String format(String value) {{ return value.trim(); }} }}\n"


def _metrics(results: list[CaseResult]) -> dict[str, Any]:
    tp = sum(item.expected_positive and item.predicted_positive for item in results)
    tn = sum(not item.expected_positive and not item.predicted_positive for item in results)
    fp = sum(not item.expected_positive and item.predicted_positive for item in results)
    fn = sum(item.expected_positive and not item.predicted_positive for item in results)
    accuracy = _ratio(tp + tn, len(results))
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    fpr = _ratio(fp, fp + tn)
    fnr = _ratio(fn, fn + tp)
    return {
        "count": len(results),
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "fpr_wilson_95": _wilson(fp, fp + tn),
        "fnr_wilson_95": _wilson(fn, fn + tp),
    }


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _wilson(successes: int, total: int) -> list[float]:
    if not total:
        return [0.0, 0.0]
    z = 1.959963984540054
    rate = successes / total
    denominator = 1 + z * z / total
    center = (rate + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((rate * (1 - rate) + z * z / (4 * total)) / total) / denominator
    return [round(max(0.0, center - margin), 6), round(min(1.0, center + margin), 6)]


def _markdown(payload: dict[str, Any]) -> str:
    base = payload["template_metrics"]
    expanded = payload["expanded_regression_metrics"]
    failures = payload["expanded_failures"]
    lines = [
        "# Native Java Finance CFG/DFG Labeled Evaluation",
        "",
        f"Generated: {payload['generated_at']}",
        "",
        "## Scope",
        "",
        "Ground truth comes from manually separated positive and negative fixtures. Symbol-renamed variants are correlated regression cases and are not presented as independent GitHub ground truth.",
        "",
        "## Metrics",
        "",
        "| Set | N | TP | TN | FP | FN | Accuracy | Precision | Recall | FPR | FNR |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        _metric_row("Independent templates", base),
        _metric_row("Expanded regression", expanded),
        "",
        f"Expanded threshold result: **{'PASS' if payload['thresholds_passed_on_expanded_regression'] else 'FAIL'}**",
        "",
        f"FPR 95% Wilson interval: `{expanded['fpr_wilson_95']}`",
        "",
        f"FNR 95% Wilson interval: `{expanded['fnr_wilson_95']}`",
        "",
        "## Failures",
        "",
    ]
    if failures:
        lines.extend(f"- `{item['case_id']}` expected={item['expected_positive']} predicted={item['predicted_positive']}" for item in failures)
    else:
        lines.append("No classification failures in the expanded regression set.")
    lines.extend([
        "",
        "## Interpretation",
        "",
        payload["methodology"]["limitation"],
        "",
    ])
    return "\n".join(lines)


def _metric_row(label: str, metrics: dict[str, Any]) -> str:
    return (
        f"| {label} | {metrics['count']} | {metrics['true_positive']} | {metrics['true_negative']} | "
        f"{metrics['false_positive']} | {metrics['false_negative']} | {metrics['accuracy']:.3%} | "
        f"{metrics['precision']:.3%} | {metrics['recall']:.3%} | "
        f"{metrics['false_positive_rate']:.3%} | {metrics['false_negative_rate']:.3%} |"
    )


if __name__ == "__main__":
    raise SystemExit(main())
