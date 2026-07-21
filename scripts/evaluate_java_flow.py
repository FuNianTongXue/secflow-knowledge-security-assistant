from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.java_flow_analyzer import analyze_java_interprocedural  # noqa: E402

from evaluate_java_semgrep import ensure_checkout, is_excluded, source_counts  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate Java interprocedural path analysis on fixed repositories.")
    parser.add_argument("--manifest", type=Path, default=ROOT / "config/evaluation/high-star-java-projects.json")
    parser.add_argument("--workspace", type=Path, default=Path("/tmp/secflow-semgrep-evaluation/high-star"))
    parser.add_argument("--baseline-results-dir", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/java-flow-project-results.json")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--source-root", type=Path, help="Analyze one source tree and write raw path-analysis JSON.")
    parser.add_argument("--resume", action="store_true", help="Reuse completed projects with matching pinned commits.")
    return parser.parse_args()


def project_code_files(root: Path) -> list[dict[str, str]]:
    files: list[dict[str, str]] = []
    for path in root.rglob("*.java"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if is_excluded(relative):
            continue
        files.append(
            {
                "file_name": relative.as_posix(),
                "content": path.read_text(encoding="utf-8", errors="replace"),
            }
        )
    return files


def normalized_result_path(value: str, root: Path) -> str:
    path = Path(value)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return path.as_posix()


def baseline_locations(result_path: Path | None, root: Path) -> set[tuple[str, str, int]]:
    if result_path is None or not result_path.is_file():
        return set()
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    locations: set[tuple[str, str, int]] = set()
    for finding in payload.get("results") or []:
        metadata = (finding.get("extra") or {}).get("metadata") or {}
        scenario = str(metadata.get("scenario") or finding.get("check_id") or "")
        locations.add(
            (
                scenario,
                normalized_result_path(str(finding.get("path") or ""), root),
                int((finding.get("start") or {}).get("line") or 0),
            )
        )
    return locations


def evaluate_project(root: Path, baseline_result: Path | None = None) -> dict[str, Any]:
    code_files = project_code_files(root)
    started = time.monotonic()
    analysis = analyze_java_interprocedural(code_files)
    elapsed = round(time.monotonic() - started, 2)
    findings = analysis.get("findings") or []
    high_confidence = [item for item in findings if str(item.get("confidence") or "").lower() == "high"]
    baseline = baseline_locations(baseline_result, root)
    high_locations = {
        (
            str(item.get("scenario") or ""),
            str((item.get("sink") or {}).get("file") or ""),
            int((item.get("sink") or {}).get("line") or 0),
        )
        for item in high_confidence
    }
    overlap = high_locations & baseline
    additions = high_locations - baseline
    return {
        "status": analysis.get("status"),
        "chunked": bool(analysis.get("chunked")),
        "chunk_count": int(analysis.get("chunk_count") or 0),
        "completed_chunk_count": int(analysis.get("completed_chunk_count") or 0),
        "skipped_chunk_count": int(analysis.get("skipped_chunk_count") or 0),
        "elapsed_seconds": elapsed,
        "java_files": len(code_files),
        "method_count": int(analysis.get("method_count") or 0),
        "call_edge_count": int(analysis.get("call_edge_count") or 0),
        "iterations": int(analysis.get("iterations") or 0),
        "parse_error_files": int(analysis.get("parse_error_files") or 0),
        "review_candidates": len(findings),
        "high_confidence_cross_method_candidates": len(high_confidence),
        "unique_high_confidence_cross_method_candidates": len(high_locations),
        "baseline_unique_candidates": len(baseline),
        "overlapping_high_confidence_candidates": len(overlap),
        "new_high_confidence_candidates": len(additions),
        "combined_unique_candidates": len(baseline | high_locations),
        "scenario_counts": dict(Counter(str(item.get("scenario") or "unknown") for item in findings)),
        "high_confidence_scenario_counts": dict(
            Counter(str(item.get("scenario") or "unknown") for item in high_confidence)
        ),
        "diagnostics": [str(item) for item in analysis.get("diagnostics") or []],
    }


def main() -> int:
    args = parse_args()
    if args.source_root:
        previous_max = os.environ.get("SECFLOW_STATIC_MAX_FINDINGS")
        os.environ["SECFLOW_STATIC_MAX_FINDINGS"] = "5000"
        try:
            code_files = project_code_files(args.source_root)
            started = time.monotonic()
            analysis = analyze_java_interprocedural(code_files)
            analysis["elapsed_seconds"] = round(time.monotonic() - started, 2)
            analysis["java_files"] = len(code_files)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(analysis, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(
                json.dumps(
                    {
                        "status": analysis.get("status"),
                        "java_files": len(code_files),
                        "finding_count": analysis.get("finding_count"),
                        "method_count": analysis.get("method_count"),
                        "call_edge_count": analysis.get("call_edge_count"),
                        "elapsed_seconds": analysis.get("elapsed_seconds"),
                    },
                    ensure_ascii=False,
                )
            )
            return 0 if analysis.get("status") == "completed" else 1
        finally:
            if previous_max is None:
                os.environ.pop("SECFLOW_STATIC_MAX_FINDINGS", None)
            else:
                os.environ["SECFLOW_STATIC_MAX_FINDINGS"] = previous_max
    specs = json.loads(args.manifest.read_text(encoding="utf-8"))
    if args.limit > 0:
        specs = specs[: args.limit]
    repositories = args.workspace / "repositories"
    baseline_results = args.baseline_results_dir or (args.workspace / "results")
    previous_by_slug: dict[str, dict[str, Any]] = {}
    if args.resume and args.output.is_file():
        try:
            previous = json.loads(args.output.read_text(encoding="utf-8"))
            previous_by_slug = {
                str(item.get("slug") or ""): item
                for item in previous.get("projects") or []
                if isinstance(item, dict) and item.get("slug")
            }
        except (OSError, json.JSONDecodeError):
            previous_by_slug = {}
    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "methodology": {
            "engine_names_exposed_to_client": False,
            "production_files_only": True,
            "ground_truth": "not available for ordinary open-source projects",
            "interpretation": "counts are review candidates, not confirmed vulnerabilities",
        },
        "projects": [],
    }
    previous_max = os.environ.get("SECFLOW_STATIC_MAX_FINDINGS")
    os.environ["SECFLOW_STATIC_MAX_FINDINGS"] = "5000"
    try:
        for index, spec in enumerate(specs, start=1):
            slug = str(spec["slug"])
            print(f"[{index}/{len(specs)}] {slug}", flush=True)
            previous_item = previous_by_slug.get(slug)
            if (
                args.resume
                and previous_item
                and previous_item.get("status") == "completed"
                and str(previous_item.get("commit") or "") == str(spec.get("ref") or "")
            ):
                report["projects"].append(previous_item)
                print("  reused completed result", flush=True)
                continue
            item: dict[str, Any] = {"slug": slug, "url": spec["url"]}
            try:
                checkout, commit = ensure_checkout(spec, repositories)
                item["commit"] = commit
                item["source_files"] = source_counts(checkout)
                item.update(
                    evaluate_project(
                        checkout,
                        baseline_results / f"{slug.replace('/', '__')}.json",
                    )
                )
            except Exception as exc:  # noqa: BLE001
                item.update({"status": "failed", "error": str(exc)})
            report["projects"].append(item)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    finally:
        if previous_max is None:
            os.environ.pop("SECFLOW_STATIC_MAX_FINDINGS", None)
        else:
            os.environ["SECFLOW_STATIC_MAX_FINDINGS"] = previous_max

    completed = [item for item in report["projects"] if item.get("status") == "completed"]
    report["summary"] = {
        "requested_projects": len(specs),
        "completed_projects": len(completed),
        "total_java_files": sum(int(item.get("java_files") or 0) for item in completed),
        "total_methods": sum(int(item.get("method_count") or 0) for item in completed),
        "total_call_edges": sum(int(item.get("call_edge_count") or 0) for item in completed),
        "total_review_candidates": sum(int(item.get("review_candidates") or 0) for item in completed),
        "total_high_confidence_cross_method_candidates": sum(
            int(item.get("high_confidence_cross_method_candidates") or 0) for item in completed
        ),
        "total_unique_high_confidence_cross_method_candidates": sum(
            int(item.get("unique_high_confidence_cross_method_candidates") or 0) for item in completed
        ),
        "total_baseline_unique_candidates": sum(int(item.get("baseline_unique_candidates") or 0) for item in completed),
        "total_overlapping_high_confidence_candidates": sum(
            int(item.get("overlapping_high_confidence_candidates") or 0) for item in completed
        ),
        "total_new_high_confidence_candidates": sum(
            int(item.get("new_high_confidence_candidates") or 0) for item in completed
        ),
        "total_combined_unique_candidates": sum(int(item.get("combined_unique_candidates") or 0) for item in completed),
        "total_parse_error_files": sum(int(item.get("parse_error_files") or 0) for item in completed),
        "total_elapsed_seconds": round(sum(float(item.get("elapsed_seconds") or 0) for item in completed), 2),
    }
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if len(completed) == len(specs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
