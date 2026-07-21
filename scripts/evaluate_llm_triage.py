from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.llm import active_model_from_env, chat_readiness_error, diagnose_chat_completion  # noqa: E402


PROMPT_VERSION = "java-security-triage-v2"
SYSTEM_PROMPT = """你是 Java 安全扫描候选的独立复核节点。你只能依据提供的完整代码和数据流证据判断，不得猜测缺失上下文。
判定规则：
1. 对 CWE-78/79/89/90/22/501/643 等数据流漏洞，confirmed 必须有攻击者可控输入到对应 sink 的可执行路径，且没有有效校验、编码、参数化或信任边界约束。
2. 对 CWE-327/328/330/614 等危险算法或安全配置，是否存在攻击者输入不是成立条件；应依据算法、随机数用途或 Cookie 配置本身判断。
3. rejected：证据显示安全分支恒定可达、危险值被覆盖为安全常量、存在对应场景的有效净化，规则把任意方法参数误当外部输入，或候选与 CWE 不匹配。
4. uncertain：完整文件仍不足以确认跨文件调用者、动态配置值或部署信任边界。
5. 必须为输入中的每一个 id 返回且只返回一个 decision，不得遗漏。
不要生成 PoC、载荷或利用步骤。输出严格 JSON：{"decisions":[{"id":"...","verdict":"confirmed|rejected|uncertain","confidence":0.0,"reason":"中文短句"}]}。"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Blind LLM triage for Java static-analysis candidates.")
    parser.add_argument("--mode", choices=["benchmark", "projects"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--max-batch-chars", type=int, default=60000)
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--flow-results", type=Path)
    parser.add_argument("--baseline-results", type=Path)
    parser.add_argument("--baseline-flow-results", type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--scan-results-dir", type=Path)
    parser.add_argument("--repositories-dir", type=Path)
    parser.add_argument("--max-per-project", type=int, default=5)
    return parser.parse_args()


def cwes_from_values(values: Any) -> list[str]:
    if isinstance(values, str):
        values = [values]
    return list(
        dict.fromkeys(
            f"CWE-{int(match.group(1))}"
            for value in values or []
            for match in re.finditer(r"CWE[-_ ]?(\d+)", str(value), flags=re.IGNORECASE)
        )
    )


def candidate_id(*parts: Any) -> str:
    digest = hashlib.sha256("\x1f".join(str(part) for part in parts).encode("utf-8")).hexdigest()
    return f"candidate-{digest[:16]}"


def source_context(path: Path, lines: list[int], radius: int = 32) -> str:
    if not path.is_file():
        return "代码文件不可用。"
    content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    complete = "\n".join(f"{index:04d}: {line}" for index, line in enumerate(content, start=1))
    if len(complete) <= 20000:
        return complete
    valid_lines = [line for line in lines if line > 0]
    center = min(valid_lines) if valid_lines else 1
    start = max(1, center - radius)
    end = min(len(content), center + radius)
    excerpt = "\n".join(f"{index:04d}: {content[index - 1]}" for index in range(start, end + 1))
    return excerpt[:16000]


def expected_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(newline="", encoding="utf-8") as stream:
        for row in csv.reader(stream):
            if not row or row[0].startswith("#"):
                continue
            rows.append(
                {
                    "test": row[0],
                    "category": row[1],
                    "vulnerable": row[2].strip().lower() == "true",
                    "cwe": f"CWE-{int(row[3])}",
                }
            )
    return rows


def benchmark_partition(item: dict[str, Any], diagnostic_percent: int = 70) -> str:
    digest = hashlib.sha256(f"{item['test']}|{item['cwe']}".encode("utf-8")).hexdigest()
    return "diagnostic" if int(digest[:8], 16) % 100 < diagnostic_percent else "holdout"


def benchmark_candidates(
    expected_path: Path,
    results_path: Path,
    flow_results_path: Path | None,
    source_root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    expected = expected_rows(expected_path)
    expected_keys = {(item["test"], item["cwe"]) for item in expected}
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    payload = json.loads(results_path.read_text(encoding="utf-8"))
    for finding in payload.get("results") or []:
        path_text = str(finding.get("path") or "")
        match = re.search(r"(BenchmarkTest\d+)", path_text)
        if not match:
            continue
        metadata = (finding.get("extra") or {}).get("metadata") or {}
        for cwe in cwes_from_values(metadata.get("cwe") or metadata.get("cwes") or []):
            key = (match.group(1), cwe)
            if key not in expected_keys:
                continue
            item = grouped.setdefault(
                key,
                {
                    "id": candidate_id(*key),
                    "benchmark_test": key[0],
                    "project": "OWASP BenchmarkJava 1.2",
                    "cwe": cwe,
                    "path": path_text,
                    "lines": [],
                    "rules": [],
                    "messages": [],
                    "flow_evidence": [],
                },
            )
            item["lines"].append(int((finding.get("start") or {}).get("line") or 0))
            item["rules"].append(str(finding.get("check_id") or ""))
            item["messages"].append(str((finding.get("extra") or {}).get("message") or ""))

    if flow_results_path and flow_results_path.is_file():
        flow_payload = json.loads(flow_results_path.read_text(encoding="utf-8"))
        for finding in flow_payload.get("findings") or []:
            if str(finding.get("confidence") or "").lower() != "high" or int(finding.get("analysis_depth") or 0) < 1:
                continue
            sink = finding.get("sink") or {}
            match = re.search(r"(BenchmarkTest\d+)", str(sink.get("file") or ""))
            if not match:
                continue
            for cwe in cwes_from_values(finding.get("cwes") or []):
                key = (match.group(1), cwe)
                if key not in expected_keys:
                    continue
                path_text = str(sink.get("file") or "")
                item = grouped.setdefault(
                    key,
                    {
                        "id": candidate_id(*key),
                        "benchmark_test": key[0],
                        "project": "OWASP BenchmarkJava 1.2",
                        "cwe": cwe,
                        "path": path_text,
                        "lines": [],
                        "rules": [],
                        "messages": [],
                        "flow_evidence": [],
                    },
                )
                item["lines"].extend(
                    [int((finding.get("source") or {}).get("line") or 0), int(sink.get("line") or 0)]
                )
                item["rules"].append(str(finding.get("rule_id") or ""))
                item["messages"].append(str(finding.get("title") or ""))
                item["flow_evidence"].append(
                    {
                        "cfg": str(finding.get("cfg") or ""),
                        "dfg": str(finding.get("dfg") or ""),
                        "path": [
                            {
                                "kind": str(node.get("kind") or ""),
                                "line": int(node.get("line") or 0),
                                "label": str(node.get("label") or ""),
                                "snippet": str(node.get("snippet") or ""),
                            }
                            for node in finding.get("path") or []
                        ],
                    }
                )

    candidates = []
    for item in grouped.values():
        source_path = Path(str(item["path"]))
        if not source_path.is_absolute():
            source_path = source_root / source_path
        if not source_path.is_file():
            source_path = source_root / f"{item['benchmark_test']}.java"
        item["rules"] = list(dict.fromkeys(item["rules"]))
        item["messages"] = list(dict.fromkeys(item["messages"]))
        item["code"] = source_context(source_path, item["lines"])
        item["display_path"] = source_path.name
        candidates.append(item)
    return sorted(candidates, key=lambda item: (item["benchmark_test"], item["cwe"])), expected


def project_candidates(
    manifest_path: Path,
    results_dir: Path,
    repositories_dir: Path,
    max_per_project: int,
) -> list[dict[str, Any]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    candidates: list[dict[str, Any]] = []
    for spec in manifest:
        slug = str(spec["slug"])
        result_path = results_dir / f"{slug.replace('/', '__')}.json"
        if not result_path.is_file():
            continue
        payload = json.loads(result_path.read_text(encoding="utf-8"))
        project_items: list[dict[str, Any]] = []
        seen: set[tuple[str, str, int]] = set()
        for finding in payload.get("results") or []:
            rule = str(finding.get("check_id") or "")
            path_text = str(finding.get("path") or "")
            line = int((finding.get("start") or {}).get("line") or 0)
            key = (rule, path_text, line)
            if key in seen:
                continue
            seen.add(key)
            metadata = (finding.get("extra") or {}).get("metadata") or {}
            path = Path(path_text)
            if not path.is_absolute():
                path = repositories_dir / slug.replace("/", "__") / path
            project_items.append(
                {
                    "id": candidate_id(slug, rule, path_text, line),
                    "project": slug,
                    "cwe": ", ".join(cwes_from_values(metadata.get("cwe") or metadata.get("cwes") or [])) or "未明确",
                    "path": path_text,
                    "display_path": path_text,
                    "lines": [line],
                    "rules": [rule],
                    "messages": [str((finding.get("extra") or {}).get("message") or "")],
                    "flow_evidence": [],
                    "code": source_context(path, [line]),
                }
            )
        project_items.sort(key=lambda item: (item["cwe"], item["path"], item["lines"][0]))
        candidates.extend(project_items[: max(0, max_per_project)])
    return candidates


def prompt_candidate(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item["id"],
        "project": item["project"],
        "cwe": item["cwe"],
        "finding": item["messages"],
        "file": item["display_path"],
        "lines": item["lines"],
        "flow_evidence": item["flow_evidence"],
        "code": item["code"],
    }


def make_batches(candidates: list[dict[str, Any]], batch_size: int, max_chars: int) -> list[list[dict[str, Any]]]:
    batches: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    current_chars = 0
    for candidate in candidates:
        size = len(json.dumps(prompt_candidate(candidate), ensure_ascii=False))
        if current and (len(current) >= batch_size or current_chars + size > max_chars):
            batches.append(current)
            current = []
            current_chars = 0
        current.append(candidate)
        current_chars += size
    if current:
        batches.append(current)
    return batches


def parse_model_json(value: str) -> dict[str, Any]:
    text = value.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            return {}
        try:
            payload = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return {}
    return payload if isinstance(payload, dict) else {}


def metric(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def matrix_metrics(matrix: Counter[str]) -> dict[str, Any]:
    tp, fp, tn, fn = matrix["TP"], matrix["FP"], matrix["TN"], matrix["FN"]
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


def score_benchmark(
    expected: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    decisions: dict[str, dict[str, Any]],
    baseline_candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    candidate_by_key = {(item["benchmark_test"], item["cwe"]): item for item in candidates}
    baseline_keys = {(item["benchmark_test"], item["cwe"]) for item in baseline_candidates}
    matrices = {
        "engine": Counter(),
        "llm_strict": Counter(),
        "llm_review": Counter(),
    }
    if baseline_keys:
        matrices["baseline_engine"] = Counter()
    categories: dict[str, dict[str, Counter[str]]] = defaultdict(
        lambda: {policy: Counter() for policy in matrices}
    )
    for item in expected:
        key = (item["test"], item["cwe"])
        baseline_detected = key in baseline_keys
        candidate = candidate_by_key.get(key)
        verdict = str((decisions.get(str((candidate or {}).get("id") or "")) or {}).get("verdict") or "")
        positives = {
            "engine": baseline_detected or bool(candidate),
            "llm_strict": baseline_detected or (bool(candidate) and verdict == "confirmed"),
            "llm_review": baseline_detected or (bool(candidate) and verdict in {"confirmed", "uncertain"}),
        }
        if baseline_keys:
            positives["baseline_engine"] = baseline_detected
        for policy, detected in positives.items():
            outcome = "TP" if item["vulnerable"] and detected else "FN" if item["vulnerable"] else "FP" if detected else "TN"
            matrices[policy][outcome] += 1
            categories[item["category"]][policy][outcome] += 1
    return {
        "overall": {policy: matrix_metrics(matrix) for policy, matrix in matrices.items()},
        "categories": {
            category: {policy: matrix_metrics(matrix) for policy, matrix in policies.items()}
            for category, policies in sorted(categories.items())
        },
    }


def write_report(
    path: Path,
    *,
    mode: str,
    model: dict[str, Any],
    candidates: list[dict[str, Any]],
    decisions: dict[str, dict[str, Any]],
    failures: list[dict[str, Any]],
    expected: list[dict[str, Any]],
    baseline_candidates: list[dict[str, Any]],
    complete: bool,
) -> None:
    verdict_counts = Counter(str(item.get("verdict") or "missing") for item in decisions.values())
    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "mode": mode,
        "model": {
            "provider": str(model.get("provider") or ""),
            "model": str(model.get("model") or ""),
        },
        "methodology": {
            "prompt_version": PROMPT_VERSION,
            "blind_review": True,
            "ground_truth_in_prompt": False,
            "verdicts": ["confirmed", "rejected", "uncertain"],
            "combined_recall_limit": "LLM filtering cannot recover findings missed by the static engine.",
            "ordinary_projects_have_ground_truth": False,
        },
        "candidate_count": len(candidates),
        "baseline_candidate_count": len(baseline_candidates),
        "adjudicated_count": len(decisions),
        "complete": complete,
        "verdict_counts": dict(verdict_counts),
        "failures": failures,
        "decisions": sorted(decisions.values(), key=lambda item: str(item.get("id") or "")),
    }
    if mode == "benchmark" and complete:
        report["benchmark"] = score_benchmark(expected, candidates, decisions, baseline_candidates)
        report["benchmark"]["partitions"] = {
            partition: score_benchmark(
                [item for item in expected if benchmark_partition(item) == partition],
                candidates,
                decisions,
                baseline_candidates,
            )
            for partition in ("diagnostic", "holdout")
        }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    if args.mode == "benchmark":
        required = [args.expected, args.results, args.source_root]
        if any(value is None for value in required):
            raise SystemExit("benchmark mode requires --expected, --results, and --source-root")
        candidates, expected = benchmark_candidates(
            args.expected,
            args.results,
            args.flow_results,
            args.source_root,
        )
        baseline_candidates: list[dict[str, Any]] = []
        if args.baseline_results:
            baseline_candidates, _ = benchmark_candidates(
                args.expected,
                args.baseline_results,
                args.baseline_flow_results,
                args.source_root,
            )
            baseline_keys = {
                (item["benchmark_test"], item["cwe"])
                for item in baseline_candidates
            }
            candidates = [
                item
                for item in candidates
                if (item["benchmark_test"], item["cwe"]) not in baseline_keys
            ]
    else:
        required = [args.manifest, args.scan_results_dir, args.repositories_dir]
        if any(value is None for value in required):
            raise SystemExit("projects mode requires --manifest, --scan-results-dir, and --repositories-dir")
        candidates = project_candidates(
            args.manifest,
            args.scan_results_dir,
            args.repositories_dir,
            args.max_per_project,
        )
        expected = []
        baseline_candidates = []

    if args.limit > 0:
        candidates = candidates[: args.limit]

    model = active_model_from_env()
    readiness_error = chat_readiness_error(model)
    if readiness_error or model is None:
        raise SystemExit(readiness_error or "No model configured")

    decisions: dict[str, dict[str, Any]] = {}
    failures: list[dict[str, Any]] = []
    if args.resume and args.output.is_file():
        try:
            previous = json.loads(args.output.read_text(encoding="utf-8"))
            decisions = {
                str(item.get("id") or ""): item
                for item in previous.get("decisions") or []
                if isinstance(item, dict) and item.get("id")
            }
            failures = [item for item in previous.get("failures") or [] if isinstance(item, dict)]
        except (OSError, json.JSONDecodeError):
            decisions = {}
            failures = []

    pending = [candidate for candidate in candidates if candidate["id"] not in decisions]
    batches = make_batches(pending, max(1, args.batch_size), max(4000, args.max_batch_chars))
    for index, batch in enumerate(batches, start=1):
        print(f"[{index}/{len(batches)}] reviewing {len(batch)} candidates", flush=True)
        result = diagnose_chat_completion(
            model,
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps({"candidates": [prompt_candidate(item) for item in batch]}, ensure_ascii=False),
                },
            ],
            json_mode=True,
        )
        if result.get("status") != "success":
            failures.append(
                {
                    "batch": index,
                    "candidate_ids": [item["id"] for item in batch],
                    "message": str(result.get("message") or "model request failed")[:500],
                }
            )
            write_report(
                args.output,
                mode=args.mode,
                model=model,
                candidates=candidates,
                decisions=decisions,
                failures=failures,
                expected=expected,
                baseline_candidates=baseline_candidates,
                complete=False,
            )
            continue

        payload = parse_model_json(str(result.get("answer") or ""))
        returned = {
            str(item.get("id") or ""): item
            for item in payload.get("decisions") or []
            if isinstance(item, dict) and item.get("id")
        }
        missing_ids = [candidate["id"] for candidate in batch if candidate["id"] not in returned]
        if missing_ids:
            failures.append(
                {
                    "batch": index,
                    "candidate_ids": missing_ids,
                    "message": "模型结构化响应遗漏候选，未将缺失项记为 uncertain；下次续跑将重试。",
                }
            )
        for candidate in batch:
            raw = returned.get(candidate["id"], {})
            if not raw:
                continue
            verdict = str(raw.get("verdict") or "uncertain").lower()
            if verdict not in {"confirmed", "rejected", "uncertain"}:
                verdict = "uncertain"
            try:
                confidence = float(raw.get("confidence") or 0.0)
            except (TypeError, ValueError):
                confidence = 0.0
            decisions[candidate["id"]] = {
                "id": candidate["id"],
                "project": candidate["project"],
                "benchmark_test": candidate.get("benchmark_test", ""),
                "cwe": candidate["cwe"],
                "file": candidate["display_path"],
                "lines": candidate["lines"],
                "verdict": verdict,
                "confidence": max(0.0, min(confidence, 1.0)),
                "reason": str(raw.get("reason") or "模型未提供理由。")[:500],
                "latency_ms": result.get("latency_ms"),
            }
        complete = len(decisions) == len(candidates)
        write_report(
            args.output,
            mode=args.mode,
            model=model,
            candidates=candidates,
            decisions=decisions,
            failures=failures,
            expected=expected,
            baseline_candidates=baseline_candidates,
            complete=complete,
        )
        time.sleep(0.15)

    complete = len(decisions) == len(candidates)
    write_report(
        args.output,
        mode=args.mode,
        model=model,
        candidates=candidates,
        decisions=decisions,
        failures=failures,
        expected=expected,
        baseline_candidates=baseline_candidates,
        complete=complete,
    )
    print(json.dumps({"candidates": len(candidates), "decisions": len(decisions), "complete": complete}, ensure_ascii=False))
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
