from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.source_filter import SEMGREP_EXCLUDE_PATTERNS, is_excluded_source_path  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate the bundled Java Semgrep rules on fixed repositories.")
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--manifest", type=Path, default=root / "config/evaluation/high-star-java-projects.json")
    parser.add_argument("--rules", type=Path, default=root / "config/semgrep/java-security.yml")
    parser.add_argument("--workspace", type=Path, default=Path("/tmp/secflow-semgrep-evaluation"))
    parser.add_argument("--repositories-dir", type=Path)
    parser.add_argument("--results-dir", type=Path)
    parser.add_argument("--output", type=Path, default=root / "docs/semgrep-java-project-results.json")
    parser.add_argument("--semgrep", default=os.getenv("SECFLOW_SEMGREP_BIN", "semgrep"))
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--scan-timeout", type=int, default=1200)
    parser.add_argument("--jobs", type=int, default=max(1, min(6, (os.cpu_count() or 4) - 1)))
    parser.add_argument("--resume", action="store_true", help="Reuse completed projects with matching pinned commits.")
    return parser.parse_args()


def run(command: list[str], *, cwd: Path | None = None, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"},
    )


def ensure_checkout(spec: dict[str, Any], repositories: Path) -> tuple[Path, str]:
    slug = str(spec["slug"])
    target = repositories / slug.replace("/", "__")
    if not (target / ".git").is_dir():
        target.parent.mkdir(parents=True, exist_ok=True)
        cloned = run(["git", "clone", "--depth", "1", "--filter=blob:none", str(spec["url"]), str(target)], timeout=900)
        if cloned.returncode != 0:
            raise RuntimeError((cloned.stderr or cloned.stdout).strip())
    ref = str(spec.get("ref") or "").strip()
    if ref:
        current = run(["git", "rev-parse", "HEAD"], cwd=target)
        if current.stdout.strip() != ref:
            fetched = run(["git", "fetch", "--depth", "1", "origin", ref], cwd=target, timeout=600)
            if fetched.returncode != 0:
                raise RuntimeError((fetched.stderr or fetched.stdout).strip())
            checked = run(["git", "checkout", "--detach", "FETCH_HEAD"], cwd=target)
            if checked.returncode != 0:
                raise RuntimeError((checked.stderr or checked.stdout).strip())
    commit = run(["git", "rev-parse", "HEAD"], cwd=target)
    if commit.returncode != 0:
        raise RuntimeError((commit.stderr or commit.stdout).strip())
    status = run(["git", "status", "--porcelain"], cwd=target)
    if status.returncode != 0:
        raise RuntimeError((status.stderr or status.stdout).strip())
    if status.stdout.strip():
        restored = run(["git", "checkout", "--force", "HEAD"], cwd=target, timeout=600)
        if restored.returncode != 0:
            raise RuntimeError((restored.stderr or restored.stdout).strip())
    return target, commit.stdout.strip()


def is_excluded(relative: Path) -> bool:
    return is_excluded_source_path(relative)


def source_counts(root: Path) -> dict[str, int]:
    java = 0
    pom = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if is_excluded(relative):
            continue
        if path.suffix.lower() == ".java":
            java += 1
        elif path.name == "pom.xml":
            pom += 1
    return {"java": java, "pom": pom}


def normalized_rule_id(value: str) -> str:
    marker = "secflow.java."
    return marker + value.split(marker, 1)[1] if marker in value else value


def result_cwes(result: dict[str, Any]) -> list[str]:
    metadata = (result.get("extra") or {}).get("metadata") or {}
    values = metadata.get("cwe") or metadata.get("cwes") or []
    if isinstance(values, str):
        values = [values]
    cwes: list[str] = []
    for value in values:
        text = str(value).upper()
        marker = "CWE-"
        if marker not in text:
            continue
        digits = "".join(character for character in text.split(marker, 1)[1] if character.isdigit())
        if digits:
            cwes.append(f"CWE-{int(digits)}")
    return list(dict.fromkeys(cwes))


def scan_project(
    semgrep: str,
    rules: Path,
    root: Path,
    result_path: Path,
    *,
    jobs: int,
    scan_timeout: int,
) -> dict[str, Any]:
    result_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        semgrep,
        "scan",
        "--config",
        str(rules.resolve()),
        "--json-output",
        str(result_path.resolve()),
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--project-root",
        str(root.resolve()),
        "--jobs",
        str(jobs),
        "--timeout",
        "10",
        "--timeout-threshold",
        "3",
        "--max-target-bytes",
        "2000000",
    ]
    for pattern in SEMGREP_EXCLUDE_PATTERNS:
        command.extend(["--exclude", pattern])
    command.append(str(root.resolve()))
    started = time.monotonic()
    try:
        completed = run(command, cwd=root, timeout=scan_timeout)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "elapsed_seconds": round(time.monotonic() - started, 2)}
    elapsed = round(time.monotonic() - started, 2)
    if not result_path.is_file():
        return {
            "status": "failed",
            "elapsed_seconds": elapsed,
            "returncode": completed.returncode,
            "error": "\n".join((completed.stderr or completed.stdout).splitlines()[-8:]),
        }
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    results = payload.get("results") or []
    rule_counts = Counter(normalized_rule_id(str(item.get("check_id") or "")) for item in results)
    cwe_counts = Counter(cwe for item in results for cwe in result_cwes(item))
    severity_counts = Counter(str((item.get("extra") or {}).get("severity") or "UNKNOWN") for item in results)
    unique_locations = {
        (
            normalized_rule_id(str(item.get("check_id") or "")),
            str(item.get("path") or ""),
            int((item.get("start") or {}).get("line") or 0),
        )
        for item in results
    }
    return {
        "status": "completed" if completed.returncode == 0 else "warning",
        "elapsed_seconds": elapsed,
        "returncode": completed.returncode,
        "findings": len(results),
        "unique_findings": len(unique_locations),
        "scanned_targets": len((payload.get("paths") or {}).get("scanned") or []),
        "rule_counts": dict(rule_counts.most_common()),
        "cwe_counts": dict(cwe_counts.most_common()),
        "severity_counts": dict(severity_counts.most_common()),
        "errors": len(payload.get("errors") or []),
    }


def main() -> int:
    args = parse_args()
    specs = json.loads(args.manifest.read_text(encoding="utf-8"))
    if args.limit > 0:
        specs = specs[: args.limit]
    repositories = args.repositories_dir or (args.workspace / "repositories")
    raw_results = args.results_dir or (args.workspace / "results")
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
    version = run([args.semgrep, "--version"])
    if version.returncode != 0:
        raise SystemExit(version.stderr or "Semgrep is not available")
    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "semgrep_version": version.stdout.strip(),
        "rules": str(args.rules.resolve()),
        "test_policy": {
            "metrics": "off",
            "network_rules": False,
            "excluded": SEMGREP_EXCLUDE_PATTERNS,
            "ground_truth": "not available for ordinary open-source projects",
        },
        "projects": [],
    }
    for index, spec in enumerate(specs, start=1):
        slug = str(spec["slug"])
        print(f"[{index}/{len(specs)}] {slug}", flush=True)
        result_path = raw_results / f"{slug.replace('/', '__')}.json"
        previous_item = previous_by_slug.get(slug)
        if (
            args.resume
            and previous_item
            and previous_item.get("status") in {"completed", "warning"}
            and str(previous_item.get("commit") or "") == str(spec.get("ref") or "")
            and result_path.is_file()
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
                scan_project(
                    args.semgrep,
                    args.rules,
                    checkout,
                    result_path,
                    jobs=args.jobs,
                    scan_timeout=args.scan_timeout,
                )
            )
        except Exception as exc:  # noqa: BLE001
            item.update({"status": "failed", "error": str(exc)})
        report["projects"].append(item)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    completed = [item for item in report["projects"] if item.get("status") in {"completed", "warning"}]
    report["summary"] = {
        "requested_projects": len(specs),
        "completed_projects": len(completed),
        "total_java_files": sum(int((item.get("source_files") or {}).get("java") or 0) for item in completed),
        "total_unique_findings": sum(int(item.get("unique_findings") or 0) for item in completed),
        "total_elapsed_seconds": round(sum(float(item.get("elapsed_seconds") or 0) for item in completed), 2),
    }
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if len(completed) == len(specs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
