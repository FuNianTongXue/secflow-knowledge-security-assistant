from __future__ import annotations

import argparse
import json
import random
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

FINANCE_QUERIES = [
    "finance language:Java archived:false fork:false",
    "fintech language:Java archived:false fork:false",
    "banking language:Java archived:false fork:false",
    "payment language:Java archived:false fork:false",
    '"payment gateway" language:Java archived:false fork:false',
    '"money transfer" language:Java archived:false fork:false',
    "wallet language:Java archived:false fork:false",
    "trading language:Java archived:false fork:false",
    '"stock trading" language:Java archived:false fork:false',
    '"trading platform" language:Java archived:false fork:false',
    "securities language:Java archived:false fork:false",
    "brokerage language:Java archived:false fork:false",
    "broker language:Java archived:false fork:false",
    "exchange language:Java archived:false fork:false",
    '"matching engine" language:Java archived:false fork:false',
    '"order book" language:Java archived:false fork:false',
    "portfolio language:Java archived:false fork:false",
    "investment language:Java archived:false fork:false",
    "ledger language:Java archived:false fork:false",
    '"crypto exchange" language:Java archived:false fork:false',
    '"trading bot" language:Java archived:false fork:false',
    "settlement language:Java archived:false fork:false",
    "loan language:Java archived:false fork:false",
]

RELEVANCE_TERMS = {
    "finance",
    "financial",
    "fintech",
    "bank",
    "banking",
    "payment",
    "pay",
    "wallet",
    "transfer",
    "ledger",
    "trading",
    "trade",
    "trader",
    "stock",
    "securities",
    "broker",
    "brokerage",
    "exchange",
    "matching",
    "orderbook",
    "order-book",
    "portfolio",
    "investment",
    "market",
    "quote",
    "settle",
    "settlement",
    "crypto",
    "cryptocurrency",
    "loan",
    "account",
}

SOFT_EXCLUDE_TERMS = {
    "minecraft",
    "game",
    "language-exchange",
    "currency-converter",
    "demo-only",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Select and pin GitHub finance/trading Java projects.")
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--pages-per-query", type=int, default=3)
    parser.add_argument("--per-page", type=int, default=100)
    parser.add_argument("--seed", type=int, default=20260718)
    parser.add_argument("--workers", type=int, default=10)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "config/evaluation/github-finance-trading-java-200-2026-07-18.json",
    )
    return parser.parse_args()


def run(command: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)


def gh_search(query: str, page: int, per_page: int) -> dict[str, Any]:
    command = [
        "gh",
        "api",
        "-X",
        "GET",
        "search/repositories",
        "-f",
        f"q={query}",
        "-f",
        "sort=stars",
        "-f",
        "order=desc",
        "-f",
        f"per_page={per_page}",
        "-f",
        f"page={page}",
    ]
    last_error = ""
    for attempt in range(1, 5):
        completed = run(command, timeout=90)
        if completed.returncode == 0:
            return json.loads(completed.stdout)
        last_error = (completed.stderr or completed.stdout).strip()
        if "HTTP 5" not in last_error and "rate limit" not in last_error.lower():
            break
        time.sleep(min(12, attempt * 3))
    raise RuntimeError(last_error)


def relevance_score(item: dict[str, Any]) -> int:
    topics = item.get("topics") or []
    text = " ".join(
        [
            str(item.get("full_name") or ""),
            str(item.get("name") or ""),
            str(item.get("description") or ""),
            " ".join(str(topic) for topic in topics),
        ]
    ).lower()
    if any(term in text for term in SOFT_EXCLUDE_TERMS):
        return -10
    return sum(1 for term in RELEVANCE_TERMS if term in text)


def collect_candidates(pages_per_query: int, per_page: int) -> list[dict[str, Any]]:
    by_slug: dict[str, dict[str, Any]] = {}
    for query_index, query in enumerate(FINANCE_QUERIES, start=1):
        for page in range(1, pages_per_query + 1):
            print(f"Query {query_index}/{len(FINANCE_QUERIES)} page {page}: {query}", flush=True)
            payload = gh_search(query, page, per_page)
            items = payload.get("items") or []
            if not items:
                break
            for item in items:
                slug = str(item.get("full_name") or "")
                if not slug or slug in by_slug:
                    continue
                if item.get("archived") or item.get("fork"):
                    continue
                if str(item.get("language") or "").lower() != "java":
                    continue
                score = relevance_score(item)
                if score <= 0:
                    continue
                by_slug[slug] = {
                    "slug": slug,
                    "url": str(item.get("clone_url") or item.get("html_url") or ""),
                    "html_url": str(item.get("html_url") or ""),
                    "stars": int(item.get("stargazers_count") or 0),
                    "description": str(item.get("description") or ""),
                    "topics": item.get("topics") or [],
                    "default_branch": str(item.get("default_branch") or ""),
                    "selection_score": score,
                    "selection_query": query,
                }
            time.sleep(0.2)
    return list(by_slug.values())


def resolve_head(url: str) -> str:
    completed = run(["git", "ls-remote", "--exit-code", url, "HEAD"], timeout=120)
    if completed.returncode != 0 or not completed.stdout.strip():
        raise RuntimeError((completed.stderr or completed.stdout or f"Unable to resolve {url}").strip())
    commit = completed.stdout.split()[0].strip().lower()
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise RuntimeError(f"Invalid HEAD commit returned for {url}: {commit}")
    return commit


def pin(candidates: list[dict[str, Any]], limit: int, workers: int, seed: int) -> list[dict[str, Any]]:
    ranked = sorted(
        candidates,
        key=lambda item: (int(item.get("selection_score") or 0), int(item.get("stars") or 0)),
        reverse=True,
    )
    high_relevance = ranked[: max(limit * 2, limit)]
    random.Random(seed).shuffle(high_relevance)
    selected = sorted(
        high_relevance[:limit],
        key=lambda item: (int(item.get("selection_score") or 0), int(item.get("stars") or 0)),
        reverse=True,
    )
    commits: dict[str, str] = {}
    errors: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 16))) as executor:
        futures = {executor.submit(resolve_head, str(item["url"])): item for item in selected}
        for future in as_completed(futures):
            item = futures[future]
            slug = str(item["slug"])
            try:
                commits[slug] = future.result()
                print(f"Pinned {len(commits)}/{len(selected)}: {slug}", flush=True)
            except Exception as exc:  # noqa: BLE001
                errors[slug] = str(exc)
                print(f"Pin failed: {slug}: {exc}", flush=True)

    pinned: list[dict[str, Any]] = []
    for item in selected:
        slug = str(item["slug"])
        if slug not in commits:
            continue
        pinned.append({**item, "ref": commits[slug]})
    if len(pinned) < limit:
        print(f"Warning: requested {limit}, pinned {len(pinned)}. Pin errors: {len(errors)}", flush=True)
    return pinned


def main() -> int:
    args = parse_args()
    candidates = collect_candidates(args.pages_per_query, args.per_page)
    if len(candidates) < args.limit:
        raise SystemExit(f"Only {len(candidates)} relevant candidates found; requested {args.limit}.")
    manifest = pin(candidates, args.limit, args.workers, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "selection": {
            "limit": args.limit,
            "language": "Java",
            "seed": args.seed,
            "queries": FINANCE_QUERIES,
            "candidate_count": len(candidates),
            "policy": "finance/securities/trading relevance terms in repository name, description, or topics",
        },
        "projects": manifest,
    }
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(manifest)} pinned projects to {args.output}")
    return 0 if len(manifest) >= args.limit else 1


if __name__ == "__main__":
    raise SystemExit(main())
