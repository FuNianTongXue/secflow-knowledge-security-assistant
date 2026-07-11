#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
SMOKE_DATA_DIR="$(mktemp -d)"
trap 'rm -rf "$SMOKE_DATA_DIR"' EXIT

export SECFLOW_DATA_DIR="$SMOKE_DATA_DIR"
export DATABASE_URL=""
export POSTGRES_DSN=""
export SECFLOW_LLM_API_KEY=""
export DEEPSEEK_API_KEY=""
export OPENAI_API_KEY=""

"$PYTHON_BIN" -m py_compile app/*.py
"$PYTHON_BIN" - <<'PY'
from app.collectors import _nvd_datetime, _nvd_references, _nvd_severity, collector_service
from app.main import app
from app.graph import knowledge_graph
from datetime import datetime, timezone

assert app.title == "SecFlow Knowledge Security Assistant"
result = knowledge_graph.invoke("Explain CVE-2021-44228", 5)
assert result["mode"] == "vulnerability_lookup"
assert result["records"]

assert _nvd_references({"references": [{"url": "https://nvd.example/CVE-2025-0001"}]}) == [
    "https://nvd.example/CVE-2025-0001"
]
assert _nvd_severity({"metrics": {"cvssMetricV40": [{"cvssData": {"baseSeverity": "CRITICAL"}}]}}) == "CRITICAL"
assert _nvd_datetime(datetime(2025, 1, 1, tzinfo=timezone.utc)).endswith("Z")

original_collect = collector_service.collect_cve_by_years
collector_service.collect_cve_by_years = lambda years, max_results=20: {
    "status": "success",
    "message": "mocked",
    "records": [
        {
            "id": "CVE-2021-9999",
            "title": "Mock year-aware CVE",
            "severity": "HIGH",
            "source": "NVD",
            "summary": "Deterministic smoke-test record.",
            "references": ["https://nvd.example/CVE-2021-9999"],
            "collection": "cve",
            "published_at": "2021-12-31T00:00:00.000Z",
            "updated_at": "2021-12-31T00:00:00.000Z",
        }
    ],
}
try:
    year_result = knowledge_graph.invoke("2021 年最新 CVE 漏洞有哪些？", 5)
    assert year_result["mode"] == "vulnerability_year_lookup"
    assert year_result["fields"]["年份过滤"] == "2021"
    assert year_result["records"][0]["id"] == "CVE-2021-9999"
    assert any(item["node"] == "fetch_live_vulnerability" for item in year_result["trace"])
finally:
    collector_service.collect_cve_by_years = original_collect

print("smoke-ok")
PY
