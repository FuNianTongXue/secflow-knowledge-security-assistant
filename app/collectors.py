from __future__ import annotations

import re
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from app.models import CollectorConfigUpdate
from app.storage import now_iso, store


class CollectorService:
    def snapshot(self) -> dict[str, Any]:
        state = store.public_state()
        return {
            "collectors": state["collectors"],
            "records": state["records"],
            "stats": self._stats(state["records"]),
        }

    def update_config(self, collector_id: str, payload: CollectorConfigUpdate) -> dict[str, Any]:
        state = store.read()
        if collector_id not in state["collectors"]:
            raise KeyError(collector_id)
        config = state["collectors"][collector_id]
        updates = payload.model_dump(exclude_unset=True)
        for key, value in updates.items():
            if value is None:
                continue
            config[key] = value
        store.write(state)
        return {
            "collector": store.public_state()["collectors"][collector_id],
            "message": f"{config['name']} configuration saved.",
        }

    def test_config(self, collector_id: str) -> dict[str, Any]:
        state = store.read()
        if collector_id not in state["collectors"]:
            raise KeyError(collector_id)
        config = state["collectors"][collector_id]
        try:
            if collector_id == "cve":
                result = self._test_cve(config)
            elif collector_id == "github_advisory":
                result = self._test_github_advisory(config)
            else:
                raise KeyError(collector_id)
        except Exception as exc:  # noqa: BLE001
            result = {"status": "failed", "message": str(exc), "checked_at": now_iso()}
        config["last_test"] = result
        store.write(state)
        return result

    def collect(self, collector_id: str) -> dict[str, Any]:
        state = store.read()
        if collector_id not in state["collectors"]:
            raise KeyError(collector_id)
        config = state["collectors"][collector_id]
        if not config.get("enabled", True):
            return {"status": "warning", "message": f"{config['name']} is disabled.", "inserted": 0}

        if collector_id == "cve":
            records = self._collect_cve(config)
        elif collector_id == "github_advisory":
            records = self._collect_github_advisory(config)
        else:
            raise KeyError(collector_id)

        existing = {str(item["id"]).lower(): item for item in state["records"]}
        inserted = 0
        for record in records:
            key = str(record["id"]).lower()
            if key not in existing:
                state["records"].append(record)
                inserted += 1
            else:
                existing[key].update(record)
        config["last_collect"] = {"status": "success", "inserted": inserted, "fetched": len(records), "checked_at": now_iso()}
        store.write(state)
        return {
            "status": "success",
            "message": f"{config['name']} collection finished.",
            "inserted": inserted,
            "fetched": len(records),
            "records": records[:5],
        }

    def collect_cve_by_years(self, years: list[int], max_results: int = 20) -> dict[str, Any]:
        state = store.read()
        config = state["collectors"].get("cve")
        if not config:
            raise KeyError("cve")
        if not config.get("enabled", True):
            return {"status": "warning", "message": "CVE collector is disabled.", "inserted": 0, "fetched": 0, "records": []}

        collected: list[dict[str, Any]] = []
        errors: list[str] = []
        per_year_limit = max(1, min(max_results, int(config.get("max_results", 20))))
        for year in sorted(set(years), reverse=True):
            try:
                collected.extend(self._collect_cve(config, year=year, max_results=per_year_limit))
            except Exception as exc:  # noqa: BLE001 - keep successful years when one source window fails.
                errors.append(f"{year}: {exc}")

        deduped: dict[str, dict[str, Any]] = {}
        for record in collected:
            deduped[str(record["id"]).lower()] = record
        records = sorted(deduped.values(), key=_record_sort_key, reverse=True)[:max_results]

        existing = {str(item["id"]).lower(): item for item in state["records"]}
        inserted = 0
        for record in records:
            key = str(record["id"]).lower()
            if key not in existing:
                state["records"].append(record)
                inserted += 1
            else:
                existing[key].update(record)

        status = "success" if records else "warning" if errors else "success"
        config["last_collect"] = {
            "status": status,
            "inserted": inserted,
            "fetched": len(records),
            "years": sorted(set(years), reverse=True),
            "errors": errors,
            "checked_at": now_iso(),
        }
        store.write(state)
        return {
            "status": status,
            "message": "CVE year collection finished." if not errors else f"CVE year collection completed with {len(errors)} failed year(s).",
            "inserted": inserted,
            "fetched": len(records),
            "records": records,
            "errors": errors,
        }

    @staticmethod
    def search(question: str, top_k: int = 5) -> list[dict[str, Any]]:
        state = store.read()
        query_terms = set(_tokens(question))
        scored: list[tuple[int, dict[str, Any]]] = []
        for record in state["records"]:
            text = " ".join(
                [
                    str(record.get("id", "")),
                    str(record.get("title", "")),
                    str(record.get("summary", "")),
                    str(record.get("severity", "")),
                    str(record.get("source", "")),
                ]
            )
            terms = set(_tokens(text))
            score = len(query_terms & terms)
            if str(record.get("id", "")).lower() in question.lower():
                score += 20
            if score > 0:
                scored.append((score, deepcopy(record)))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [record for _, record in scored[:top_k]]

    @staticmethod
    def search_by_years(question: str, years: list[int], top_k: int = 5) -> list[dict[str, Any]]:
        state = store.read()
        query_terms = set(_tokens(question))
        year_set = {str(year) for year in years}
        scored: list[tuple[int, str, dict[str, Any]]] = []
        for record in state["records"]:
            record_year = _record_year(record)
            if record_year not in year_set:
                continue
            text = " ".join(
                [
                    str(record.get("id", "")),
                    str(record.get("title", "")),
                    str(record.get("summary", "")),
                    str(record.get("severity", "")),
                    str(record.get("source", "")),
                    str(record.get("published_at", "")),
                    str(record.get("updated_at", "")),
                ]
            )
            terms = set(_tokens(text))
            score = len(query_terms & terms) + _severity_score(str(record.get("severity", "")))
            if str(record.get("collection", "")).lower() == "cve":
                score += 3
            scored.append((score, str(record.get("published_at") or record.get("updated_at") or ""), deepcopy(record)))
        scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
        return [record for _, _, record in scored[:top_k]]

    @staticmethod
    def _stats(records: list[dict[str, Any]]) -> dict[str, Any]:
        by_collection: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for record in records:
            by_collection[record.get("collection", "unknown")] = by_collection.get(record.get("collection", "unknown"), 0) + 1
            sev = str(record.get("severity", "unknown")).upper()
            by_severity[sev] = by_severity.get(sev, 0) + 1
        return {"total": len(records), "by_collection": by_collection, "by_severity": by_severity}

    @staticmethod
    def _test_cve(config: dict[str, Any]) -> dict[str, Any]:
        params = {"resultsPerPage": "1"}
        headers = {"User-Agent": "SecFlow-Knowledge-Security-Assistant/1.0"}
        if config.get("api_key"):
            headers["apiKey"] = config["api_key"]
        with httpx.Client(timeout=12.0, follow_redirects=True) as client:
            response = client.get(config["api_url"], params=params, headers=headers)
            response.raise_for_status()
        return {"status": "success", "message": "NVD CVE API is reachable.", "checked_at": now_iso()}

    @staticmethod
    def _test_github_advisory(config: dict[str, Any]) -> dict[str, Any]:
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "SecFlow-Knowledge-Security-Assistant/1.0"}
        if config.get("token"):
            headers["Authorization"] = f"Bearer {config['token']}"
        with httpx.Client(timeout=12.0, follow_redirects=True) as client:
            response = client.get(config["api_url"], params={"per_page": "1"}, headers=headers)
            response.raise_for_status()
        return {"status": "success", "message": "GitHub Advisory API is reachable.", "checked_at": now_iso()}

    def _collect_cve(self, config: dict[str, Any], year: int | None = None, max_results: int | None = None) -> list[dict[str, Any]]:
        headers = {"User-Agent": "SecFlow-Knowledge-Security-Assistant/1.0"}
        if config.get("api_key"):
            headers["apiKey"] = config["api_key"]
        limit = min(int(max_results or config.get("max_results", 20)), 200)
        page_size = min(max(limit * 5, 100), 2000)
        base_params = {"resultsPerPage": str(page_size)}
        windows = _nvd_year_windows(year) if year else [(None, None)]
        allowed = {str(item).upper() for item in config.get("severity_filter", [])}
        records: dict[str, dict[str, Any]] = {}
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            for start, end in windows:
                params = dict(base_params)
                if start and end:
                    params["pubStartDate"] = _nvd_datetime(start)
                    params["pubEndDate"] = _nvd_datetime(end)
                response = client.get(config["api_url"], params=params, headers=headers)
                response.raise_for_status()
                data = response.json()
                total_results = int(data.get("totalResults") or 0)
                if total_results > page_size:
                    params["startIndex"] = str(max(0, total_results - page_size))
                    response = client.get(config["api_url"], params=params, headers=headers)
                    response.raise_for_status()
                    data = response.json()
                for item in data.get("vulnerabilities", []):
                    record = _nvd_record(item.get("cve", {}), config, year)
                    if not record or (allowed and str(record["severity"]).upper() not in allowed):
                        continue
                    records[str(record["id"]).lower()] = record
                if len(records) >= limit:
                    break
        return sorted(records.values(), key=_record_sort_key, reverse=True)[:limit]

    def _collect_github_advisory(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "SecFlow-Knowledge-Security-Assistant/1.0"}
        if config.get("token"):
            headers["Authorization"] = f"Bearer {config['token']}"
        params = {"per_page": str(min(int(config.get("max_results", 20)), 100))}
        if config.get("ecosystem"):
            params["ecosystem"] = config["ecosystem"]
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            response = client.get(config["api_url"], params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
        records: list[dict[str, Any]] = []
        allowed = {str(item).lower() for item in config.get("severity_filter", [])}
        for item in data if isinstance(data, list) else []:
            ghsa_id = str(item.get("ghsa_id", "")).upper()
            if not ghsa_id:
                continue
            severity = str(item.get("severity") or "unknown")
            if allowed and severity.lower() not in allowed:
                continue
            references = [item.get("html_url")] if item.get("html_url") else []
            records.append(
                {
                    "id": ghsa_id,
                    "title": item.get("summary") or ghsa_id,
                    "severity": severity,
                    "source": "GitHub Advisory",
                    "summary": item.get("description") or item.get("summary") or "",
                    "references": references,
                    "collection": config.get("collection_name", "github_advisory"),
                    "updated_at": item.get("updated_at") or now_iso(),
                }
            )
        return records


def _description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    for item in descriptions:
        if item.get("lang") == "en" and item.get("value"):
            return str(item["value"])
    return str(descriptions[0].get("value", "")) if descriptions else ""


def _nvd_record(cve: dict[str, Any], config: dict[str, Any], year: int | None) -> dict[str, Any] | None:
    cve_id = str(cve.get("id", "")).upper()
    if not cve_id or (year and not cve_id.startswith(f"CVE-{year}-")):
        return None
    if str(cve.get("vulnStatus") or "").lower() == "rejected":
        return None
    summary = _description(cve)
    return {
        "id": cve_id,
        "title": summary[:160] or cve_id,
        "severity": _nvd_severity(cve),
        "source": "NVD",
        "summary": summary,
        "references": _nvd_references(cve),
        "collection": config.get("collection_name", "cve"),
        "published_at": cve.get("published") or "",
        "updated_at": cve.get("lastModified") or now_iso(),
    }


def _nvd_references(cve: dict[str, Any]) -> list[str]:
    references = cve.get("references") or []
    if isinstance(references, dict):
        references = references.get("referenceData") or []
    if not isinstance(references, list):
        return []
    return [str(reference["url"]) for reference in references if isinstance(reference, dict) and reference.get("url")]


def _nvd_severity(cve: dict[str, Any]) -> str:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            cvss = values[0].get("cvssData", {})
            return str(cvss.get("baseSeverity") or values[0].get("baseSeverity") or "UNKNOWN")
    return "UNKNOWN"


def _tokens(text: str) -> list[str]:
    lowered = text.lower()
    tokens = re.findall(r"cve-\d{4}-\d{4,8}|ghsa-[a-z0-9-]+|cwe-\d+|[a-z0-9_.+-]{2,}", lowered)
    tokens.extend(re.findall(r"[\u4e00-\u9fff]{2,}", lowered))
    return tokens


def _nvd_year_windows(year: int | None) -> list[tuple[datetime, datetime]]:
    if not year:
        return []
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = datetime(year, 1, 1, tzinfo=timezone.utc)
    final = datetime(year + 1, 1, 1, tzinfo=timezone.utc) - timedelta(seconds=1)
    if year >= now.year:
        final = min(final, now)
    windows: list[tuple[datetime, datetime]] = []
    cursor = final
    while cursor >= start:
        window_start = max(start, cursor - timedelta(days=89, hours=23, minutes=59, seconds=59))
        windows.append((window_start, cursor))
        cursor = window_start - timedelta(seconds=1)
    return windows


def _nvd_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _record_year(record: dict[str, Any]) -> str:
    cve = re.match(r"CVE-(\d{4})-", str(record.get("id", "")), flags=re.IGNORECASE)
    if cve:
        return cve.group(1)
    for key in ("published_at", "updated_at"):
        value = str(record.get(key, ""))
        if re.match(r"\d{4}-", value):
            return value[:4]
    return ""


def _record_sort_key(record: dict[str, Any]) -> tuple[str, int]:
    timestamp = str(record.get("published_at") or record.get("updated_at") or "")
    return (timestamp, _severity_score(str(record.get("severity", ""))))


def _severity_score(severity: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(severity.upper(), 0)


collector_service = CollectorService()
