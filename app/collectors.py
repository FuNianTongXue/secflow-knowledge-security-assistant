from __future__ import annotations

import re
from copy import deepcopy
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

    def _collect_cve(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        headers = {"User-Agent": "SecFlow-Knowledge-Security-Assistant/1.0"}
        if config.get("api_key"):
            headers["apiKey"] = config["api_key"]
        params = {"resultsPerPage": str(min(int(config.get("max_results", 20)), 200))}
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            response = client.get(config["api_url"], params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
        records: list[dict[str, Any]] = []
        allowed = {str(item).upper() for item in config.get("severity_filter", [])}
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = str(cve.get("id", "")).upper()
            if not cve_id:
                continue
            severity = _nvd_severity(cve)
            if allowed and severity.upper() not in allowed:
                continue
            records.append(
                {
                    "id": cve_id,
                    "title": _description(cve)[:160] or cve_id,
                    "severity": severity,
                    "source": "NVD",
                    "summary": _description(cve),
                    "references": [ref.get("url") for ref in cve.get("references", {}).get("referenceData", []) if ref.get("url")],
                    "collection": config.get("collection_name", "cve"),
                    "updated_at": cve.get("lastModified") or now_iso(),
                }
            )
        return records

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


def _nvd_severity(cve: dict[str, Any]) -> str:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
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


collector_service = CollectorService()

