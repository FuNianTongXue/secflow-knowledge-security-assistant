from __future__ import annotations

import json
import os
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any


DATA_DIR = Path(os.getenv("SECFLOW_DATA_DIR", "data"))
STATE_PATH = DATA_DIR / "state.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def default_state() -> dict[str, Any]:
    return {
        "collectors": {
            "cve": {
                "id": "cve",
                "name": "CVE Vulnerability Database",
                "enabled": True,
                "api_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "api_key": "",
                "collection_name": "cve",
                "severity_filter": ["CRITICAL", "HIGH", "MEDIUM"],
                "dedupe_key": "cve_id",
                "max_results": 20,
                "sync_interval_minutes": 60,
                "last_test": None,
                "last_collect": None,
            },
            "github_advisory": {
                "id": "github_advisory",
                "name": "GitHub Advisory",
                "enabled": True,
                "api_url": "https://api.github.com/advisories",
                "token": "",
                "collection_name": "github_advisory",
                "severity_filter": ["critical", "high", "medium"],
                "ecosystem": "",
                "dedupe_key": "ghsa_id",
                "max_results": 20,
                "sync_interval_minutes": 60,
                "last_test": None,
                "last_collect": None,
            },
        },
        "records": [
            {
                "id": "CVE-2021-44228",
                "title": "Apache Log4j remote code execution vulnerability",
                "severity": "CRITICAL",
                "source": "seed",
                "summary": "Log4Shell allows remote code execution through crafted JNDI lookup strings in vulnerable Log4j versions.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                "collection": "cve",
                "updated_at": now_iso(),
            },
            {
                "id": "GHSA-jfh8-c2jp-5v3q",
                "title": "Example GitHub Advisory security record",
                "severity": "high",
                "source": "seed",
                "summary": "A sample advisory record used to validate the GitHub Advisory knowledge collection flow.",
                "references": ["https://github.com/advisories"],
                "collection": "github_advisory",
                "updated_at": now_iso(),
            },
        ],
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }


class StateStore:
    def __init__(self, path: Path = STATE_PATH) -> None:
        self.path = path
        self._lock = RLock()

    def read(self) -> dict[str, Any]:
        with self._lock:
            if not self.path.exists():
                state = default_state()
                self.write(state)
                return state
            try:
                with self.path.open("r", encoding="utf-8") as handle:
                    return json.load(handle)
            except (json.JSONDecodeError, OSError):
                state = default_state()
                self.write(state)
                return state

    def write(self, state: dict[str, Any]) -> None:
        with self._lock:
            state["updated_at"] = now_iso()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as handle:
                json.dump(state, handle, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)

    def public_state(self) -> dict[str, Any]:
        state = deepcopy(self.read())
        for config in state.get("collectors", {}).values():
            if config.get("api_key"):
                config["api_key"] = mask_secret(config["api_key"])
            if config.get("token"):
                config["token"] = mask_secret(config["token"])
        return state


def mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "********"
    return f"{value[:4]}********{value[-4:]}"


store = StateStore()

