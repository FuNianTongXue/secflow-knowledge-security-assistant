from __future__ import annotations

import re
from copy import deepcopy
from typing import Any


_PRIVATE_KEYS = {
    "source",
    "sources",
    "source_url",
    "sourceUrl",
    "references",
    "reference",
    "collection",
    "collection_name",
    "retrieval_path",
    "provider",
}
_PRIVATE_KEYS_LOWER = {key.lower() for key in _PRIVATE_KEYS}

_INTERNAL_FIELD_KEYS = {
    "意图",
    "长期记忆",
    "模型调用状态",
    "漏洞数据策略",
    "记忆持久化",
    "数据来源",
    "漏洞链接",
    "情报链路",
    "参考来源",
    "集合",
    "RAG 集合",
}

_SEVERITY_MAP = {
    "CRITICAL": "严重",
    "SEVERE": "严重",
    "严重": "严重",
    "HIGH": "高危",
    "高危": "高危",
    "MEDIUM": "中危",
    "MODERATE": "中危",
    "中危": "中危",
    "LOW": "低危",
    "低危": "低危",
    "UNKNOWN": "未知",
    "未知": "未知",
}

_PROVIDER_PATTERN = re.compile(
    r"GitHub\s+Advisory|GitHub\s+Security\s+Advisory|NVD(?:\s+CVE)?|OSV(?:\.dev)?|"
    r"Milvus|RAG|向量库|实时\s*CVE\s*接口|CVE\s*接口",
    flags=re.IGNORECASE,
)


def severity_cn(value: Any) -> str:
    return _SEVERITY_MAP.get(str(value or "UNKNOWN").strip().upper(), "未知")


def sanitize_public_text(value: Any) -> str:
    text = str(value or "")
    return _PROVIDER_PATTERN.sub("内部安全知识", text)


def public_answer_payload(answer: dict[str, Any]) -> dict[str, Any]:
    """Return the customer-facing assistant payload without intelligence provenance."""

    payload = _sanitize(deepcopy(answer))
    payload.pop("sources", None)

    mode = str(payload.get("mode") or "")
    if mode in {"vulnerability_lookup", "vulnerability_year_lookup"}:
        # Structured cards contain every customer-facing vulnerability fact. Raw
        # records stay server-side because they can disclose collection topology.
        payload.pop("records", None)
        fields = payload.get("fields")
        if isinstance(fields, dict):
            payload["fields"] = {
                key: value
                for key, value in fields.items()
                if key not in _INTERNAL_FIELD_KEYS
            }

    card = payload.get("vulnerability_card")
    if isinstance(card, dict):
        card["严重等级"] = severity_cn(card.get("严重等级"))

    return payload


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text in _PRIVATE_KEYS or key_text.lower() in _PRIVATE_KEYS_LOWER:
                continue
            cleaned[key_text] = _sanitize(item)
        return cleaned
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, str):
        return sanitize_public_text(value)
    return value
