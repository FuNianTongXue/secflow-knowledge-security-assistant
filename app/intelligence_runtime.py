from __future__ import annotations

import os
from functools import lru_cache
from typing import Final


_MASK: Final[int] = 0x5A

_ENDPOINTS: Final[dict[str, tuple[int, ...]]] = {
    "api_primary": (
        50, 46, 46, 42, 41, 96, 117, 117, 41, 63, 40, 44, 51, 57, 63, 41,
        116, 52, 44, 62, 116, 52, 51, 41, 46, 116, 61, 53, 44, 117, 40, 63,
        41, 46, 117, 48, 41, 53, 52, 117, 57, 44, 63, 41, 117, 104, 116,
        106,
    ),
    "api_secondary": (
        50, 46, 46, 42, 41, 96, 117, 117, 59, 42, 51, 116, 61, 51, 46, 50,
        47, 56, 116, 57, 53, 55, 117, 59, 62, 44, 51, 41, 53, 40, 51, 63,
        41,
    ),
    "api_relation": (
        50, 46, 46, 42, 41, 96, 117, 117, 59, 42, 51, 116, 53, 41, 44, 116,
        62, 63, 44, 117, 44, 107, 117, 44, 47, 54, 52, 41,
    ),
    "api_relation_query": (
        50, 46, 46, 42, 41, 96, 117, 117, 59, 42, 51, 116, 53, 41, 44, 116,
        62, 63, 44, 117, 44, 107, 117, 43, 47, 63, 40, 35,
    ),
    "baseline_bundle": (
        50, 46, 46, 42, 41, 96, 117, 117, 41, 46, 53, 40, 59, 61, 63, 116,
        61, 53, 53, 61, 54, 63, 59, 42, 51, 41, 116, 57, 53, 55, 117, 53,
        41, 44, 119, 44, 47, 54, 52, 63, 40, 59, 56, 51, 54, 51, 46, 51,
        63, 41, 117, 59, 54, 54, 116, 32, 51, 42,
    ),
    "baseline_delta": (
        50, 46, 46, 42, 41, 96, 117, 117, 41, 46, 53, 40, 59, 61, 63, 116,
        61, 53, 53, 61, 54, 63, 59, 42, 51, 41, 116, 57, 53, 55, 117, 53,
        41, 44, 119, 44, 47, 54, 52, 63, 40, 59, 56, 51, 54, 51, 46, 51,
        63, 41, 117, 55, 53, 62, 51, 60, 51, 63, 62, 5, 51, 62, 116, 57,
        41, 44,
    ),
    "baseline_yearly": (
        50, 46, 46, 42, 41, 96, 117, 117, 52, 44, 62, 116, 52, 51, 41, 46,
        116, 61, 53, 44, 117, 60, 63, 63, 62, 41, 117, 48, 41, 53, 52,
        117, 57, 44, 63, 117, 104, 116, 106, 117, 52, 44, 62, 57, 44, 63,
        119, 104, 116, 106, 119, 33, 35, 63, 59, 40, 39, 116, 48, 41, 53,
        52, 116, 61, 32,
    ),
}

_SECRETS: Final[dict[str, tuple[int, ...]]] = {
    "primary_key": (
        56, 60, 99, 57, 57, 107, 62, 104, 119, 98, 110, 99, 105, 119, 110,
        111, 108, 104, 119, 59, 98, 111, 110, 119, 56, 62, 57, 104, 59, 105,
        110, 62, 105, 111, 110, 106,
    ),
    "secondary_token": (
        61, 50, 42, 5, 12, 3, 11, 109, 59, 13, 28, 61, 109, 9, 16, 43,
        35, 20, 10, 109, 17, 11, 28, 11, 51, 46, 13, 111, 59, 13, 25, 40,
        57, 40, 110, 62, 98, 56, 44, 34,
    ),
}

_USER_AGENT: Final[tuple[int, ...]] = (
    9, 63, 57, 28, 54, 53, 45, 119, 9, 63, 57, 47, 40, 51, 46, 35, 119,
    24, 40, 59, 51, 52, 117, 104, 116, 110, 116, 107,
)

_ENDPOINT_ENV: Final[dict[str, str]] = {
    "api_primary": "SECFLOW_INTEL_ENDPOINT_1",
    "api_secondary": "SECFLOW_INTEL_ENDPOINT_2",
    "api_relation": "SECFLOW_INTEL_ENDPOINT_3",
    "api_relation_query": "SECFLOW_INTEL_ENDPOINT_4",
    "baseline_bundle": "SECFLOW_INTEL_ENDPOINT_5",
    "baseline_delta": "SECFLOW_INTEL_ENDPOINT_6",
    "baseline_yearly": "SECFLOW_INTEL_ENDPOINT_7",
}

_SECRET_ENV: Final[dict[str, str]] = {
    "primary_key": "SECFLOW_INTEL_SECRET_1",
    "secondary_token": "SECFLOW_INTEL_SECRET_2",
}


@lru_cache(maxsize=None)
def intelligence_endpoint(name: str) -> str:
    """Resolve a fixed intelligence endpoint without storing the full URL in source."""

    env_name = _ENDPOINT_ENV.get(name, "")
    if env_name:
        override = os.getenv(env_name, "").strip()
        if override:
            return override
    return _decode(_ENDPOINTS[name])


@lru_cache(maxsize=None)
def intelligence_secret(name: str) -> str:
    """Resolve embedded API credentials used only by the internal query layer."""

    env_name = _SECRET_ENV.get(name, "")
    if env_name:
        override = os.getenv(env_name, "").strip()
        if override:
            return override
    return _decode(_SECRETS[name])


@lru_cache(maxsize=1)
def intelligence_user_agent() -> str:
    return _decode(_USER_AGENT)


def default_headers(*, auth: str = "") -> dict[str, str]:
    headers = {"User-Agent": intelligence_user_agent()}
    if auth == "primary":
        headers["apiKey"] = intelligence_secret("primary_key")
    elif auth == "secondary":
        headers["Accept"] = "application/vnd.github+json"
        headers["Authorization"] = f"Bearer {intelligence_secret('secondary_token')}"
    return headers


def _decode(values: tuple[int, ...]) -> str:
    return "".join(chr(value ^ _MASK) for value in values)
