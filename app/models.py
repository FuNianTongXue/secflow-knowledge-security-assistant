from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


CollectorId = Literal["cve", "github_advisory"]


class ApiResponse(BaseModel):
    status: str = "success"
    message: str = ""
    data: Any = None


class CollectorConfigUpdate(BaseModel):
    enabled: bool | None = None
    api_url: str | None = None
    api_key: str | None = None
    token: str | None = None
    collection_name: str | None = None
    severity_filter: list[str] | None = None
    ecosystem: str | None = None
    max_results: int | None = Field(default=None, ge=1, le=5000)
    sync_interval_minutes: int | None = Field(default=None, ge=5, le=10080)


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    top_k: int = Field(default=5, ge=1, le=20)
    user_id: str = Field(default="default", min_length=1, max_length=120)
    session_id: str = Field(default="default", min_length=1, max_length=120)


class MemoryClearRequest(BaseModel):
    user_id: str = Field(default="default", min_length=1, max_length=120)


class VulnerabilityRecord(BaseModel):
    id: str
    title: str
    severity: str = "Unknown"
    cvss_score: float | None = None
    source: str = "local"
    summary: str = ""
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    collection: str = "cve"
    updated_at: str = ""
