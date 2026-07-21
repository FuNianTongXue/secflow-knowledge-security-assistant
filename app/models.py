from __future__ import annotations

from datetime import date
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from app.dependencies import MAX_ASK_ATTACHMENTS, is_allowed_attachment_name


CollectorId = Literal["cve", "github_advisory"]
SupportedLanguage = Literal["zh-Hans", "zh-Hant", "en", "ko", "ja", "es", "fr", "de", "it", "ru"]


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
    response_language: str = Field(default="zh-Hans", max_length=24)
    attachments: list["AskAttachment"] = Field(default_factory=list, max_length=MAX_ASK_ATTACHMENTS)


class AskAttachment(BaseModel):
    file_name: str = Field(min_length=1, max_length=1024)
    content: str = Field(min_length=1, max_length=120000)
    mime_type: str | None = Field(default=None, max_length=120)

    @field_validator("file_name")
    @classmethod
    def validate_file_name(cls, value: str) -> str:
        clean_value = value.strip()
        if not is_allowed_attachment_name(clean_value):
            raise ValueError("仅支持上传受支持的项目依赖清单或代码文件")
        return clean_value


class IntelligenceQueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=1000)
    limit: int = Field(default=10, ge=1, le=50)
    response_language: str | None = Field(default=None, max_length=24)
    sources: list[Literal["nvd", "github_advisory", "osv"]] | None = None


class DashboardRefreshRequest(BaseModel):
    start_date: date | None = None
    end_date: date | None = None


class InformationSourceUpdate(BaseModel):
    enabled: bool


class UserProfileSettingsUpdate(BaseModel):
    display_name: str = Field(min_length=1, max_length=80)
    email: str = Field(min_length=1, max_length=160)
    phone: str = Field(default="", max_length=80)
    department: str = Field(default="", max_length=120)
    role: str = Field(default="", max_length=120)
    employee_id: str = Field(default="", max_length=80)
    bio: str = Field(default="", max_length=200)


class AvatarUploadRequest(BaseModel):
    file_name: str = Field(min_length=1, max_length=255)
    content_base64: str = Field(min_length=1, max_length=3_000_000)
    content_type: str | None = Field(default=None, max_length=80)


class AppPreferenceSettingsUpdate(BaseModel):
    language: SupportedLanguage = "zh-Hans"
    dark_mode: bool = False
    font_size: Literal["small", "default", "large"] = "default"
    launch_at_login: bool = False
    auto_check_updates: bool = True


class LegalDocumentSectionUpdate(BaseModel):
    heading: str = Field(min_length=1, max_length=120)
    paragraphs: list[str] = Field(min_length=1, max_length=40)

    @field_validator("paragraphs")
    @classmethod
    def validate_paragraphs(cls, values: list[str]) -> list[str]:
        cleaned = [str(value).strip() for value in values if str(value).strip()]
        if not cleaned:
            raise ValueError("协议章节内容不能为空")
        if any(len(value) > 2000 for value in cleaned):
            raise ValueError("协议单段内容过长")
        return cleaned


class LegalDocumentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=80)
    heading: str | None = Field(default=None, min_length=1, max_length=120)
    updated_at: str | None = Field(default=None, min_length=1, max_length=40)
    effective_at: str | None = Field(default=None, min_length=1, max_length=40)
    intro: str | None = Field(default=None, min_length=1, max_length=3000)
    sections: list[LegalDocumentSectionUpdate] | None = Field(default=None, min_length=1, max_length=30)


class ReportDeleteRequest(BaseModel):
    report_ids: list[str] = Field(min_length=1, max_length=100)

    @field_validator("report_ids")
    @classmethod
    def validate_report_ids(cls, values: list[str]) -> list[str]:
        cleaned = list(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))
        if not cleaned:
            raise ValueError("至少选择一份报告")
        if any(len(value) > 160 for value in cleaned):
            raise ValueError("报告编号长度无效")
        return cleaned


class LLMConfigRequest(BaseModel):
    provider: Literal["openai", "claude", "deepseek", "custom"]
    model: str = Field(min_length=1, max_length=120)
    endpoint: str | None = Field(default=None, max_length=300)
    api_key: str | None = Field(default=None, max_length=300)
    enabled: bool = True
    max_tokens: int = Field(default=1800, ge=128, le=8192)
    temperature: float = Field(default=0.25, ge=0, le=2)
    top_p: float = Field(default=0.9, ge=0, le=1)
    timeout_ms: int = Field(default=60000, ge=1000, le=180000)
    reasoning_effort: str | None = Field(default=None, max_length=40)
    disable_response_storage: bool | None = None


class LLMModelsRequest(BaseModel):
    provider: Literal["openai", "claude", "deepseek", "custom"]
    endpoint: str | None = Field(default=None, max_length=300)
    api_key: str | None = Field(default=None, max_length=300)
    timeout_ms: int = Field(default=30000, ge=1000, le=180000)


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
