from __future__ import annotations

import os
from datetime import date
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from app.collectors import collector_graph, collector_service
from app.graph import knowledge_graph, runtime_status
from app.information import information_service, load_information_image
from app.llm import list_llm_models, llm_public_config, save_llm_config, test_llm_config
from app.intelligence import intelligence_service
from app.memory import memory_service
from app.models import ApiResponse, AppPreferenceSettingsUpdate, AskRequest, AvatarUploadRequest, CollectorConfigUpdate, DashboardRefreshRequest, InformationSourceUpdate, IntelligenceQueryRequest, LegalDocumentUpdate, LLMConfigRequest, LLMModelsRequest, MemoryClearRequest, ReportDeleteRequest, UserProfileSettingsUpdate
from app.privacy import public_answer_payload
from app.reports import report_store
from app.settings import (
    APP_VERSION,
    avatar_response,
    delete_profile_avatar,
    get_legal_document,
    get_legal_documents,
    get_preference_settings,
    get_profile_settings,
    public_settings_snapshot,
    save_profile_avatar,
    update_legal_document,
    update_preference_settings,
    update_profile_settings,
)
from app.trial import trial_manager


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
MACOS_API_CONTRACT_VERSION = "2026-07-dashboard-published-at-v1"

app = FastAPI(
    title="SecFlow Knowledge Security Assistant",
    version=APP_VERSION,
    description="A source-available LangGraph knowledge security assistant by ShenSiQi.",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def enforce_trial_period(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.url.path != "/api/trial/status":
        trial = trial_manager.status()
        if not trial["usable"]:
            return JSONResponse(
                status_code=403,
                content={
                    "status": "error",
                    "message": trial["message"],
                    "data": {"trial": trial},
                },
                headers={"Cache-Control": "no-store"},
            )
    return await call_next(request)


@app.on_event("startup")
def startup_batch_jobs() -> None:
    report_store.sanitize_existing_reports()
    if os.getenv("SECFLOW_DISABLE_BATCH_SCHEDULER", "").strip().lower() in {"1", "true", "yes", "on"}:
        return
    intelligence_service.start_batch_scheduler()


@app.on_event("shutdown")
def shutdown_batch_jobs() -> None:
    intelligence_service.stop_batch_scheduler()


def ok(data=None, message: str = "ok") -> ApiResponse:
    return ApiResponse(status="success", message=message, data=data)


@app.get("/")
def root():
    return RedirectResponse(url="/ui")


@app.get("/ui")
def ui():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health():
    return {
        "ok": True,
        "service": "secflow-knowledge-security-assistant",
        "contract_version": MACOS_API_CONTRACT_VERSION,
        "author": "ShenSiQi",
    }


@app.get("/api/trial/status", response_model=ApiResponse)
def trial_status():
    return ok(trial_manager.status(), "Trial status loaded.")


@app.get("/api/config", response_model=ApiResponse)
def config():
    snapshot = collector_service.snapshot()
    snapshot["runtime"] = runtime_status()
    snapshot["dashboard"] = intelligence_service.dashboard()
    return ok(snapshot, "Configuration loaded.")


@app.get("/api/settings", response_model=ApiResponse)
def settings_snapshot():
    return ok(public_settings_snapshot(), "Settings loaded.")


@app.get("/api/settings/profile", response_model=ApiResponse)
def settings_profile():
    return ok(get_profile_settings(), "Profile settings loaded.")


@app.patch("/api/settings/profile", response_model=ApiResponse)
def update_settings_profile(payload: UserProfileSettingsUpdate):
    return ok(update_profile_settings(payload.model_dump()), "Profile settings saved.")


@app.post("/api/settings/profile/avatar", response_model=ApiResponse)
def upload_settings_profile_avatar(payload: AvatarUploadRequest):
    try:
        return ok(
            save_profile_avatar(
                payload.file_name,
                payload.content_base64,
                payload.content_type or "",
            ),
            "Profile avatar uploaded.",
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.delete("/api/settings/profile/avatar", response_model=ApiResponse)
def remove_settings_profile_avatar():
    return ok(delete_profile_avatar(), "Profile avatar removed.")


@app.get("/api/settings/profile/avatar")
def settings_profile_avatar():
    try:
        return avatar_response()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Profile avatar not found.") from exc


@app.get("/api/settings/preferences", response_model=ApiResponse)
def settings_preferences():
    return ok(get_preference_settings(), "Preference settings loaded.")


@app.patch("/api/settings/preferences", response_model=ApiResponse)
def update_settings_preferences(payload: AppPreferenceSettingsUpdate):
    return ok(update_preference_settings(payload.model_dump()), "Preference settings saved.")


@app.get("/api/settings/legal", response_model=ApiResponse)
def settings_legal_documents():
    return ok(get_legal_documents(), "Legal documents loaded.")


@app.get("/api/settings/legal/{document_id}", response_model=ApiResponse)
def settings_legal_document(document_id: str):
    try:
        return ok(get_legal_document(document_id), "Legal document loaded.")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown legal document: {document_id}") from exc


@app.patch("/api/settings/legal/{document_id}", response_model=ApiResponse)
def update_settings_legal_document(document_id: str, payload: LegalDocumentUpdate):
    try:
        return ok(
            update_legal_document(document_id, payload.model_dump(exclude_unset=True)),
            "Legal document saved.",
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown legal document: {document_id}") from exc


@app.patch("/api/config/{collector_id}", response_model=ApiResponse)
def update_config(collector_id: str, payload: CollectorConfigUpdate):
    try:
        return ok(collector_service.update_config(collector_id, payload), "Collector configuration saved.")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown collector: {collector_id}") from exc


@app.post("/api/config/{collector_id}/test", response_model=ApiResponse)
def test_config(collector_id: str):
    try:
        result = collector_service.test_config(collector_id)
        return ok(result, result.get("message", "Collector test finished."))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown collector: {collector_id}") from exc


@app.post("/api/collect/{collector_id}", response_model=ApiResponse)
def collect(collector_id: str):
    try:
        result = collector_service.collect(collector_id)
        return ok(result, result.get("message", "Collection finished."))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown collector: {collector_id}") from exc


@app.get("/api/vulnerabilities", response_model=ApiResponse)
def vulnerabilities():
    snapshot = collector_service.snapshot()
    return ok({"records": snapshot["records"], "stats": snapshot["stats"]}, "Vulnerability records loaded.")


@app.get("/api/dashboard", response_model=ApiResponse)
def dashboard(start_date: date | None = None, end_date: date | None = None):
    try:
        return ok(intelligence_service.dashboard(start_date=start_date, end_date=end_date), "Dashboard batch snapshot loaded.")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/dashboard/refresh", response_model=ApiResponse)
def refresh_dashboard(payload: DashboardRefreshRequest | None = None):
    payload = payload or DashboardRefreshRequest()
    try:
        result = intelligence_service.refresh_dashboard_batch(
            start_date=payload.start_date,
            end_date=payload.end_date,
        )
        return ok(result, "Dashboard batch snapshot refreshed.")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/intelligence/sources", response_model=ApiResponse)
def intelligence_sources():
    return ok(intelligence_service.sources_status(), "Intelligence query sources loaded.")


@app.get("/api/intelligence/recent", response_model=ApiResponse)
def recent_intelligence():
    return ok(intelligence_service.recent(), "Recent intelligence queries loaded.")


@app.get("/api/information", response_model=ApiResponse)
def information(
    query: str = "",
    category: str = "全部",
    sort: str = "latest",
    limit: int = 80,
    refresh: bool = False,
):
    return ok(
        information_service.snapshot(
            query=query,
            category=category,
            sort=sort,
            limit=max(1, min(limit, 200)),
            refresh=refresh,
        ),
        "Public security information loaded.",
    )


@app.post("/api/information/refresh", response_model=ApiResponse)
def refresh_information():
    return ok(information_service.refresh(), "Public security information refreshed.")


@app.get("/api/information/images/{item_id}")
def information_image(item_id: str):
    try:
        result = load_information_image(item_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Information item not found.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return Response(
        content=result.data,
        media_type=result.content_type,
        headers={
            "Cache-Control": "public, max-age=86400, stale-if-error=604800",
            "ETag": f'"{result.etag}"',
            "X-SecFlow-Image-Kind": result.kind,
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.patch("/api/information/sources/{source_id}", response_model=ApiResponse)
def update_information_source(source_id: str, payload: InformationSourceUpdate):
    try:
        return ok(
            information_service.set_source_enabled(source_id, payload.enabled),
            "Information source subscription updated.",
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown information source: {source_id}") from exc


@app.post("/api/intelligence/query", response_model=ApiResponse)
def query_intelligence(payload: IntelligenceQueryRequest):
    try:
        result = intelligence_service.query(
            payload.query,
            limit=payload.limit,
            sources=payload.sources,
            response_language=payload.response_language or "zh-Hans",
        )
        return ok(result, "API intelligence query and graph enrichment completed.")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/knowledge-graph/query", response_model=ApiResponse)
def query_knowledge_graph(payload: IntelligenceQueryRequest):
    try:
        result = intelligence_service.query(
            payload.query,
            limit=payload.limit,
            sources=payload.sources,
            response_language=payload.response_language or "zh-Hans",
        )
        return ok(result["graph"], "Knowledge graph enriched from upstream API intelligence.")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/ask", response_model=ApiResponse)
def ask(payload: AskRequest):
    return ok(
        public_answer_payload(
            knowledge_graph.invoke(
                payload.question,
                payload.top_k,
                user_id=payload.user_id,
                session_id=payload.session_id,
                response_language=payload.response_language,
                attachments=[attachment.model_dump() for attachment in payload.attachments],
            )
        ),
        "Assistant response generated.",
    )


@app.get("/api/graph", response_model=ApiResponse)
def graph():
    return ok(knowledge_graph.graph_spec(), "LangGraph specification loaded.")


@app.get("/api/collector-graph", response_model=ApiResponse)
def collector_graph_spec():
    return ok(collector_graph.graph_spec(), "Collector subgraph specification loaded.")


@app.get("/api/runtime", response_model=ApiResponse)
def runtime():
    return ok(runtime_status(), "Runtime status loaded.")


@app.get("/api/reports", response_model=ApiResponse)
def reports():
    return ok(report_store.list_reports(), "Analysis reports loaded.")


@app.delete("/api/reports", response_model=ApiResponse)
def delete_reports(payload: ReportDeleteRequest):
    result = report_store.delete_reports(payload.report_ids)
    return ok(result, f"Deleted {result['deleted']} analysis reports.")


@app.get("/api/reports/{report_id}/download")
def download_report(report_id: str, format: str = "md"):
    try:
        path, file_name, media_type = report_store.resolve_download(report_id, format)
        return FileResponse(
            path,
            media_type=media_type,
            filename=file_name,
            headers={"Cache-Control": "no-store"},
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown report: {report_id}") from exc


@app.get("/api/reports/{report_id}", response_model=ApiResponse)
def report_detail(report_id: str):
    try:
        return ok(report_store.get_report(report_id), "Analysis report loaded.")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown report: {report_id}") from exc


@app.get("/api/llm/config", response_model=ApiResponse)
def llm_config():
    return ok(llm_public_config(), "LLM configuration loaded.")


@app.patch("/api/llm/config", response_model=ApiResponse)
def update_llm_config(payload: LLMConfigRequest):
    try:
        return ok(save_llm_config(payload.model_dump(exclude_unset=True)), "LLM configuration saved.")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/llm/test", response_model=ApiResponse)
def test_llm(payload: LLMConfigRequest):
    try:
        result = test_llm_config(payload.model_dump(exclude_unset=True))
        return ok(result, result.get("message", "LLM connection test finished."))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/llm/models", response_model=ApiResponse)
def llm_models(payload: LLMModelsRequest):
    try:
        result = list_llm_models(payload.model_dump(exclude_unset=True))
        return ok(result, result.get("message", "LLM models loaded."))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.delete("/api/memory", response_model=ApiResponse)
def clear_memory(payload: MemoryClearRequest):
    return ok(memory_service.clear_history(payload.user_id), "Memory cleared.")
