from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.collectors import collector_service
from app.graph import knowledge_graph, runtime_status
from app.memory import memory_service
from app.models import ApiResponse, AskRequest, CollectorConfigUpdate, MemoryClearRequest


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="SecFlow Knowledge Security Assistant",
    version="1.0.0",
    description="A source-available LangGraph knowledge security assistant by ShenSiQi.",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


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
    return {"ok": True, "service": "secflow-knowledge-security-assistant", "author": "ShenSiQi"}


@app.get("/api/config", response_model=ApiResponse)
def config():
    snapshot = collector_service.snapshot()
    snapshot["runtime"] = runtime_status()
    return ok(snapshot, "Configuration loaded.")


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


@app.post("/api/ask", response_model=ApiResponse)
def ask(payload: AskRequest):
    return ok(
        knowledge_graph.invoke(
            payload.question,
            payload.top_k,
            user_id=payload.user_id,
            session_id=payload.session_id,
        ),
        "Assistant response generated.",
    )


@app.get("/api/graph", response_model=ApiResponse)
def graph():
    return ok(knowledge_graph.graph_spec(), "LangGraph specification loaded.")


@app.get("/api/runtime", response_model=ApiResponse)
def runtime():
    return ok(runtime_status(), "Runtime status loaded.")


@app.delete("/api/memory", response_model=ApiResponse)
def clear_memory(payload: MemoryClearRequest):
    return ok(memory_service.clear_history(payload.user_id), "Memory cleared.")
