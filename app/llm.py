from __future__ import annotations

import os
import time
from typing import Any

import httpx


LOCAL_PROVIDERS = {"ollama", "vllm", "local"}


def active_model_from_env() -> dict[str, Any] | None:
    provider = os.getenv("SECFLOW_LLM_PROVIDER", "").strip().lower()
    if not provider:
        provider = "deepseek" if os.getenv("DEEPSEEK_API_KEY") else "openai"

    api_key = (
        os.getenv("SECFLOW_LLM_API_KEY")
        or os.getenv("DEEPSEEK_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or ""
    ).strip()
    endpoint = (
        os.getenv("SECFLOW_LLM_ENDPOINT")
        or os.getenv("DEEPSEEK_BASE_URL")
        or os.getenv("OPENAI_BASE_URL")
        or _default_endpoint(provider)
    ).strip()
    model = (
        os.getenv("SECFLOW_LLM_MODEL")
        or os.getenv("DEEPSEEK_MODEL")
        or os.getenv("OPENAI_MODEL")
        or _default_model(provider)
    ).strip()

    return {
        "name": os.getenv("SECFLOW_LLM_NAME") or f"{provider}:{model}",
        "provider": provider,
        "model": model,
        "endpoint": endpoint,
        "apiKey": api_key,
        "maxTokens": int(os.getenv("SECFLOW_LLM_MAX_TOKENS", "1800")),
        "temperature": float(os.getenv("SECFLOW_LLM_TEMPERATURE", "0.25")),
        "topP": float(os.getenv("SECFLOW_LLM_TOP_P", "0.9")),
        "timeoutMs": int(os.getenv("SECFLOW_LLM_TIMEOUT_MS", "60000")),
    }


def llm_status() -> dict[str, Any]:
    model = active_model_from_env()
    error = chat_readiness_error(model)
    return {
        "configured": not bool(error),
        "name": model.get("name") if model else "",
        "provider": model.get("provider") if model else "",
        "model": model.get("model") if model else "",
        "endpoint": _safe_endpoint(model.get("endpoint", "")) if model else "",
        "message": error or "模型配置可用于 OpenAI Chat Completions 调用。",
    }


def chat_readiness_error(active_model: dict[str, Any] | None) -> str:
    if not active_model:
        return "未配置可用模型。"
    provider = str(active_model.get("provider", "")).lower()
    endpoint = _normalized_endpoint(active_model)
    if provider not in LOCAL_PROVIDERS and not str(active_model.get("apiKey", "")):
        return (
            f"{active_model.get('name', '当前模型')} 未配置 API Key。"
            "请通过 SECFLOW_LLM_API_KEY、DEEPSEEK_API_KEY 或 OPENAI_API_KEY 配置。"
        )
    if not endpoint.startswith(("http://", "https://")):
        return f"{active_model.get('name', '当前模型')} 的接口地址需要包含 http:// 或 https://。"
    return ""


def diagnose_chat_completion(
    active_model: dict[str, Any],
    messages: list[dict[str, str]],
    enable_thinking: bool = False,
) -> dict[str, Any]:
    readiness_error = chat_readiness_error(active_model)
    if readiness_error:
        return {"status": "failed", "message": readiness_error, "latency_ms": None}

    endpoint = _normalized_endpoint(active_model)
    body: dict[str, Any] = {
        "model": active_model.get("model", "deepseek-chat"),
        "messages": messages,
        "max_tokens": int(active_model.get("maxTokens", 1800)),
        "temperature": float(active_model.get("temperature", 0.25)),
        "top_p": float(active_model.get("topP", 0.9)),
    }
    if enable_thinking and _supports_thinking_param(active_model):
        body["thinking"] = {"type": "enabled"}

    headers = {"Content-Type": "application/json"}
    api_key = str(active_model.get("apiKey", ""))
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    timeout_s = max(float(active_model.get("timeoutMs", 60000)) / 1000.0, 1.0)
    started = time.perf_counter()
    try:
        with httpx.Client(timeout=timeout_s) as client:
            response = client.post(f"{endpoint}/chat/completions", json=body, headers=headers)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as exc:
        latency_ms = int((time.perf_counter() - started) * 1000)
        detail = exc.response.text[:500] if exc.response is not None else str(exc)
        return {
            "status": "failed",
            "message": f"模型接口返回 HTTP {exc.response.status_code if exc.response else ''}：{detail}",
            "latency_ms": latency_ms,
        }
    except Exception as exc:  # noqa: BLE001
        latency_ms = int((time.perf_counter() - started) * 1000)
        return {"status": "failed", "message": f"模型接口请求失败：{exc}", "latency_ms": latency_ms}

    latency_ms = int((time.perf_counter() - started) * 1000)
    try:
        choice = data["choices"][0]["message"]
    except Exception:  # noqa: BLE001
        return {"status": "failed", "message": "模型接口返回格式不符合 OpenAI Chat Completions。", "latency_ms": latency_ms}

    answer_text = str(choice.get("content", "") or "").strip()
    reasoning_text = str(choice.get("reasoning_content", "") or "").strip()
    if not answer_text and reasoning_text:
        answer_text = reasoning_text
    if not answer_text:
        return {"status": "failed", "message": "当前模型未返回可用结果。", "latency_ms": latency_ms}

    return {
        "status": "success",
        "message": "模型接口调用成功。",
        "latency_ms": latency_ms,
        "answer": answer_text,
        "reasoning": reasoning_text,
        "data": data,
    }


def _default_endpoint(provider: str) -> str:
    if provider == "deepseek":
        return "https://api.deepseek.com/v1"
    if provider == "openai":
        return "https://api.openai.com/v1"
    return "http://127.0.0.1:11434/v1"


def _default_model(provider: str) -> str:
    if provider == "deepseek":
        return "deepseek-chat"
    if provider == "openai":
        return "gpt-4o-mini"
    return "qwen2.5-coder-security"


def _normalized_endpoint(active_model: dict[str, Any]) -> str:
    return str(active_model.get("endpoint", "") or _default_endpoint(str(active_model.get("provider", "")))).rstrip("/")


def _supports_thinking_param(active_model: dict[str, Any]) -> bool:
    provider = str(active_model.get("provider", "")).lower()
    model = str(active_model.get("model", "")).lower()
    if provider == "deepseek":
        return "reasoner" in model
    return provider in {"ollama", "vllm"} and any(token in model for token in ("reason", "thinking", "qwq"))


def _safe_endpoint(endpoint: str) -> str:
    if not endpoint:
        return ""
    return endpoint.replace("api_key=", "api_key=***")
