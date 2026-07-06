from __future__ import annotations

import re
from typing import Any, TypedDict

try:
    from langgraph.graph import END, StateGraph
except Exception:  # noqa: BLE001
    END = "__end__"
    StateGraph = None

from app.collectors import collector_service
from app.llm import active_model_from_env, diagnose_chat_completion, llm_status
from app.memory import memory_service
from app.storage import now_iso


SYSTEM_PROMPT = """你是 SecFlow Knowledge Security Assistant，定位是安全知识助手。
请用中文回答，语气专业、简洁、可落地。
如果问题包含 CVE 或 GHSA 编号，优先结合漏洞知识库记录回答，并说明影响、利用条件、修复建议和参考来源。
如果问题不是具体漏洞查询，不要编造漏洞库记录；应结合长期记忆、上下文和通用安全工程经验回答。
当模型上下文中提供了长期记忆时，只把它作为偏好和历史背景，不要泄露内部存储结构。
"""


class AssistantState(TypedDict, total=False):
    question: str
    top_k: int
    user_id: str
    session_id: str
    intent: str
    vulnerability_id: str
    records: list[dict[str, Any]]
    memory_context: dict[str, Any]
    llm_result: dict[str, Any]
    llm_error: str
    answer: dict[str, Any]
    trace: list[dict[str, Any]]


class KnowledgeSecurityGraph:
    def __init__(self) -> None:
        self._graph = self._build_graph()

    def invoke(self, question: str, top_k: int = 5, user_id: str = "default", session_id: str = "default") -> dict[str, Any]:
        state: AssistantState = {
            "question": question,
            "top_k": top_k,
            "user_id": user_id or "default",
            "session_id": session_id or "default",
            "intent": "security_knowledge",
            "vulnerability_id": "",
            "records": [],
            "memory_context": {},
            "llm_result": {},
            "llm_error": "",
            "trace": [],
        }
        if self._graph is None:
            state = self._classify_query(state)
            state = self._load_memory_context(state)
            if self._should_retrieve(state):
                state = self._retrieve_local_knowledge(state)
            if self._should_fetch_live(state):
                state = self._fetch_live_vulnerability(state)
            state = self._call_llm(state)
            state = self._compose_answer(state)
            state = self._persist_memory(state)
            return state["answer"]
        final = self._graph.invoke(state)
        return final["answer"]

    @staticmethod
    def graph_spec() -> dict[str, Any]:
        return {
            "name": "Knowledge Security Assistant LangGraph",
            "nodes": [
                {"id": "classify_query", "label": "识别问题意图"},
                {"id": "load_memory_context", "label": "加载长期记忆"},
                {"id": "retrieve_local_knowledge", "label": "漏洞知识库检索"},
                {"id": "fetch_live_vulnerability", "label": "实时补充漏洞记录"},
                {"id": "call_llm", "label": "调用安全专家模型"},
                {"id": "compose_answer", "label": "生成回答"},
                {"id": "persist_memory", "label": "保存长期记忆"},
            ],
            "edges": [
                {"source": "classify_query", "target": "load_memory_context", "label": "问题分类"},
                {"source": "load_memory_context", "target": "retrieve_local_knowledge", "label": "CVE/GHSA"},
                {"source": "load_memory_context", "target": "call_llm", "label": "通用安全问题"},
                {"source": "retrieve_local_knowledge", "target": "fetch_live_vulnerability", "label": "未命中精确记录"},
                {"source": "retrieve_local_knowledge", "target": "call_llm", "label": "检索完成"},
                {"source": "fetch_live_vulnerability", "target": "call_llm", "label": "采集完成"},
                {"source": "call_llm", "target": "compose_answer", "label": "模型结果"},
                {"source": "compose_answer", "target": "persist_memory", "label": "落库"},
            ],
        }

    def _build_graph(self):
        if StateGraph is None:
            return None
        graph = StateGraph(AssistantState)
        graph.add_node("classify_query", self._classify_query)
        graph.add_node("load_memory_context", self._load_memory_context)
        graph.add_node("retrieve_local_knowledge", self._retrieve_local_knowledge)
        graph.add_node("fetch_live_vulnerability", self._fetch_live_vulnerability)
        graph.add_node("call_llm", self._call_llm)
        graph.add_node("compose_answer", self._compose_answer)
        graph.add_node("persist_memory", self._persist_memory)
        graph.set_entry_point("classify_query")
        graph.add_edge("classify_query", "load_memory_context")
        graph.add_conditional_edges(
            "load_memory_context",
            lambda state: "retrieve_local_knowledge" if self._should_retrieve(state) else "call_llm",
            {
                "retrieve_local_knowledge": "retrieve_local_knowledge",
                "call_llm": "call_llm",
            },
        )
        graph.add_conditional_edges(
            "retrieve_local_knowledge",
            lambda state: "fetch_live_vulnerability" if self._should_fetch_live(state) else "call_llm",
            {
                "fetch_live_vulnerability": "fetch_live_vulnerability",
                "call_llm": "call_llm",
            },
        )
        graph.add_edge("fetch_live_vulnerability", "call_llm")
        graph.add_edge("call_llm", "compose_answer")
        graph.add_edge("compose_answer", "persist_memory")
        graph.add_edge("persist_memory", END)
        return graph.compile()

    def _classify_query(self, state: AssistantState) -> AssistantState:
        question = state["question"]
        vuln_id = extract_vulnerability_id(question)
        lowered = question.lower()
        if vuln_id:
            state["intent"] = "vulnerability_lookup"
            state["vulnerability_id"] = vuln_id
        elif any(word in lowered for word in ["supply chain", "dependency", "poisoning", "sbom", "sca", "供应链", "依赖"]):
            state["intent"] = "supply_chain"
        elif any(word in lowered for word in ["compliance", "policy", "control", "audit", "合规", "等保", "审计"]):
            state["intent"] = "compliance"
        else:
            state["intent"] = "security_knowledge"
        return add_trace(state, "classify_query", f"已识别为 {state['intent']}。")

    def _load_memory_context(self, state: AssistantState) -> AssistantState:
        try:
            context = memory_service.build_context(state.get("user_id", "default"), state["question"])
            state["memory_context"] = context
            stats = context.get("stats", {})
            return add_trace(
                state,
                "load_memory_context",
                f"已从 {context.get('backend')} 召回长期记忆：历史 {stats.get('historyCount', 0)} 条，相关 {stats.get('retrievedCount', 0)} 条。",
            )
        except Exception as exc:  # noqa: BLE001
            state["memory_context"] = {"enabled": False, "error": str(exc)}
            return add_trace(state, "load_memory_context", f"长期记忆读取失败：{exc}", status="warning")

    def _retrieve_local_knowledge(self, state: AssistantState) -> AssistantState:
        records = collector_service.search(state["question"], state.get("top_k", 5))
        state["records"] = records
        return add_trace(state, "retrieve_local_knowledge", f"已检索到 {len(records)} 条本地漏洞记录。")

    def _fetch_live_vulnerability(self, state: AssistantState) -> AssistantState:
        vuln_id = state.get("vulnerability_id", "")
        if not vuln_id:
            return add_trace(state, "fetch_live_vulnerability", "未识别到漏洞编号，跳过实时采集。")
        collector_id = "github_advisory" if vuln_id.startswith("GHSA-") else "cve"
        try:
            result = collector_service.collect(collector_id)
            live_records = [record for record in result.get("records", []) if str(record.get("id", "")).upper() == vuln_id]
            refreshed = live_records or collector_service.search(vuln_id, 3)
            if refreshed:
                state["records"] = [*refreshed, *state.get("records", [])]
            return add_trace(state, "fetch_live_vulnerability", f"已执行 {collector_id} 采集，补充 {len(refreshed)} 条候选记录。")
        except Exception as exc:  # noqa: BLE001
            return add_trace(state, "fetch_live_vulnerability", f"实时采集失败：{exc}", status="warning")

    def _call_llm(self, state: AssistantState) -> AssistantState:
        model = active_model_from_env()
        messages = self._build_messages(state)
        result = diagnose_chat_completion(model, messages) if model else {"status": "failed", "message": "未配置可用模型。"}
        state["llm_result"] = result
        if result.get("status") == "success":
            return add_trace(state, "call_llm", f"模型调用成功，耗时 {result.get('latency_ms', 0)}ms。")
        state["llm_error"] = str(result.get("message") or "模型未返回可用结果。")
        return add_trace(state, "call_llm", state["llm_error"], status="warning")

    def _compose_answer(self, state: AssistantState) -> AssistantState:
        records = state.get("records", [])
        llm_result = state.get("llm_result", {})
        fields = {
            "意图": state.get("intent", "security_knowledge"),
            "长期记忆": self._memory_label(state.get("memory_context", {})),
            "模型调用状态": "成功" if llm_result.get("status") == "success" else state.get("llm_error", "未调用"),
        }
        sources = self._record_sources(records)

        if llm_result.get("status") == "success":
            summary = str(llm_result.get("answer", "")).strip()
            confidence = 0.82 if not records else 0.9
        elif records:
            primary = records[0]
            summary = build_record_answer(primary)
            confidence = 0.72
        else:
            summary = fallback_answer(state)
            confidence = 0.46

        answer = {
            "mode": state.get("intent", "security_knowledge"),
            "summary": summary,
            "records": records,
            "sources": sources,
            "fields": fields,
            "confidence": confidence,
            "trace": state.get("trace", []),
            "generated_at": now_iso(),
        }
        state["answer"] = answer
        return add_trace(state, "compose_answer", "已生成最终回答。")

    def _persist_memory(self, state: AssistantState) -> AssistantState:
        answer = dict(state.get("answer", {}))
        try:
            memory_service.add_exchange(
                state.get("user_id", "default"),
                state["question"],
                answer,
                session_id=state.get("session_id", "default"),
            )
            answer.setdefault("fields", {})["记忆持久化"] = "已保存"
            state["answer"] = answer
            return add_trace(state, "persist_memory", "已写入长期记忆。")
        except Exception as exc:  # noqa: BLE001
            answer.setdefault("fields", {})["记忆持久化"] = f"保存失败：{exc}"
            state["answer"] = answer
            return add_trace(state, "persist_memory", f"长期记忆保存失败：{exc}", status="warning")

    @staticmethod
    def _should_retrieve(state: AssistantState) -> bool:
        return state.get("intent") == "vulnerability_lookup"

    @staticmethod
    def _should_fetch_live(state: AssistantState) -> bool:
        vuln_id = state.get("vulnerability_id", "")
        if not vuln_id:
            return False
        records = state.get("records", [])
        return not any(str(record.get("id", "")).upper() == vuln_id for record in records)

    def _build_messages(self, state: AssistantState) -> list[dict[str, str]]:
        records = state.get("records", [])
        memory_context = state.get("memory_context", {})
        context_parts: list[str] = []
        if memory_context.get("promptContext"):
            context_parts.append(str(memory_context["promptContext"]))
        if records:
            context_parts.append("漏洞知识库记录：\n" + "\n".join(format_record_context(record) for record in records[:5]))
        context_text = "\n\n".join(context_parts) or "暂无额外上下文。"
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        messages.extend(memory_context.get("injectedMessages", [])[:6])
        messages.append(
            {
                "role": "user",
                "content": f"上下文：\n{context_text}\n\n用户问题：{state['question']}",
            }
        )
        return messages

    @staticmethod
    def _memory_label(memory_context: dict[str, Any]) -> str:
        if not memory_context.get("enabled", True):
            return "未启用"
        stats = memory_context.get("stats", {})
        return f"{memory_context.get('backend', 'json')} · 历史 {stats.get('historyCount', 0)} 条 · 相关 {stats.get('retrievedCount', 0)} 条"

    @staticmethod
    def _record_sources(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        sources: list[dict[str, Any]] = []
        for record in records[:5]:
            refs = record.get("references") or []
            sources.append(
                {
                    "id": record.get("id"),
                    "title": record.get("title"),
                    "collection": record.get("collection"),
                    "source": record.get("source"),
                    "url": refs[0] if refs else "",
                }
            )
        return sources


def add_trace(state: AssistantState, node: str, message: str, status: str = "completed") -> AssistantState:
    state["trace"] = [
        *state.get("trace", []),
        {"node": node, "status": status, "message": message, "time": now_iso()},
    ]
    return state


def extract_vulnerability_id(text: str) -> str:
    cve = re.search(r"CVE-\d{4}-\d{4,8}", text, flags=re.IGNORECASE)
    if cve:
        return cve.group(0).upper()
    ghsa = re.search(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", text, flags=re.IGNORECASE)
    if ghsa:
        return ghsa.group(0).upper()
    return ""


def build_record_answer(record: dict[str, Any]) -> str:
    references = record.get("references") or []
    ref_text = f"\n参考：{references[0]}" if references else ""
    summary = str(record.get("summary") or record.get("title") or "").strip().rstrip(".")
    return (
        f"{record.get('id')} 已在 {record.get('collection')} 集合中命中，严重等级为 {record.get('severity')}。"
        f"{summary}。建议优先核查受影响组件版本、暴露面、可利用条件，并按官方修复版本或缓解方案处置。{ref_text}"
    )


def format_record_context(record: dict[str, Any]) -> str:
    refs = record.get("references") or []
    return (
        f"- {record.get('id')} | {record.get('severity')} | {record.get('source')} | "
        f"{record.get('summary') or record.get('title') or ''} | {refs[0] if refs else ''}"
    )


def fallback_answer(state: AssistantState) -> str:
    question = state.get("question", "")
    lowered = question.lower()
    if any(token in lowered for token in ["供应链", "supply chain", "dependency", "sbom", "sca"]):
        return (
            "当前模型不可用，先给出本地安全专家建议：供应链治理应从依赖资产清单、SBOM、锁定版本、来源可信校验、"
            "漏洞情报订阅、CI 阶段阻断高危依赖和制品签名验证开始，并把例外审批与修复 SLA 固化到研发流程。"
        )
    if any(token in lowered for token in ["代码审计", "sast", "semgrep", "codeql"]):
        return (
            "当前模型不可用，先给出本地安全专家建议：代码审计应按入口点、鉴权边界、数据流、危险函数、依赖风险和历史漏洞模式"
            "分层排查；SAST 结果需要结合可达性、利用条件和业务影响做优先级排序。"
        )
    if any(token in lowered for token in ["威胁建模", "stride", "攻击面"]):
        return (
            "当前模型不可用，先给出本地安全专家建议：威胁建模建议先画清资产、数据流、信任边界和外部入口，"
            "再按 STRIDE 检查身份伪造、篡改、抵赖、信息泄露、拒绝服务和权限提升风险。"
        )
    return (
        "当前模型未返回可用结果，先给出本地安全专家降级建议。请检查 LLM API Key、Endpoint、模型名称和网络连通性；"
        "对于非 CVE 问题，系统会优先把长期记忆与上下文注入模型后回答。"
    )


def runtime_status() -> dict[str, Any]:
    return {"llm": llm_status(), "memory": memory_service.status()}


knowledge_graph = KnowledgeSecurityGraph()
