from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, TypedDict

try:
    from langgraph.graph import END, StateGraph
except Exception:  # noqa: BLE001
    END = "__end__"
    StateGraph = None

from app.collectors import collector_service
from app.llm import active_model_from_env, diagnose_chat_completion, llm_status
from app.memory import memory_service
from app.privacy import public_answer_payload, sanitize_public_text, severity_cn
from app.storage import now_iso


SYSTEM_PROMPT = """你是 SecFlow Knowledge Security Assistant，定位是安全知识助手。
请用中文回答，语气专业、简洁、可落地。
如果问题包含 CVE 或 GHSA 编号，优先结合内部安全知识回答，并说明影响、利用条件、涉及版本、修复版本、修复建议和缓释措施。
如果问题包含年份并询问漏洞、CVE、高危漏洞或最新漏洞，必须先结合内部安全知识完成事实核验再回答。
如果问题不是具体漏洞查询，不要编造漏洞库记录；应结合长期记忆、上下文和通用安全工程经验回答。
当模型上下文中提供了长期记忆时，只把它作为偏好和历史背景，不要泄露内部存储结构。
禁止在回答中披露情报供应商、接口名称、内部集合名、检索链路、来源 URL、参考链接或模型调用链。
涉及版本与修复版本必须忠实使用上下文中的结构化事实；不得把通配符解释为“所有版本”，不得猜测修复版本。
"""


VULNERABILITY_CARD_PROMPT = """你是安全漏洞中文整理子节点。请根据给定事实和分析结果输出严格 JSON，不要输出 Markdown 或解释。
必须包含且只包含这些键：漏洞编号、漏洞名称、漏洞描述、CVSS评分、严重等级、涉及版本、修复版本、修复方案、缓释措施、代码片段。
所有叙述字段必须使用简体中文并换行清晰；漏洞编号、产品名、包名、版本号和代码保持原文。
涉及版本只能翻译和整理输入中的 affected_versions，不能把 * 改成所有版本。
修复版本只能使用输入中的 fixed_versions；如果没有明确修复版本，填写“未明确”。
禁止输出情报来源、链接、供应商、接口、集合名、检索链路或模型信息。
"""


class AssistantState(TypedDict, total=False):
    question: str
    top_k: int
    user_id: str
    session_id: str
    intent: str
    vulnerability_id: str
    year_filter: list[int]
    records: list[dict[str, Any]]
    memory_context: dict[str, Any]
    llm_result: dict[str, Any]
    llm_error: str
    vulnerability_card: dict[str, Any]
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
            "year_filter": [],
            "records": [],
            "memory_context": {},
            "llm_result": {},
            "llm_error": "",
            "vulnerability_card": {},
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
            state = self._translate_vulnerability_card(state)
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
                {"id": "translate_vulnerability_card", "label": "中文整理漏洞卡片"},
                {"id": "compose_answer", "label": "生成回答"},
                {"id": "persist_memory", "label": "保存长期记忆"},
            ],
            "edges": [
                {"source": "classify_query", "target": "load_memory_context", "label": "问题分类"},
                {"source": "load_memory_context", "target": "retrieve_local_knowledge", "label": "CVE/GHSA/年份漏洞"},
                {"source": "load_memory_context", "target": "call_llm", "label": "通用安全问题"},
                {"source": "retrieve_local_knowledge", "target": "fetch_live_vulnerability", "label": "精确漏洞未命中或年份查询"},
                {"source": "retrieve_local_knowledge", "target": "call_llm", "label": "检索完成"},
                {"source": "fetch_live_vulnerability", "target": "call_llm", "label": "采集完成"},
                {"source": "call_llm", "target": "translate_vulnerability_card", "label": "整理客户可见字段"},
                {"source": "translate_vulnerability_card", "target": "compose_answer", "label": "中文结构化卡片"},
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
        graph.add_node("translate_vulnerability_card", self._translate_vulnerability_card)
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
        graph.add_edge("call_llm", "translate_vulnerability_card")
        graph.add_edge("translate_vulnerability_card", "compose_answer")
        graph.add_edge("compose_answer", "persist_memory")
        graph.add_edge("persist_memory", END)
        return graph.compile()

    def _classify_query(self, state: AssistantState) -> AssistantState:
        question = state["question"]
        vuln_id = extract_vulnerability_id(question)
        year_filter = extract_year_filter(question)
        lowered = question.lower()
        if vuln_id:
            state["intent"] = "vulnerability_lookup"
            state["vulnerability_id"] = vuln_id
        elif year_filter and is_vulnerability_year_question(question):
            state["intent"] = "vulnerability_year_lookup"
            state["year_filter"] = year_filter
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
                f"已召回长期记忆：历史 {stats.get('historyCount', 0)} 条，相关 {stats.get('retrievedCount', 0)} 条。",
            )
        except Exception as exc:  # noqa: BLE001
            state["memory_context"] = {"enabled": False, "error": str(exc)}
            return add_trace(state, "load_memory_context", f"长期记忆读取失败：{exc}", status="warning")

    def _retrieve_local_knowledge(self, state: AssistantState) -> AssistantState:
        if state.get("intent") == "vulnerability_year_lookup":
            records = collector_service.search_by_years(state["question"], state.get("year_filter", []), state.get("top_k", 5))
            state["records"] = records
            years = "、".join(str(year) for year in state.get("year_filter", []))
            return add_trace(state, "retrieve_local_knowledge", f"已按年份 {years} 核验到 {len(records)} 条内部安全记录。")
        records = collector_service.search(state["question"], state.get("top_k", 5))
        state["records"] = records
        return add_trace(state, "retrieve_local_knowledge", f"已检索到 {len(records)} 条本地漏洞记录。")

    def _fetch_live_vulnerability(self, state: AssistantState) -> AssistantState:
        if state.get("intent") == "vulnerability_year_lookup":
            years = state.get("year_filter", [])
            try:
                result = collector_service.collect_cve_by_years(years, max_results=max(state.get("top_k", 5), 10))
                live_records = result.get("records", [])
                merged = merge_records(live_records, state.get("records", []), state.get("top_k", 5))
                state["records"] = merged
                year_text = "、".join(str(year) for year in years)
                if result.get("status") != "success":
                    return add_trace(
                        state,
                        "fetch_live_vulnerability",
                        f"按年份 {year_text} 补充安全事实时未取得完整结果，已保留 {len(merged)} 条可用记录。",
                        status="warning",
                    )
                return add_trace(
                    state,
                    "fetch_live_vulnerability",
                    f"已按年份 {year_text} 补充 {len(live_records)} 条候选记录，并合并为 {len(merged)} 条内部安全事实。",
                )
            except Exception as exc:  # noqa: BLE001
                return add_trace(state, "fetch_live_vulnerability", "安全事实补充失败，已保留现有核验结果。", status="warning")

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
            return add_trace(state, "fetch_live_vulnerability", f"已补充 {len(refreshed)} 条候选安全记录。")
        except Exception as exc:  # noqa: BLE001
            return add_trace(state, "fetch_live_vulnerability", "安全记录补充失败，继续使用现有知识回答。", status="warning")

    def _call_llm(self, state: AssistantState) -> AssistantState:
        model = active_model_from_env()
        messages = self._build_messages(state)
        result = diagnose_chat_completion(model, messages) if model else {"status": "failed", "message": "未配置可用模型。"}
        state["llm_result"] = result
        if result.get("status") == "success":
            return add_trace(state, "call_llm", f"模型调用成功，耗时 {result.get('latency_ms', 0)}ms。")
        state["llm_error"] = str(result.get("message") or "模型未返回可用结果。")
        return add_trace(state, "call_llm", state["llm_error"], status="warning")

    def _translate_vulnerability_card(self, state: AssistantState) -> AssistantState:
        if state.get("intent") not in {"vulnerability_lookup", "vulnerability_year_lookup"}:
            return add_trace(state, "translate_vulnerability_card", "当前问题无需生成漏洞卡片。")

        records = state.get("records", [])
        if not records:
            state["vulnerability_card"] = build_empty_vulnerability_card(state.get("vulnerability_id", ""))
            return add_trace(state, "translate_vulnerability_card", "未找到可整理的漏洞事实，已生成未命中卡片。", status="warning")

        record = records[0]
        fallback = build_vulnerability_card(record)
        model = active_model_from_env()
        if not model:
            state["vulnerability_card"] = fallback
            return add_trace(state, "translate_vulnerability_card", "已按本地规则生成中文结构化漏洞卡片。")

        facts = record_for_card_prompt(record)
        analysis = str((state.get("llm_result") or {}).get("answer") or "")
        messages = [
            {"role": "system", "content": VULNERABILITY_CARD_PROMPT},
            {
                "role": "user",
                "content": "漏洞事实：\n"
                + json.dumps(facts, ensure_ascii=False)
                + "\n\n安全分析：\n"
                + analysis,
            },
        ]
        result = diagnose_chat_completion(model, messages)
        if result.get("status") != "success":
            state["vulnerability_card"] = fallback
            return add_trace(state, "translate_vulnerability_card", "中文整理未返回有效内容，已使用事实模板。", status="warning")

        parsed = parse_json_object(str(result.get("answer") or ""))
        state["vulnerability_card"] = merge_translated_card(parsed, fallback, record)
        return add_trace(state, "translate_vulnerability_card", "已完成中文翻译、版本约束校验和结构化卡片整理。")

    def _compose_answer(self, state: AssistantState) -> AssistantState:
        records = state.get("records", [])
        llm_result = state.get("llm_result", {})
        fields = {
            "意图": state.get("intent", "security_knowledge"),
            "长期记忆": self._memory_label(state.get("memory_context", {})),
            "模型调用状态": "成功" if llm_result.get("status") == "success" else state.get("llm_error", "未调用"),
        }
        if state.get("year_filter"):
            fields["年份过滤"] = "、".join(str(year) for year in state.get("year_filter", []))
            fields["漏洞数据策略"] = "年份问题已优先查询本地 RAG，并尝试调用 CVE 接口补充最新记录"
        card = state.get("vulnerability_card", {})

        if card and state.get("intent") == "vulnerability_lookup":
            summary = build_card_summary(card)
            confidence = 0.9 if records else 0.5
        elif llm_result.get("status") == "success":
            summary = str(llm_result.get("answer", "")).strip()
            confidence = 0.82 if not records else 0.9
        elif records and state.get("intent") == "vulnerability_year_lookup":
            summary = build_year_vulnerability_answer(records, state.get("year_filter", []))
            confidence = 0.76
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
            "fields": fields,
            "vulnerability_card": card,
            "confidence": confidence,
            "trace": state.get("trace", []),
            "generated_at": now_iso(),
        }
        state["answer"] = public_answer_payload(answer)
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
            state["answer"] = public_answer_payload(answer)
            return add_trace(state, "persist_memory", "已写入长期记忆。")
        except Exception as exc:  # noqa: BLE001
            state["answer"] = public_answer_payload(answer)
            return add_trace(state, "persist_memory", f"长期记忆保存失败：{exc}", status="warning")

    @staticmethod
    def _should_retrieve(state: AssistantState) -> bool:
        return state.get("intent") in {"vulnerability_lookup", "vulnerability_year_lookup"}

    @staticmethod
    def _should_fetch_live(state: AssistantState) -> bool:
        if state.get("intent") == "vulnerability_year_lookup" and state.get("year_filter"):
            return True
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

def add_trace(state: AssistantState, node: str, message: str, status: str = "completed") -> AssistantState:
    state["trace"] = [
        *state.get("trace", []),
        {"node": node, "status": status, "message": sanitize_public_text(message), "time": now_iso()},
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


def extract_year_filter(text: str) -> list[int]:
    now_year = datetime.now().year
    years = {int(item) for item in re.findall(r"(?<!\d)(20\d{2}|19\d{2})(?!\d)", text)}
    if re.search(r"今年|本年|current year|this year", text, flags=re.IGNORECASE):
        years.add(now_year)
    if re.search(r"去年|上一年|last year", text, flags=re.IGNORECASE):
        years.add(now_year - 1)
    recent = re.search(r"近\s*([两二三四五2-5])\s*年|最近\s*([两二三四五2-5])\s*年", text)
    if recent:
        raw = next(group for group in recent.groups() if group)
        count = {"两": 2, "二": 2, "三": 3, "四": 4, "五": 5}.get(raw, int(raw) if raw.isdigit() else 2)
        years.update(now_year - offset for offset in range(count))
    return sorted((year for year in years if 1999 <= year <= now_year + 1), reverse=True)


def is_vulnerability_year_question(text: str) -> bool:
    lowered = text.lower()
    security_keywords = [
        "cve",
        "漏洞",
        "高危",
        "严重",
        "rce",
        "0day",
        "zero-day",
        "vulnerability",
        "exploit",
        "安全",
        "修复",
        "补丁",
        "最新",
    ]
    return bool(extract_year_filter(text)) and any(keyword in lowered for keyword in security_keywords)


def build_record_answer(record: dict[str, Any]) -> str:
    summary = str(record.get("summary") or record.get("title") or "").strip().rstrip(".")
    return (
        f"{record.get('id')} 的严重等级为 {severity_cn(record.get('severity'))}。"
        f"{summary}。建议优先核查受影响组件版本、暴露面、可利用条件，并按明确的修复版本或缓解方案处置。"
    )


def build_year_vulnerability_answer(records: list[dict[str, Any]], years: list[int]) -> str:
    year_text = "、".join(str(year) for year in years) or "指定年份"
    lines = [f"已完成 {year_text} 年漏洞事实核验。当前候选漏洞如下："]
    for record in records[:8]:
        lines.append(
            f"- {record.get('id')} | {severity_cn(record.get('severity'))} | "
            f"{record.get('title') or record.get('summary') or '暂无标题'}"
        )
    lines.append("请结合资产暴露面、受影响版本、是否已有利用代码和官方补丁状态继续排序处置。")
    return "\n".join(lines)


def merge_records(primary: list[dict[str, Any]], secondary: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for record in [*primary, *secondary]:
        key = str(record.get("id", "")).upper()
        if key and key not in merged:
            merged[key] = record
    return list(merged.values())[:limit]


def format_record_context(record: dict[str, Any]) -> str:
    return (
        f"- 漏洞编号: {record.get('id')} | 严重等级: {severity_cn(record.get('severity'))} | "
        f"CVSS: {record.get('cvss_score') if record.get('cvss_score') is not None else '未明确'} | "
        f"漏洞描述: {record.get('summary') or record.get('title') or ''} | "
        f"涉及版本: {'；'.join(record.get('affected_versions') or []) or '未明确'} | "
        f"修复版本: {'；'.join(record.get('fixed_versions') or []) or '未明确'}"
    )


def record_for_card_prompt(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": record.get("id") or "",
        "title": record.get("title") or "",
        "description": record.get("summary") or "",
        "cvss_score": record.get("cvss_score"),
        "severity": severity_cn(record.get("severity")),
        "affected_versions": record.get("affected_versions") or [],
        "fixed_versions": record.get("fixed_versions") or [],
    }


def build_vulnerability_card(record: dict[str, Any]) -> dict[str, Any]:
    facts = record_for_card_prompt(record)
    affected = "；".join(str(value) for value in facts["affected_versions"] if value) or "未明确"
    fixed = "；".join(str(value) for value in facts["fixed_versions"] if value) or "未明确"
    fixed_instruction = (
        f"升级到已确认的修复版本：{fixed}，并在测试环境完成兼容性与回归验证。"
        if fixed != "未明确"
        else "当前知识记录未明确给出修复版本；请完成资产版本核验并采用厂商确认的首个安全版本，禁止猜测版本号。"
    )
    return {
        "漏洞编号": facts["id"] or "未明确",
        "漏洞名称": facts["title"] or facts["id"] or "未明确",
        "漏洞描述": facts["description"] or "暂无可核验的漏洞描述。",
        "CVSS评分": facts["cvss_score"] if facts["cvss_score"] is not None else "未明确",
        "严重等级": facts["severity"],
        "涉及版本": affected,
        "修复版本": fixed,
        "修复方案": fixed_instruction,
        "缓释措施": "修复完成前限制受影响组件的网络暴露和访问权限，启用异常行为监控，并对高风险入口实施临时阻断。",
        "代码片段": "",
    }


def build_empty_vulnerability_card(vulnerability_id: str) -> dict[str, Any]:
    return {
        "漏洞编号": vulnerability_id or "未明确",
        "漏洞名称": "未找到可核验的漏洞记录",
        "漏洞描述": "当前安全知识中没有足够事实生成可靠结论。",
        "CVSS评分": "未明确",
        "严重等级": "未知",
        "涉及版本": "未明确",
        "修复版本": "未明确",
        "修复方案": "请先核验漏洞编号及资产版本，再根据确认后的安全版本制定升级计划。",
        "缓释措施": "在事实核验完成前收敛相关组件暴露面并加强访问监控。",
        "代码片段": "",
    }


def parse_json_object(text: str) -> dict[str, Any]:
    value = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", value, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        value = fenced.group(1)
    else:
        match = re.search(r"\{.*\}", value, flags=re.DOTALL)
        value = match.group(0) if match else ""
    if not value:
        return {}
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def merge_translated_card(parsed: dict[str, Any], fallback: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    keys = tuple(fallback)
    merged = {key: parsed.get(key) or fallback[key] for key in keys}

    # Fact fields are authoritative and may not be invented by the model.
    merged["漏洞编号"] = fallback["漏洞编号"]
    merged["CVSS评分"] = fallback["CVSS评分"]
    merged["严重等级"] = fallback["严重等级"]
    merged["涉及版本"] = fallback["涉及版本"]
    merged["修复版本"] = fallback["修复版本"]
    if not record.get("fixed_versions"):
        merged["修复版本"] = "未明确"
    return {key: sanitize_public_text(merged[key]) for key in keys}


def build_card_summary(card: dict[str, Any]) -> str:
    return "\n".join(
        f"{key}：{card.get(key, '')}"
        for key in (
            "漏洞编号",
            "漏洞名称",
            "漏洞描述",
            "CVSS评分",
            "严重等级",
            "涉及版本",
            "修复版本",
            "修复方案",
            "缓释措施",
            "代码片段",
        )
        if card.get(key) not in {None, ""}
    )


def fallback_answer(state: AssistantState) -> str:
    question = state.get("question", "")
    lowered = question.lower()
    if state.get("intent") == "vulnerability_year_lookup":
        years = "、".join(str(year) for year in state.get("year_filter", [])) or "指定年份"
        return (
            f"当前没有足够事实完成 {years} 年漏洞回答。请由管理员检查内部漏洞采集配置、网络连通性和知识记录。"
        )
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
