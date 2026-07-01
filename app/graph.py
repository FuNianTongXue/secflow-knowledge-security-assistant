from __future__ import annotations

import re
from typing import Any, TypedDict

try:
    from langgraph.graph import END, StateGraph
except Exception:  # noqa: BLE001
    END = "__end__"
    StateGraph = None

from app.collectors import collector_service
from app.storage import now_iso


class AssistantState(TypedDict, total=False):
    question: str
    top_k: int
    intent: str
    vulnerability_id: str
    records: list[dict[str, Any]]
    answer: dict[str, Any]
    trace: list[dict[str, Any]]


class KnowledgeSecurityGraph:
    def __init__(self) -> None:
        self._graph = self._build_graph()

    def invoke(self, question: str, top_k: int = 5) -> dict[str, Any]:
        state: AssistantState = {
            "question": question,
            "top_k": top_k,
            "intent": "general",
            "vulnerability_id": "",
            "records": [],
            "trace": [],
        }
        if self._graph is None:
            state = self._classify_query(state)
            state = self._retrieve_local_knowledge(state)
            state = self._fetch_live_vulnerability(state)
            state = self._compose_answer(state)
            return state["answer"]
        final = self._graph.invoke(state)
        return final["answer"]

    @staticmethod
    def graph_spec() -> dict[str, Any]:
        return {
            "name": "Knowledge Security Assistant LangGraph",
            "nodes": [
                {"id": "classify_query", "label": "Classify Query"},
                {"id": "retrieve_local_knowledge", "label": "Retrieve Local Knowledge"},
                {"id": "fetch_live_vulnerability", "label": "Fetch Live Vulnerability"},
                {"id": "compose_answer", "label": "Compose Answer"},
            ],
            "edges": [
                {"source": "classify_query", "target": "retrieve_local_knowledge", "label": "query intent"},
                {"source": "retrieve_local_knowledge", "target": "fetch_live_vulnerability", "label": "missing exact record"},
                {"source": "retrieve_local_knowledge", "target": "compose_answer", "label": "local context ready"},
                {"source": "fetch_live_vulnerability", "target": "compose_answer", "label": "live result"},
            ],
        }

    def _build_graph(self):
        if StateGraph is None:
            return None
        graph = StateGraph(AssistantState)
        graph.add_node("classify_query", self._classify_query)
        graph.add_node("retrieve_local_knowledge", self._retrieve_local_knowledge)
        graph.add_node("fetch_live_vulnerability", self._fetch_live_vulnerability)
        graph.add_node("compose_answer", self._compose_answer)
        graph.set_entry_point("classify_query")
        graph.add_edge("classify_query", "retrieve_local_knowledge")
        graph.add_conditional_edges(
            "retrieve_local_knowledge",
            self._route_after_retrieve,
            {
                "fetch_live_vulnerability": "fetch_live_vulnerability",
                "compose_answer": "compose_answer",
            },
        )
        graph.add_edge("fetch_live_vulnerability", "compose_answer")
        graph.add_edge("compose_answer", END)
        return graph.compile()

    def _classify_query(self, state: AssistantState) -> AssistantState:
        question = state["question"]
        vuln_id = extract_vulnerability_id(question)
        if vuln_id:
            state["intent"] = "vulnerability_lookup"
            state["vulnerability_id"] = vuln_id
        elif any(word in question.lower() for word in ["supply chain", "dependency", "poisoning", "sbom"]):
            state["intent"] = "supply_chain"
        elif any(word in question.lower() for word in ["compliance", "policy", "control", "audit"]):
            state["intent"] = "compliance"
        else:
            state["intent"] = "security_knowledge"
        return add_trace(state, "classify_query", f"Intent classified as {state['intent']}.")

    def _retrieve_local_knowledge(self, state: AssistantState) -> AssistantState:
        records = collector_service.search(state["question"], state.get("top_k", 5))
        state["records"] = records
        return add_trace(state, "retrieve_local_knowledge", f"Retrieved {len(records)} local knowledge records.")

    def _fetch_live_vulnerability(self, state: AssistantState) -> AssistantState:
        vuln_id = state.get("vulnerability_id", "")
        if not vuln_id:
            return add_trace(state, "fetch_live_vulnerability", "No vulnerability ID found; live fetch skipped.")
        collector_id = "github_advisory" if vuln_id.startswith("GHSA-") else "cve"
        try:
            result = collector_service.collect(collector_id)
            live_records = [record for record in result.get("records", []) if str(record.get("id", "")).upper() == vuln_id]
            if live_records:
                state["records"] = [*live_records, *state.get("records", [])]
                return add_trace(state, "fetch_live_vulnerability", f"Live record fetched for {vuln_id}.")
            refreshed = collector_service.search(vuln_id, 3)
            state["records"] = [*refreshed, *state.get("records", [])]
            return add_trace(state, "fetch_live_vulnerability", f"Live collector executed for {collector_id}.")
        except Exception as exc:  # noqa: BLE001
            return add_trace(state, "fetch_live_vulnerability", f"Live fetch failed: {exc}", status="warning")

    def _compose_answer(self, state: AssistantState) -> AssistantState:
        state = add_trace(state, "compose_answer", "Answer composed.")
        records = state.get("records", [])
        if records:
            primary = records[0]
            answer = {
                "mode": state.get("intent", "security_knowledge"),
                "summary": build_record_answer(primary),
                "records": records,
                "confidence": 0.86 if state.get("vulnerability_id") else 0.68,
                "trace": state.get("trace", []),
                "generated_at": now_iso(),
            }
        else:
            answer = {
                "mode": state.get("intent", "security_knowledge"),
                "summary": (
                    "No matching local record was found. Configure and run the CVE or GitHub Advisory collector, "
                    "then ask again with a CVE or GHSA identifier."
                ),
                "records": [],
                "confidence": 0.38,
                "trace": state.get("trace", []),
                "generated_at": now_iso(),
            }
        state["answer"] = answer
        return state

    @staticmethod
    def _route_after_retrieve(state: AssistantState) -> str:
        vuln_id = state.get("vulnerability_id", "")
        records = state.get("records", [])
        exact = any(str(record.get("id", "")).upper() == vuln_id for record in records)
        if vuln_id and not exact:
            return "fetch_live_vulnerability"
        return "compose_answer"


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
    ref_text = f" Reference: {references[0]}" if references else ""
    summary = str(record.get("summary") or record.get("title") or "").strip().rstrip(".")
    return (
        f"{record.get('id')} is tracked in {record.get('collection')} with severity "
        f"{record.get('severity')}. {summary}.{ref_text}"
    )


knowledge_graph = KnowledgeSecurityGraph()
