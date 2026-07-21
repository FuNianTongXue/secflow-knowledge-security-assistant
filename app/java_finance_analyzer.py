from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any, Iterable


UNSAFE_ENTRY_ANNOTATIONS = {
    "PostMapping",
    "PutMapping",
    "PatchMapping",
    "DeleteMapping",
    "MessageMapping",
    "KafkaListener",
    "RabbitListener",
    "JmsListener",
    "SqsListener",
}

FINANCE_ACTION_RE = re.compile(
    r"pay|payment|refund|transfer|withdraw|deposit|recharge|settle|checkout|charge|capture|"
    r"debit|credit|payout|disburse|repay|remit|topup|addfunds|deduct|balance|wallet|ledger|"
    r"trade|transaction|order|fund|money|freeze|unfreeze",
    re.IGNORECASE,
)
FINANCE_STRONG_MUTATION_RE = re.compile(
    r"^(?:pay|payment|process.*payment|refund|transfer|withdraw|deposit|recharge|settle|checkout|charge|"
    r"capture|debit|credit|payout|disburse|repay|remit|topup|addfunds|deduct|"
    r"increasebalance|decreasebalance|updatebalance|adjustbalance|bookentry|postentry|"
    r"createpayment|createcharge|executepayment|executeorder|place.*order|cancel.*order|"
    r"purchase|subscribe|runbilling|creditpending|paybill|donat).*$",
    re.IGNORECASE,
)
FINANCE_DATA_RE = re.compile(
    r"amount|balance|wallet|ledger|payment|refund|transfer|withdraw|deposit|charge|capture|"
    r"transaction|trade|order|settlement|payout|disbursement|repayment|fund|money",
    re.IGNORECASE,
)
NON_FUNDS_CONTEXT_RE = re.compile(
    r"profile|password|login|auth|oauth|token|email|address|contact|preference|config|setting|"
    r"statistics|chart|watchlist|bind(?:ing)?|customer|userdetail|paymentdetails?|dto|mapper|convert",
    re.IGNORECASE,
)
READ_ONLY_RE = re.compile(r"^(?:get|find|query|list|search|show|load|fetch|read|count|exists|validate|verify)", re.IGNORECASE)
PERSISTENCE_RE = re.compile(r"^(?:save|saveall|insert|update|upsert|merge|persist|create|delete)$", re.IGNORECASE)
KEY_RE = re.compile(
    r"idempot|dedup|nonce|request(?:id|no|key)|clientorderid|paymentid|transactionid|"
    r"transactionno|orderno|bizno|businessno|serialno|eventid|messageid|operationid",
    re.IGNORECASE,
)
ATOMIC_CLAIM_RE = re.compile(
    r"^(?:setnx|setifabsent|putifabsent|trybegin|tryclaim|claim|claimonce|insertunique|"
    r"insertonconflict|saveifabsent|createifabsent|recordonce|acquireonce|"
    r"compareandset|updatestatusifcurrent|transitionifcurrent|updateifversion)$",
    re.IGNORECASE,
)
LOOKUP_RE = re.compile(
    r"^(?:isduplicate|alreadyprocessed|containskey|exists|existsby.+|findby.+|getby.+|"
    r"lookup|checkduplicate|checkprocessed)$",
    re.IGNORECASE,
)
LOCK_RE = re.compile(r"^(?:trylock|lock|acquire)$", re.IGNORECASE)
PREVIOUS_RESULT_RE = re.compile(
    r"previous|existing|cached|replay|findby|getby|lookup|alreadyprocessed|duplicate",
    re.IGNORECASE,
)
RESULT_PERSIST_RE = re.compile(
    r"^(?:saveresult|storeresult|persistresult|cacheresult|markcompleted|complete|finish|"
    r"completeidempotency|finishidempotency)$",
    re.IGNORECASE,
)
TRANSACTION_RE = re.compile(
    r"@(?:org\.springframework\.transaction\.annotation\.)?Transactional\b|"
    r"transactionTemplate\s*\.\s*execute|beginTransaction\s*\(|setAutoCommit\s*\(\s*false",
    re.IGNORECASE,
)
STATUS_RE = re.compile(r"status|state|version", re.IGNORECASE)
STATE_CAS_RE = re.compile(
    r"compareandset|updatestatusif|transitionif|updateifversion|updatewhere.*status|"
    r"mark.*if|advance.*if",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ValueOrigin:
    kind: str
    param_index: int = -1
    label: str = ""
    key_like: bool = False
    steps: tuple[tuple[str, int, str], ...] = ()


@dataclass(frozen=True)
class Location:
    method_key: str
    block_id: int
    order: int
    file: str
    line: int
    method: str
    snippet: str
    label: str


@dataclass(frozen=True)
class Effect:
    kind: str
    path: tuple[Location, ...]
    origins: tuple[ValueOrigin, ...] = ()
    atomic: bool = False
    durable: bool = False
    transactional: bool = False
    store: str = ""
    resolved: bool = True

    @property
    def location(self) -> Location:
        return self.path[-1]


@dataclass(frozen=True)
class CallSite:
    location: Location
    name: str
    object_text: str
    receiver_type: str
    arity: int
    argument_origins: tuple[tuple[ValueOrigin, ...], ...]


@dataclass
class BasicBlock:
    id: int
    node: Any
    kind: str


@dataclass
class MethodModel:
    method: Any
    blocks: dict[int, BasicBlock]
    edges: set[tuple[int, int]]
    entry: int
    dominators: dict[int, frozenset[int]]
    local_effects: tuple[Effect, ...]
    calls: tuple[CallSite, ...]
    transactional: bool
    dfg_edges: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class MethodEffects:
    effects: tuple[Effect, ...] = ()


@dataclass
class _CfgBuilder:
    method: Any
    blocks: dict[int, BasicBlock] = field(default_factory=dict)
    edges: set[tuple[int, int]] = field(default_factory=set)
    next_id: int = 0

    def block(self, node: Any, kind: str) -> int:
        block_id = self.next_id
        self.next_id += 1
        self.blocks[block_id] = BasicBlock(block_id, node, kind)
        return block_id

    def connect(self, incoming: Iterable[int], target: int) -> None:
        for source in incoming:
            self.edges.add((source, target))

    def sequence(self, nodes: Iterable[Any], incoming: set[int]) -> set[int]:
        exits = set(incoming)
        for node in nodes:
            exits = self.statement(node, exits)
        return exits

    def statement(self, node: Any, incoming: set[int]) -> set[int]:
        if node.type in {"block", "class_body"}:
            return self.sequence(node.named_children, incoming)
        if node.type == "if_statement":
            condition = node.child_by_field_name("condition") or node
            condition_id = self.block(condition, "condition")
            self.connect(incoming, condition_id)
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")
            consequence_exits = self.statement(consequence, {condition_id}) if consequence is not None else {condition_id}
            alternative_exits = self.statement(alternative, {condition_id}) if alternative is not None else {condition_id}
            return consequence_exits | alternative_exits
        if node.type in {"while_statement", "do_statement", "for_statement", "enhanced_for_statement"}:
            condition = node.child_by_field_name("condition") or node.child_by_field_name("value") or node
            condition_id = self.block(condition, "loop_condition")
            self.connect(incoming, condition_id)
            body = node.child_by_field_name("body")
            body_exits = self.statement(body, {condition_id}) if body is not None else {condition_id}
            self.connect(body_exits, condition_id)
            return {condition_id}
        if node.type in {"switch_expression", "switch_statement"}:
            condition = node.child_by_field_name("condition") or node
            condition_id = self.block(condition, "switch_condition")
            self.connect(incoming, condition_id)
            body = node.child_by_field_name("body")
            if body is None:
                return {condition_id}
            exits: set[int] = {condition_id}
            for child in body.named_children:
                exits |= self.statement(child, {condition_id})
            return exits
        if node.type == "try_statement":
            try_id = self.block(node, "try")
            self.connect(incoming, try_id)
            exits: set[int] = set()
            body = node.child_by_field_name("body")
            if body is not None:
                exits |= self.statement(body, {try_id})
            for child in node.named_children:
                if child.type in {"catch_clause", "finally_clause"}:
                    exits |= self.statement(child, {try_id})
            return exits or {try_id}
        block_id = self.block(node, "return" if node.type in {"return_statement", "throw_statement"} else "statement")
        self.connect(incoming, block_id)
        if node.type in {"return_statement", "throw_statement"}:
            return set()
        return {block_id}


class JavaFinanceAnalyzer:
    """Native Java finance analysis using explicit CFG, dominance and interprocedural effect summaries."""

    def __init__(
        self,
        methods: dict[str, Any],
        by_class_name_arity: dict[tuple[str, str, int], list[str]],
        code_files: list[dict[str, str]],
    ) -> None:
        self.methods = methods
        self.by_class_name_arity = by_class_name_arity
        self.code_files = code_files
        self.models: dict[str, MethodModel] = {}
        project_text = "\n".join(str(item.get("content") or "") for item in code_files)
        self.has_unique_idempotency_constraint = bool(
            re.search(
                r"unique\s*=\s*true|uniqueConstraints\s*=|CREATE\s+UNIQUE\s+INDEX|"
                r"\bUNIQUE\s*\([^)]*(?:idempot|request|client_order|payment|transaction|event)",
                project_text,
                re.IGNORECASE,
            )
        )

    def analyze(self) -> dict[str, Any]:
        if not self.methods:
            return self._empty_result()
        self.models = {key: self._build_method_model(method) for key, method in self.methods.items()}
        # A resolved project call is represented by the callee summary. Keeping the
        # name-based local effect as well would double count controller/service wrappers.
        for model in self.models.values():
            resolved_locations = {
                (call.location.block_id, call.location.order)
                for call in model.calls
                if self._resolve_call(model.method, call) is not None
            }
            model.local_effects = tuple(
                effect
                for effect in model.local_effects
                if (effect.location.block_id, effect.location.order) not in resolved_locations
            )
        summaries = {key: MethodEffects(model.local_effects) for key, model in self.models.items()}
        iterations = 0
        for iteration in range(8):
            updated: dict[str, MethodEffects] = {}
            changed = False
            for key, model in self.models.items():
                effects = list(model.local_effects)
                for call in model.calls:
                    callee = self._resolve_call(model.method, call)
                    if callee is None:
                        continue
                    for effect in summaries[callee.key].effects:
                        mapped = self._map_effect(effect, call, model.transactional)
                        if mapped is not None:
                            effects.append(mapped)
                summary = MethodEffects(_compact_effects(effects))
                updated[key] = summary
                changed = changed or summary != summaries[key]
            summaries = updated
            iterations = iteration + 1
            if not changed:
                break

        findings: list[dict[str, Any]] = []
        analyzed_endpoints = 0
        for key, model in self.models.items():
            if not _is_unsafe_entrypoint(model.method):
                continue
            effects = summaries[key].effects
            mutations = [effect for effect in effects if effect.kind in {"finance_mutation", "external_effect"}]
            if not mutations:
                continue
            analyzed_endpoints += 1
            findings.extend(self._idempotency_findings(model, effects, mutations))
            findings.extend(self._transaction_findings(model, effects, mutations))
            findings.extend(self._state_race_findings(model, effects, mutations))

        findings = _dedupe_findings(findings)
        return {
            "findings": findings,
            "finding_count": len(findings),
            "iterations": iterations,
            "finance_method_count": sum(1 for summary in summaries.values() if summary.effects),
            "finance_endpoint_count": analyzed_endpoints,
            "cfg_node_count": sum(len(model.blocks) for model in self.models.values()),
            "cfg_edge_count": sum(len(model.edges) for model in self.models.values()),
            "dfg_edge_count": sum(len(model.dfg_edges) for model in self.models.values()),
        }

    def _empty_result(self) -> dict[str, Any]:
        return {
            "findings": [],
            "finding_count": 0,
            "iterations": 0,
            "finance_method_count": 0,
            "finance_endpoint_count": 0,
            "cfg_node_count": 0,
            "cfg_edge_count": 0,
            "dfg_edge_count": 0,
        }

    def _build_method_model(self, method: Any) -> MethodModel:
        builder = _CfgBuilder(method)
        entry = builder.block(method.body, "entry")
        builder.sequence(method.body.named_children, {entry})
        dominators = _dominators(builder.blocks, builder.edges, entry)
        transaction_text = f"{method.modifiers}\n{_node_text(method.body, method.source)}"
        transactional = "Transactional" in method.annotations or "Transactional" in method.class_annotations or bool(
            TRANSACTION_RE.search(transaction_text)
        )
        effects, calls, dfg_edges = self._semantic_events(method, builder.blocks, transactional)
        return MethodModel(
            method=method,
            blocks=builder.blocks,
            edges=builder.edges,
            entry=entry,
            dominators=dominators,
            local_effects=tuple(effects),
            calls=tuple(calls),
            transactional=transactional,
            dfg_edges=tuple(dfg_edges),
        )

    def _semantic_events(
        self,
        method: Any,
        blocks: dict[int, BasicBlock],
        transactional: bool,
    ) -> tuple[list[Effect], list[CallSite], list[tuple[str, str]]]:
        environment: dict[str, tuple[ValueOrigin, ...]] = {}
        types = dict(method.field_types)
        dfg_edges: list[tuple[str, str]] = []
        for index, parameter in enumerate(method.parameters):
            key_like = _is_key_text(f"{parameter.name} {parameter.snippet}")
            environment[parameter.name] = (
                ValueOrigin(
                    "parameter",
                    param_index=index,
                    label=parameter.name,
                    key_like=key_like,
                    steps=((method.file_name, parameter.line, parameter.name),),
                ),
            )
            types[parameter.name] = parameter.type_name

        effects: list[Effect] = []
        calls: list[CallSite] = []
        ordered_blocks = sorted(blocks.values(), key=lambda item: (item.node.start_byte, item.id))
        for block in ordered_blocks:
            node = block.node
            if block.kind == "entry":
                continue
            self._update_environment(node, method, environment, types, dfg_edges)
            invocations = ([node] if node.type == "method_invocation" else []) + list(
                _descendants(node, {"method_invocation"}, stop_at_nested_types=True)
            )
            for call_node in sorted(invocations, key=lambda item: (item.start_byte, item.end_byte)):
                event, call = self._call_event(
                    call_node,
                    block.id,
                    method,
                    environment,
                    types,
                    transactional,
                )
                if event is not None:
                    effects.append(event)
                    for origin in event.origins:
                        dfg_edges.append((origin.label, event.location.label))
                if call is not None:
                    calls.append(call)
            if node.type == "return_statement":
                text = _node_text(node, method.source)
                location = _location(method, block.id, node, "重复请求返回路径")
                effects.append(
                    Effect(
                        kind="return_previous" if PREVIOUS_RESULT_RE.search(text) else "return",
                        path=(location,),
                        origins=_expr_origins(node, environment, method),
                        transactional=transactional,
                    )
                )
        return effects, _compact_calls(calls), dfg_edges

    def _update_environment(
        self,
        node: Any,
        method: Any,
        environment: dict[str, tuple[ValueOrigin, ...]],
        types: dict[str, str],
        dfg_edges: list[tuple[str, str]],
    ) -> None:
        if node.type == "local_variable_declaration":
            type_name = _node_text(node.child_by_field_name("type"), method.source)
            for declarator in (child for child in node.named_children if child.type == "variable_declarator"):
                name = _node_text(declarator.child_by_field_name("name"), method.source)
                value = declarator.child_by_field_name("value")
                if not name:
                    continue
                origins = _expr_origins(value, environment, method)
                environment[name] = _append_origin_step(origins, method, declarator, name)
                types[name] = type_name
                for origin in origins:
                    dfg_edges.append((origin.label, name))
            return
        assignments = [node] if node.type == "assignment_expression" else list(
            _descendants(node, {"assignment_expression"}, stop_at_nested_types=True)
        )
        for assignment in assignments:
            left = _node_text(assignment.child_by_field_name("left"), method.source)
            names = re.findall(r"[A-Za-z_$][\w$]*", left)
            if not names:
                continue
            name = names[-1]
            origins = _expr_origins(assignment.child_by_field_name("right"), environment, method)
            environment[name] = _append_origin_step(origins, method, assignment, name)
            for origin in origins:
                dfg_edges.append((origin.label, name))

    def _call_event(
        self,
        node: Any,
        block_id: int,
        method: Any,
        environment: dict[str, tuple[ValueOrigin, ...]],
        types: dict[str, str],
        transactional: bool,
    ) -> tuple[Effect | None, CallSite | None]:
        name = _node_text(node.child_by_field_name("name"), method.source)
        object_node = node.child_by_field_name("object")
        object_text = _node_text(object_node, method.source)
        receiver_name = object_text.split(".", 1)[0]
        receiver_type = _simple_type(types.get(receiver_name, "") or method.field_types.get(receiver_name, ""))
        arguments_node = node.child_by_field_name("arguments")
        argument_nodes = tuple(arguments_node.named_children) if arguments_node is not None else ()
        argument_origins = tuple(_expr_origins(argument, environment, method) for argument in argument_nodes)
        merged_origins = _merge_origins(*argument_origins)
        call_text = _node_text(node, method.source)
        argument_text = " ".join(_node_text(argument, method.source) for argument in argument_nodes)
        location = _location(method, block_id, node, f"调用 {name}")
        call = CallSite(location, name, object_text, receiver_type, len(argument_nodes), argument_origins)
        context = f"{method.class_name} {method.name} {receiver_name} {receiver_type} {call_text}"

        if STATE_CAS_RE.search(name):
            return (
                Effect(
                    "state_cas",
                    (replace(location, label="原子状态迁移"),),
                    merged_origins,
                    atomic=True,
                    durable=True,
                    transactional=transactional,
                    store="database",
                ),
                call,
            )
        if _is_atomic_claim(name, context):
            key_origins = _key_origins(merged_origins, argument_text, method, node)
            store = _claim_store(name, context)
            durable = store in {"database", "redis"}
            if store == "database" and PERSISTENCE_RE.match(name) and not self.has_unique_idempotency_constraint:
                durable = False
            return (
                Effect(
                    "idempotency_claim",
                    (replace(location, label="原子幂等认领"),),
                    key_origins,
                    atomic=True,
                    durable=durable,
                    transactional=transactional,
                    store=store,
                ),
                call,
            )
        if RESULT_PERSIST_RE.match(name) and re.search(r"idempot|dedup|request|operation", context, re.IGNORECASE):
            return (
                Effect(
                    "idempotency_result",
                    (replace(location, label="幂等结果持久化"),),
                    _key_origins(merged_origins, argument_text, method, node),
                    durable=_claim_store(name, context) in {"database", "redis"},
                    transactional=transactional,
                    store=_claim_store(name, context),
                ),
                call,
            )
        if LOCK_RE.match(name) and _is_key_text(context):
            return (
                Effect(
                    "idempotency_claim",
                    (replace(location, label="锁式重复请求保护"),),
                    _key_origins(merged_origins, argument_text, method, node),
                    atomic=True,
                    durable=False,
                    transactional=transactional,
                    store="lock",
                ),
                call,
            )
        if LOOKUP_RE.match(name) and (_is_key_text(context) or any(origin.key_like for origin in merged_origins)):
            return (
                Effect(
                    "idempotency_lookup",
                    (replace(location, label="非原子重复检查"),),
                    _key_origins(merged_origins, argument_text, method, node),
                    transactional=transactional,
                    store=_claim_store(name, context),
                ),
                call,
            )
        if _is_state_read(name, context):
            return Effect("state_read", (replace(location, label="资金状态读取"),), transactional=transactional), call
        effect_kind, store = _finance_effect_kind(name, context)
        if effect_kind:
            return (
                Effect(
                    effect_kind,
                    (replace(location, label="外部资金副作用" if effect_kind == "external_effect" else "资金状态变更"),),
                    merged_origins,
                    transactional=transactional,
                    store=store,
                ),
                call,
            )
        return None, call

    def _resolve_call(self, method: Any, call: CallSite) -> Any | None:
        receiver = call.object_text.strip()
        candidates: list[str] = []
        if not receiver or receiver in {"this", "super"}:
            candidates = self.by_class_name_arity.get((method.class_name, call.name, call.arity), [])
        else:
            simple_type = _simple_type(call.receiver_type)
            creation = re.match(r"new\s+(?:[A-Za-z_$][\w$]*\.)*([A-Za-z_$][\w$]*)\s*\(", receiver)
            if not simple_type and creation:
                simple_type = creation.group(1)
            if simple_type:
                candidates = self.by_class_name_arity.get((simple_type, call.name, call.arity), [])
            if not candidates:
                candidates = self.by_class_name_arity.get((_simple_type(receiver), call.name, call.arity), [])
            if not candidates and simple_type:
                implementation_names = {
                    f"{simple_type}Impl",
                    f"Default{simple_type}",
                    f"{simple_type}ServiceImpl" if not simple_type.endswith("Service") else f"{simple_type}Impl",
                }
                candidates = [
                    key
                    for key, candidate in self.methods.items()
                    if candidate.name == call.name
                    and candidate.arity == call.arity
                    and candidate.class_name in implementation_names
                ]
            if not candidates and simple_type:
                normalized_receiver = _normalized_implementation_name(simple_type)
                candidates = [
                    key
                    for key, candidate in self.methods.items()
                    if candidate.name == call.name
                    and candidate.arity == call.arity
                    and _normalized_implementation_name(candidate.class_name) == normalized_receiver
                ]
        if len(candidates) != 1:
            return None
        return self.methods[candidates[0]]

    def _map_effect(self, effect: Effect, call: CallSite, caller_transactional: bool) -> Effect | None:
        if len(effect.path) >= 8:
            return None
        origins: list[ValueOrigin] = []
        for origin in effect.origins:
            if origin.kind != "parameter":
                origins.append(origin)
                continue
            if origin.param_index < 0 or origin.param_index >= len(call.argument_origins):
                continue
            origins.extend(call.argument_origins[origin.param_index])
        return replace(
            effect,
            path=(replace(call.location, label=f"调用 {effect.path[0].method}"), *effect.path),
            origins=_merge_origins(tuple(origins)),
            transactional=caller_transactional or effect.transactional,
        )

    def _idempotency_findings(
        self,
        endpoint: MethodModel,
        effects: tuple[Effect, ...],
        mutations: list[Effect],
    ) -> list[dict[str, Any]]:
        claims = [
            effect
            for effect in effects
            if effect.kind in {"idempotency_claim", "state_cas"}
            and effect.atomic
            and effect.durable
            and (effect.kind == "state_cas" or any(origin.key_like for origin in effect.origins))
        ]
        weak_claims = [effect for effect in effects if effect.kind == "idempotency_claim" and effect not in claims]
        lookups = [effect for effect in effects if effect.kind == "idempotency_lookup"]
        findings: list[dict[str, Any]] = []
        for mutation in mutations:
            valid_claims = [claim for claim in claims if self._effect_dominates(claim, mutation)]
            if valid_claims:
                continue
            after_claims = [claim for claim in claims if self._effect_precedes(mutation, claim)]
            dominating_lookups = [lookup for lookup in lookups if self._effect_dominates(lookup, mutation)]
            dominating_weak = [claim for claim in weak_claims if self._effect_dominates(claim, mutation)]
            if after_claims:
                risk_kind = "guard_after_effect"
                title = "资金副作用发生在幂等认领之前"
                reason = "原子幂等认领未支配资金副作用；重试窗口中副作用可能已重复执行。"
                evidence_effect = after_claims[0]
            elif dominating_lookups:
                risk_kind = "check_then_act"
                title = "资金接口使用非原子先查后写幂等检查"
                reason = "重复检查与资金写入之间存在竞态窗口，并发请求可同时通过检查。"
                evidence_effect = dominating_lookups[0]
            elif dominating_weak:
                risk_kind = "non_durable_guard"
                title = "资金接口仅使用非持久化幂等保护"
                reason = "锁或普通保存不能提供可恢复的唯一认领与结果复用，进程重启或重放仍可能重复执行。"
                evidence_effect = dominating_weak[0]
            else:
                risk_kind = "missing_guard"
                title = "资金接口缺少原子且持久化的幂等保护"
                reason = "从可重放入口到资金副作用的 CFG 路径上，没有支配该副作用的原子持久化认领。"
                evidence_effect = None
            findings.append(
                self._finding(
                    endpoint,
                    mutation,
                    scenario="idempotency_missing",
                    title=title,
                    reason=reason,
                    risk_kind=risk_kind,
                    related=evidence_effect,
                    cwes=["CWE-362", "CWE-841"],
                )
            )
        return findings

    def _transaction_findings(
        self,
        endpoint: MethodModel,
        effects: tuple[Effect, ...],
        mutations: list[Effect],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        claims = [effect for effect in effects if effect.kind == "idempotency_claim" and effect.atomic and effect.durable]
        persisted_results = [effect for effect in effects if effect.kind == "idempotency_result" and effect.durable]
        for mutation in mutations:
            if mutation.kind != "finance_mutation" or mutation.store not in {"database", "memory"}:
                continue
            if not mutation.transactional:
                findings.append(
                    self._finding(
                        endpoint,
                        mutation,
                        scenario="funds_transaction_boundary",
                        title="资金状态变更缺少可证明的事务边界",
                        reason="资金持久化路径未被 @Transactional 或显式事务包围，异常可留下部分提交状态。",
                        risk_kind="missing_transaction",
                        related=None,
                        cwes=["CWE-841", "CWE-703"],
                    )
                )
                continue
            guarding = [claim for claim in claims if self._effect_dominates(claim, mutation)]
            recoverable_cross_store = any(
                self._effect_precedes(mutation, result)
                for result in persisted_results
            )
            if guarding and any(claim.store and claim.store != mutation.store for claim in guarding) and not recoverable_cross_store:
                findings.append(
                    self._finding(
                        endpoint,
                        mutation,
                        scenario="funds_transaction_boundary",
                        title="幂等认领与资金写入跨存储且缺少一致性协议",
                        reason="幂等认领和资金写入位于不同存储，单库事务不能保证二者原子提交。",
                        risk_kind="cross_store_consistency",
                        related=guarding[0],
                        cwes=["CWE-841", "CWE-662"],
                    )
                )
        return findings

    def _state_race_findings(
        self,
        endpoint: MethodModel,
        effects: tuple[Effect, ...],
        mutations: list[Effect],
    ) -> list[dict[str, Any]]:
        reads = [effect for effect in effects if effect.kind == "state_read"]
        state_cas = [effect for effect in effects if effect.kind == "state_cas"]
        findings: list[dict[str, Any]] = []
        for mutation in mutations:
            if not any(self._effect_dominates(read, mutation) for read in reads):
                continue
            if any(self._effect_dominates(cas, mutation) for cas in state_cas):
                continue
            findings.append(
                self._finding(
                    endpoint,
                    mutation,
                    scenario="funds_state_transition_race",
                    title="资金状态先读后写缺少原子状态迁移",
                    reason="状态校验与资金变更分离执行，竞争请求可能基于同一旧状态重复推进。",
                    risk_kind="state_check_then_write",
                    related=reads[0],
                    cwes=["CWE-362", "CWE-367", "CWE-841"],
                )
            )
        return findings

    def _effect_dominates(self, first: Effect, second: Effect) -> bool:
        left, right = _first_distinct_locations(first.path, second.path)
        if left is None:
            return len(first.path) <= len(second.path)
        if right is None or left.method_key != right.method_key:
            return False
        model = self.models.get(left.method_key)
        if model is None:
            return False
        return left.block_id in model.dominators.get(right.block_id, frozenset()) and (
            left.block_id != right.block_id or left.order < right.order
        )

    def _effect_precedes(self, first: Effect, second: Effect) -> bool:
        left, right = _first_distinct_locations(first.path, second.path)
        if left is None or right is None or left.method_key != right.method_key:
            return False
        model = self.models.get(left.method_key)
        if model is None:
            return False
        return left.block_id in model.dominators.get(right.block_id, frozenset()) and (
            left.block_id != right.block_id or left.order < right.order
        )

    def _finding(
        self,
        endpoint: MethodModel,
        mutation: Effect,
        *,
        scenario: str,
        title: str,
        reason: str,
        risk_kind: str,
        related: Effect | None,
        cwes: list[str],
    ) -> dict[str, Any]:
        method = endpoint.method
        source_line = method.parameters[0].line if method.parameters else method.body.start_point.row + 1
        source_snippet = method.parameters[0].snippet if method.parameters else _line(method, source_line)
        source = {
            "kind": "source",
            "file": method.file_name,
            "line": source_line,
            "label": "可重放资金请求入口",
            "snippet": source_snippet,
            "method": method.display,
        }
        path = [source]
        if related is not None:
            path.append(_public_location(related.location, "cfg_condition" if related.kind.endswith("lookup") else "dataflow_step"))
        for location in mutation.path[:-1]:
            path.append(_public_location(location, "call"))
        sink = _public_location(mutation.location, "sink")
        path.append(sink)
        dfg_edges = []
        if related is not None:
            for origin in related.origins:
                dfg_edges.append({"from": origin.label, "to": related.location.label, "key_like": origin.key_like})
        cfg_model = self.models[method.key]
        return {
            "id": "",
            "engine": "java-native-finance",
            "rule_id": f"secflow.java.native.finance.{scenario}.{risk_kind}",
            "scenario": scenario,
            "title": title,
            "record_id": "",
            "component": "",
            "severity": "HIGH",
            "cwes": cwes,
            "confidence": "high",
            "source": source,
            "sink": sink,
            "path": path,
            "ast": {
                "entry_method": method.display,
                "effect_method": mutation.location.method,
                "effect_kind": mutation.kind,
                "resolved_calls": [location.label for location in mutation.path[:-1]],
            },
            "cfg": reason,
            "cfg_graph": {
                "entry_block": cfg_model.entry,
                "effect_block": mutation.path[0].block_id,
                "node_count": len(cfg_model.blocks),
                "edge_count": len(cfg_model.edges),
                "dominance_verified": related is not None and self._effect_dominates(related, mutation),
            },
            "dfg": _dfg_description(related, mutation),
            "dfg_edges": dfg_edges,
            "evidence": mutation.location.snippet,
            "analysis_depth": max(0, len(mutation.path) - 1),
            "semantic_proof": {
                "native_cfg": True,
                "native_dfg": True,
                "interprocedural": len(mutation.path) > 1,
                "risk_kind": risk_kind,
                "transactional": mutation.transactional,
                "effect_store": mutation.store,
            },
        }


def analyze_java_finance(
    methods: dict[str, Any],
    by_class_name_arity: dict[tuple[str, str, int], list[str]],
    code_files: list[dict[str, str]],
) -> dict[str, Any]:
    return JavaFinanceAnalyzer(methods, by_class_name_arity, code_files).analyze()


def _dominators(
    blocks: dict[int, BasicBlock],
    edges: set[tuple[int, int]],
    entry: int,
) -> dict[int, frozenset[int]]:
    nodes = set(blocks)
    predecessors: dict[int, set[int]] = {node: set() for node in nodes}
    for source, target in edges:
        predecessors.setdefault(target, set()).add(source)
    dominators: dict[int, set[int]] = {node: ({entry} if node == entry else set(nodes)) for node in nodes}
    changed = True
    while changed:
        changed = False
        for node in sorted(nodes - {entry}):
            preds = predecessors.get(node, set())
            if not preds:
                updated = {node}
            else:
                common = set(nodes)
                for predecessor in preds:
                    common &= dominators[predecessor]
                updated = {node} | common
            if updated != dominators[node]:
                dominators[node] = updated
                changed = True
    return {node: frozenset(value) for node, value in dominators.items()}


def _is_unsafe_entrypoint(method: Any) -> bool:
    if method.annotations & UNSAFE_ENTRY_ANNOTATIONS:
        return True
    if "RequestMapping" in method.annotations:
        header = f"{method.modifiers}\n{_node_text(method.body, method.source)[:120]}"
        return bool(re.search(r"RequestMethod\.(?:POST|PUT|PATCH|DELETE)", header, re.IGNORECASE))
    return False


def _is_atomic_claim(name: str, context: str) -> bool:
    if ATOMIC_CLAIM_RE.match(name):
        return True
    if PERSISTENCE_RE.match(name) and re.search(r"idempot|dedup|requestrecord|operationrecord", context, re.IGNORECASE):
        return True
    return bool(STATE_CAS_RE.search(name))


def _claim_store(name: str, context: str) -> str:
    if re.search(r"redis|redisson|setnx|setifabsent|putifabsent", f"{name} {context}", re.IGNORECASE):
        return "redis"
    if re.search(r"repository|mapper|dao|jdbc|jpa|insert|save|database|record", f"{name} {context}", re.IGNORECASE):
        return "database"
    if STATE_CAS_RE.search(name):
        return "database"
    return "memory"


def _finance_effect_kind(name: str, context: str) -> tuple[str, str]:
    if READ_ONLY_RE.match(name):
        return "", ""
    if NON_FUNDS_CONTEXT_RE.search(context) and not re.search(
        r"amount|balance|debit|credit|transfer|withdraw|deposit|refund|charge|capture|settle|"
        r"payout|disburse|repay|remit|purchase|funds?",
        context,
        re.IGNORECASE,
    ):
        return "", ""
    gateway = bool(re.search(r"gateway|paymentclient|stripe|paypal|adyen|acquirer|processor", context, re.IGNORECASE))
    if gateway and (FINANCE_STRONG_MUTATION_RE.match(name) or re.match(r"^(?:execute|send|submit|process)$", name, re.IGNORECASE)):
        return "external_effect", "external"
    if FINANCE_STRONG_MUTATION_RE.match(name):
        store = "database" if re.search(r"repository|mapper|dao|jdbc|service", context, re.IGNORECASE) else "memory"
        return "finance_mutation", store
    if PERSISTENCE_RE.match(name) and FINANCE_ACTION_RE.search(context) and FINANCE_DATA_RE.search(context):
        return "finance_mutation", "database"
    return "", ""


def _is_state_read(name: str, context: str) -> bool:
    return bool(READ_ONLY_RE.match(name) and STATUS_RE.search(f"{name} {context}") and FINANCE_ACTION_RE.search(context))


def _is_key_text(value: str) -> bool:
    return bool(KEY_RE.search(re.sub(r"[^A-Za-z0-9]", "", value)))


def _key_origins(
    origins: tuple[ValueOrigin, ...],
    call_text: str,
    method: Any,
    node: Any,
) -> tuple[ValueOrigin, ...]:
    selected = [origin for origin in origins if origin.key_like]
    if selected:
        return _merge_origins(tuple(selected))
    if _is_key_text(call_text):
        return (
            ValueOrigin(
                "derived_key",
                label="幂等键表达式",
                key_like=True,
                steps=((method.file_name, node.start_point.row + 1, call_text),),
            ),
        )
    return origins


def _expr_origins(
    node: Any | None,
    environment: dict[str, tuple[ValueOrigin, ...]],
    method: Any,
) -> tuple[ValueOrigin, ...]:
    if node is None:
        return ()
    if node.type == "identifier":
        return environment.get(_node_text(node, method.source), ())
    if node.type == "method_invocation":
        name = _node_text(node.child_by_field_name("name"), method.source)
        object_node = node.child_by_field_name("object")
        object_origins = _expr_origins(object_node, environment, method)
        arguments_node = node.child_by_field_name("arguments")
        arguments = tuple(arguments_node.named_children) if arguments_node is not None else ()
        origins = _merge_origins(object_origins, *(_expr_origins(arg, environment, method) for arg in arguments))
        call_text = _node_text(node, method.source)
        key_like = _is_key_text(name) or _is_key_text(call_text)
        if name == "getHeader" and re.search(r"Idempotency-Key|X-Idempotency-Key", call_text, re.IGNORECASE):
            return (
                ValueOrigin(
                    "request_header",
                    label="Idempotency-Key",
                    key_like=True,
                    steps=((method.file_name, node.start_point.row + 1, call_text),),
                ),
            )
        if origins and key_like:
            return tuple(replace(origin, key_like=True) for origin in origins)
        return origins
    if node.type in {"string_literal", "decimal_integer_literal", "decimal_floating_point_literal", "true", "false"}:
        return ()
    return _merge_origins(*(_expr_origins(child, environment, method) for child in node.named_children))


def _append_origin_step(
    origins: tuple[ValueOrigin, ...],
    method: Any,
    node: Any,
    name: str,
) -> tuple[ValueOrigin, ...]:
    return tuple(
        replace(
            origin,
            label=name,
            key_like=origin.key_like or _is_key_text(name),
            steps=(*origin.steps, (method.file_name, node.start_point.row + 1, name)),
        )
        for origin in origins
    )


def _merge_origins(*groups: tuple[ValueOrigin, ...]) -> tuple[ValueOrigin, ...]:
    result: list[ValueOrigin] = []
    seen: set[tuple[str, int, str, bool]] = set()
    for group in groups:
        for origin in group:
            key = (origin.kind, origin.param_index, origin.label, origin.key_like)
            if key in seen:
                continue
            seen.add(key)
            result.append(origin)
    return tuple(result)


def _compact_effects(effects: Iterable[Effect]) -> tuple[Effect, ...]:
    result: list[Effect] = []
    seen: set[tuple[Any, ...]] = set()
    for effect in effects:
        key = (
            effect.kind,
            tuple((item.method_key, item.line, item.order) for item in effect.path),
            tuple((origin.kind, origin.param_index, origin.label, origin.key_like) for origin in effect.origins),
            effect.atomic,
            effect.durable,
            effect.transactional,
            effect.store,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(effect)
        if len(result) >= 512:
            break
    return tuple(result)


def _compact_calls(calls: Iterable[CallSite]) -> list[CallSite]:
    result: list[CallSite] = []
    seen: set[tuple[str, int, int, str, int]] = set()
    for call in calls:
        key = (call.location.method_key, call.location.block_id, call.location.order, call.name, call.arity)
        if key in seen:
            continue
        seen.add(key)
        result.append(call)
    return result


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, str]] = set()
    for finding in findings:
        sink = finding.get("sink") or {}
        risk_kind = str((finding.get("semantic_proof") or {}).get("risk_kind") or "")
        key = (str(finding.get("scenario") or ""), str(sink.get("file") or ""), int(sink.get("line") or 0), risk_kind)
        if key in seen:
            continue
        seen.add(key)
        copied = dict(finding)
        copied["id"] = f"native-finance-{len(result) + 1}"
        result.append(copied)
    return result


def _first_distinct_locations(
    first: tuple[Location, ...],
    second: tuple[Location, ...],
) -> tuple[Location | None, Location | None]:
    limit = min(len(first), len(second))
    index = 0
    while index < limit and _same_location(first[index], second[index]):
        index += 1
    left = first[index] if index < len(first) else None
    right = second[index] if index < len(second) else None
    return left, right


def _same_location(first: Location, second: Location) -> bool:
    return (
        first.method_key == second.method_key
        and first.block_id == second.block_id
        and first.order == second.order
    )


def _location(method: Any, block_id: int, node: Any, label: str) -> Location:
    line_number = node.start_point.row + 1
    return Location(
        method.key,
        block_id,
        node.start_byte,
        method.file_name,
        line_number,
        method.display,
        _line(method, line_number),
        label,
    )


def _public_location(location: Location, kind: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "file": location.file,
        "line": location.line,
        "label": location.label,
        "snippet": location.snippet,
        "method": location.method,
    }


def _dfg_description(related: Effect | None, mutation: Effect) -> str:
    if related is None:
        return f"可重放请求入口 -> {mutation.location.label}（未建立幂等键到原子认领的定义-使用链）"
    origins = ", ".join(origin.label for origin in related.origins) or "未知键"
    return f"{origins} -> {related.location.label} -> {mutation.location.label}"


def _line(method: Any, line_number: int) -> str:
    if line_number <= 0 or line_number > len(method.lines):
        return ""
    return method.lines[line_number - 1].strip()


def _node_text(node: Any | None, source: bytes) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _simple_type(value: str) -> str:
    cleaned = re.sub(r"<.*>", "", value or "").strip()
    return cleaned.rsplit(".", 1)[-1].replace("[]", "").strip()


def _normalized_implementation_name(value: str) -> str:
    normalized = re.sub(r"V\d+$", "", _simple_type(value), flags=re.IGNORECASE)
    normalized = re.sub(r"Impl$", "", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"^Default", "", normalized, flags=re.IGNORECASE)
    return normalized.lower()


def _descendants(node: Any, types: set[str], *, stop_at_nested_types: bool) -> Iterable[Any]:
    pending = [node]
    first = True
    while pending:
        current = pending.pop()
        if not first and current.type in types:
            yield current
        first = False
        if stop_at_nested_types and current is not node and current.type in {
            "class_declaration",
            "interface_declaration",
            "record_declaration",
            "lambda_expression",
        }:
            continue
        pending.extend(reversed(current.named_children))
