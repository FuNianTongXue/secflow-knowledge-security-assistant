from __future__ import annotations

import warnings
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

try:
    from tree_sitter import Language, Node, Parser
except Exception:  # pragma: no cover - optional runtime dependency
    Language = None
    Node = Any
    Parser = None


@dataclass(frozen=True)
class LanguageProfile:
    id: str
    extensions: frozenset[str]
    module: str
    functions: frozenset[str]
    types: frozenset[str]
    imports: frozenset[str]
    controls: frozenset[str]
    assignments: frozenset[str]


_COMMON_CONTROLS = frozenset(
    {
        "if_statement",
        "for_statement",
        "for_in_statement",
        "while_statement",
        "do_statement",
        "switch_statement",
        "switch_expression",
        "match_expression",
        "try_statement",
        "catch_clause",
        "with_statement",
        "conditional_expression",
        "ternary_expression",
    }
)

_COMMON_ASSIGNMENTS = frozenset(
    {
        "assignment",
        "assignment_expression",
        "assignment_statement",
        "augmented_assignment",
        "short_var_declaration",
        "let_declaration",
        "init_declarator",
        "variable_declaration",
        "variable_declaration_statement",
    }
)


LANGUAGE_PROFILES: tuple[LanguageProfile, ...] = (
    LanguageProfile(
        "java",
        frozenset({".java"}),
        "tree_sitter_java",
        frozenset({"method_declaration", "constructor_declaration", "lambda_expression"}),
        frozenset({"class_declaration", "interface_declaration", "enum_declaration", "record_declaration"}),
        frozenset({"import_declaration", "package_declaration"}),
        _COMMON_CONTROLS | {"enhanced_for_statement", "synchronized_statement"},
        _COMMON_ASSIGNMENTS | {"local_variable_declaration"},
    ),
    LanguageProfile(
        "python",
        frozenset({".py"}),
        "tree_sitter_python",
        frozenset({"function_definition", "lambda"}),
        frozenset({"class_definition"}),
        frozenset({"import_statement", "import_from_statement"}),
        _COMMON_CONTROLS | {"elif_clause", "except_clause"},
        _COMMON_ASSIGNMENTS | {"named_expression"},
    ),
    LanguageProfile(
        "go",
        frozenset({".go"}),
        "tree_sitter_go",
        frozenset({"function_declaration", "method_declaration", "func_literal"}),
        frozenset({"type_declaration", "struct_type", "interface_type"}),
        frozenset({"import_declaration", "import_spec", "package_clause"}),
        _COMMON_CONTROLS | {"expression_switch_statement", "type_switch_statement", "select_statement"},
        _COMMON_ASSIGNMENTS | {"var_declaration", "const_declaration"},
    ),
    LanguageProfile(
        "c",
        frozenset({".c", ".h"}),
        "tree_sitter_c",
        frozenset({"function_definition"}),
        frozenset({"struct_specifier", "union_specifier", "enum_specifier"}),
        frozenset({"preproc_include", "preproc_def"}),
        _COMMON_CONTROLS | {"case_statement"},
        _COMMON_ASSIGNMENTS | {"declaration"},
    ),
    LanguageProfile(
        "cpp",
        frozenset({".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"}),
        "tree_sitter_cpp",
        frozenset({"function_definition", "lambda_expression"}),
        frozenset({"class_specifier", "struct_specifier", "union_specifier", "enum_specifier", "namespace_definition"}),
        frozenset({"preproc_include", "preproc_def", "using_declaration"}),
        _COMMON_CONTROLS | {"case_statement", "try_block"},
        _COMMON_ASSIGNMENTS | {"declaration", "structured_binding_declarator"},
    ),
    LanguageProfile(
        "rust",
        frozenset({".rs"}),
        "tree_sitter_rust",
        frozenset({"function_item", "closure_expression"}),
        frozenset({"struct_item", "enum_item", "trait_item", "impl_item", "type_item"}),
        frozenset({"use_declaration", "extern_crate_declaration", "mod_item"}),
        _COMMON_CONTROLS | {"if_expression", "for_expression", "while_expression", "loop_expression"},
        _COMMON_ASSIGNMENTS | {"let_declaration"},
    ),
    LanguageProfile(
        "solidity",
        frozenset({".sol"}),
        "tree_sitter_solidity",
        frozenset(
            {
                "function_definition",
                "constructor_definition",
                "modifier_definition",
                "fallback_receive_definition",
            }
        ),
        frozenset({"contract_declaration", "interface_declaration", "library_declaration", "struct_declaration", "enum_declaration"}),
        frozenset({"import_directive", "pragma_directive", "using_directive"}),
        _COMMON_CONTROLS | {"emit_statement", "revert_statement"},
        _COMMON_ASSIGNMENTS | {"state_variable_declaration"},
    ),
)

_PROFILE_BY_ID = {profile.id: profile for profile in LANGUAGE_PROFILES}
_PROFILE_BY_EXTENSION = {
    extension: profile
    for profile in LANGUAGE_PROFILES
    for extension in profile.extensions
}

_AST_PREVIEW_LIMIT = 160
_GRAPH_PREVIEW_LIMIT = 120


def language_for_file(file_name: str) -> str:
    suffix = Path(file_name).suffix.lower()
    profile = _PROFILE_BY_EXTENSION.get(suffix)
    if profile is not None:
        return profile.id
    if suffix in {".kt", ".kts"}:
        return "kotlin"
    if suffix == ".scala":
        return "scala"
    if suffix == ".groovy":
        return "groovy"
    if suffix in {".js", ".jsx"}:
        return "javascript"
    if suffix in {".ts", ".tsx"}:
        return "typescript"
    return suffix.lstrip(".") or "unknown"


def supported_flow_languages() -> list[str]:
    return [profile.id for profile in LANGUAGE_PROFILES]


def analyze_source_structure(file_name: str, content: str) -> dict[str, Any]:
    language = language_for_file(file_name)
    profile = _PROFILE_BY_ID.get(language)
    if profile is None:
        return _empty_analysis(file_name, language, "没有对应的 Tree-sitter 语法包。")
    parser = _parser_for(profile.id)
    if parser is None:
        return _empty_analysis(file_name, language, "Tree-sitter 语法包不可用。")

    source = content.encode("utf-8", errors="replace")
    tree = parser.parse(source)
    nodes = list(_walk(tree.root_node))
    imports = [_compact_text(node, source) for node in nodes if node.type in profile.imports]
    type_nodes = [node for node in nodes if node.type in profile.types]
    function_nodes = [node for node in nodes if node.type in profile.functions]
    controls = [node for node in nodes if node.type in profile.controls]
    assignments = [node for node in nodes if node.type in profile.assignments]
    cfg_nodes = [node for node in nodes if _is_cfg_node(node, profile)]
    ast_graph = _ast_graph(nodes, source)
    cfg_graph = _cfg_graph(cfg_nodes, function_nodes, controls, source)
    dfg_graph = _dfg_graph(assignments, profile, source)

    return {
        "file": file_name,
        "language": language,
        "parser": "tree-sitter",
        "parse_error": bool(tree.root_node.has_error),
        "ast_node_count": len(nodes),
        "imports": list(dict.fromkeys(item for item in imports if item))[:30],
        "types": list(dict.fromkeys(_declaration_name(node, source) for node in type_nodes if _declaration_name(node, source)))[:30],
        "functions": list(dict.fromkeys(_declaration_name(node, source) for node in function_nodes if _declaration_name(node, source)))[:60],
        "control_count": len(controls),
        "assignment_count": len(assignments),
        "cfg_node_count": cfg_graph["node_count"],
        "cfg_edge_count": cfg_graph["edge_count"],
        "dfg_edge_count": dfg_graph["edge_count"],
        "ast_graph": ast_graph,
        "cfg_graph": cfg_graph,
        "dfg_graph": dfg_graph,
    }


def control_flow_steps(
    file_name: str,
    content: str,
    source_line: int,
    sink_line: int,
) -> list[dict[str, Any]]:
    profile = _PROFILE_BY_ID.get(language_for_file(file_name))
    parser = _parser_for(profile.id) if profile else None
    if profile is None or parser is None or source_line <= 0 or sink_line <= 0:
        return []
    source = content.encode("utf-8", errors="replace")
    tree = parser.parse(source)
    lower, upper = sorted((source_line, sink_line))
    candidates: list[Node] = []
    for node in _walk(tree.root_node):
        if node.type not in profile.controls:
            continue
        start = node.start_point.row + 1
        end = node.end_point.row + 1
        if start <= upper <= end and end >= lower:
            candidates.append(node)
    candidates.sort(key=lambda node: (node.start_point.row, -(node.end_point.row - node.start_point.row)))
    return [
        {
            "kind": "cfg_condition",
            "file": file_name,
            "line": node.start_point.row + 1,
            "label": f"{profile.id} {node.type} 控制条件",
            "snippet": _compact_text(node, source, limit=240),
        }
        for node in candidates[:8]
    ]


@lru_cache(maxsize=None)
def _parser_for(language_id: str) -> Any | None:
    if Parser is None or Language is None:
        return None
    profile = _PROFILE_BY_ID.get(language_id)
    if profile is None:
        return None
    try:
        module = __import__(profile.module)
        # tree-sitter-solidity 1.2.x still exposes a pointer integer; py-tree-sitter
        # 0.25 supports it but emits a compatibility deprecation warning.
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="int argument support is deprecated", category=DeprecationWarning)
            return Parser(Language(module.language()))
    except Exception:  # noqa: BLE001 - missing optional grammar must degrade cleanly
        return None


def _empty_analysis(file_name: str, language: str, error: str) -> dict[str, Any]:
    return {
        "file": file_name,
        "language": language,
        "parser": "unavailable",
        "parse_error": True,
        "error": error,
        "ast_node_count": 0,
        "imports": [],
        "types": [],
        "functions": [],
        "control_count": 0,
        "assignment_count": 0,
        "cfg_node_count": 0,
        "cfg_edge_count": 0,
        "dfg_edge_count": 0,
        "ast_graph": {"node_count": 0, "edge_count": 0, "nodes": [], "edges": [], "truncated": False},
        "cfg_graph": {"node_count": 0, "edge_count": 0, "nodes": [], "edges": [], "truncated": False},
        "dfg_graph": {"node_count": 0, "edge_count": 0, "nodes": [], "edges": [], "truncated": False},
    }


def _walk(root: Node) -> Iterable[Node]:
    stack = [root]
    while stack:
        node = stack.pop()
        if node.is_named:
            yield node
        stack.extend(reversed(node.named_children))


def _compact_text(node: Node, source: bytes, *, limit: int = 320) -> str:
    text = source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    return " ".join(text.split())[:limit]


def _declaration_name(node: Node, source: bytes) -> str:
    direct = node.child_by_field_name("name")
    if direct is not None:
        return _compact_text(direct, source, limit=120)
    declarator = node.child_by_field_name("declarator")
    if declarator is not None:
        nested = declarator
        for _ in range(8):
            next_declarator = nested.child_by_field_name("declarator")
            if next_declarator is None:
                break
            nested = next_declarator
        if nested.type in {"identifier", "field_identifier", "type_identifier"}:
            return _compact_text(nested, source, limit=120)
        identifiers = [item for item in _walk(declarator) if item.type in {"identifier", "field_identifier", "type_identifier"}]
        if identifiers:
            return _compact_text(identifiers[0], source, limit=120)
    identifiers = [item for item in node.named_children if item.type in {"identifier", "type_identifier"}]
    return _compact_text(identifiers[0], source, limit=120) if identifiers else node.type


def _is_cfg_node(node: Node, profile: LanguageProfile) -> bool:
    return (
        node.type in profile.functions
        or node.type in profile.controls
        or node.type.endswith("_statement")
        or node.type in {"return_expression", "break_expression", "continue_expression", "expression_statement", "match_arm"}
    )


def _ast_graph(nodes: list[Node], source: bytes) -> dict[str, Any]:
    node_ids = {_node_key(node): f"ast-{index}" for index, node in enumerate(nodes)}
    preview = nodes[:_AST_PREVIEW_LIMIT]
    preview_ids = {_node_key(node) for node in preview}
    edges = [
        {"from": node_ids[_node_key(node.parent)], "to": node_ids[_node_key(node)], "kind": "child"}
        for node in preview
        if node.parent is not None and _node_key(node.parent) in preview_ids
    ]
    return {
        "node_count": len(nodes),
        "edge_count": max(0, len(nodes) - 1),
        "nodes": [
            {
                "id": node_ids[_node_key(node)],
                "kind": node.type,
                "line": node.start_point.row + 1,
                "end_line": node.end_point.row + 1,
                "snippet": _compact_text(node, source, limit=120),
            }
            for node in preview
        ],
        "edges": edges,
        "truncated": len(nodes) > len(preview),
    }


def _cfg_graph(
    cfg_nodes: list[Node],
    function_nodes: list[Node],
    controls: list[Node],
    source: bytes,
) -> dict[str, Any]:
    terminal_types = {"return_statement", "return_expression", "break_statement", "continue_statement"}
    control_types = {node.type for node in controls}
    relevant_descendant_types = control_types | terminal_types
    ordered = sorted(
        (
            node
            for node in cfg_nodes
            if not (
                node.type == "expression_statement"
                and any(child.type in relevant_descendant_types for child in list(_walk(node))[1:])
            )
        ),
        key=lambda node: (node.start_byte, -node.end_byte, node.type),
    )
    node_ids = {_node_key(node): f"cfg-{index}" for index, node in enumerate(ordered)}
    function_ids = {_node_key(node) for node in function_nodes}

    def owner(node: Node) -> tuple[int, int, str] | None:
        if _node_key(node) in function_ids:
            return _node_key(node)
        parent = node.parent
        while parent is not None:
            if _node_key(parent) in function_ids:
                return _node_key(parent)
            parent = parent.parent
        return None

    groups: dict[tuple[int, int, str] | None, list[Node]] = {}
    for node in ordered:
        groups.setdefault(owner(node), []).append(node)

    edges: list[dict[str, str]] = []
    edge_keys: set[tuple[str, str, str]] = set()

    def add_edge(start: Node, end: Node, kind: str) -> None:
        if _node_key(start) == _node_key(end):
            return
        key = (node_ids[_node_key(start)], node_ids[_node_key(end)], kind)
        if key in edge_keys:
            return
        edge_keys.add(key)
        edges.append({"from": key[0], "to": key[1], "kind": kind})

    for members in groups.values():
        for current, following in zip(members, members[1:]):
            if current.type not in terminal_types and current.type not in control_types:
                add_edge(current, following, "next")

    for control in controls:
        members = groups.get(owner(control), [])
        contained = [
            node
            for node in members
            if _node_key(node) != _node_key(control) and _is_descendant(node, control)
        ]
        following = next((node for node in members if node.start_byte >= control.end_byte), None)
        if "switch" in control.type or control.type == "match_expression":
            cases = [node for node in contained if "case" in node.type or node.type == "match_arm"]
            for case in cases:
                add_edge(control, case, "case")
            if not cases and contained:
                add_edge(control, contained[0], "case")
        elif control.type.startswith("if") or control.type in {"conditional_expression", "ternary_expression"}:
            consequence = _first_field(control, "consequence", "body")
            alternative = _first_field(control, "alternative")
            true_target = _first_cfg_member(consequence, contained) or (contained[0] if contained else None)
            false_target = _first_cfg_member(alternative, contained) or following
            if true_target is not None:
                add_edge(control, true_target, "branch_true")
            if false_target is not None:
                add_edge(control, false_target, "branch_false")
        else:
            body = _first_field(control, "body")
            target = _first_cfg_member(body, contained) or (contained[0] if contained else None)
            if target is not None:
                add_edge(control, target, "branch_true")
            if following is not None:
                add_edge(control, following, "branch_false")
        if contained and _is_loop_control(control) and contained[-1].type not in terminal_types:
            add_edge(contained[-1], control, "loop_back")

    preview = ordered[:_GRAPH_PREVIEW_LIMIT]
    preview_ids = {node_ids[_node_key(node)] for node in preview}
    preview_edges = [
        edge
        for edge in edges
        if edge["from"] in preview_ids and edge["to"] in preview_ids
    ][:_GRAPH_PREVIEW_LIMIT]
    return {
        "node_count": len(ordered),
        "edge_count": len(edges),
        "nodes": [
            {
                "id": node_ids[_node_key(node)],
                "kind": node.type,
                "line": node.start_point.row + 1,
                "end_line": node.end_point.row + 1,
                "snippet": _compact_text(node, source, limit=160),
            }
            for node in preview
        ],
        "edges": preview_edges,
        "truncated": len(ordered) > len(preview) or len(edges) > len(preview_edges),
    }


def _dfg_graph(assignments: list[Node], profile: LanguageProfile, source: bytes) -> dict[str, Any]:
    graph_nodes: dict[tuple[str, str], dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    edge_keys: set[tuple[str, str, int, str]] = set()

    for assignment in assignments:
        left, right = _assignment_sides(assignment, profile)
        if left is None or right is None:
            continue
        targets = _identifier_names(left, source)
        if not targets:
            continue
        source_identifiers = _identifier_names(right, source)
        sources = source_identifiers or [_compact_text(right, source, limit=120) or "<expression>"]
        scope = _scope_name(assignment, profile, source)
        line = assignment.start_point.row + 1
        for name in sources:
            key = (scope, name)
            graph_nodes.setdefault(
                key,
                {
                    "id": f"dfg-{len(graph_nodes)}",
                    "name": name,
                    "scope": scope,
                    "kind": "variable" if source_identifiers else "expression",
                },
            )
        for name in targets:
            key = (scope, name)
            graph_nodes.setdefault(
                key,
                {"id": f"dfg-{len(graph_nodes)}", "name": name, "scope": scope, "kind": "variable"},
            )
        for source_name in sources:
            for target_name in targets:
                source_id = graph_nodes[(scope, source_name)]["id"]
                target_id = graph_nodes[(scope, target_name)]["id"]
                key = (source_id, target_id, line, assignment.type)
                if key in edge_keys:
                    continue
                edge_keys.add(key)
                edges.append(
                    {
                        "from": source_id,
                        "to": target_id,
                        "kind": assignment.type,
                        "line": line,
                        "expression": _compact_text(assignment, source, limit=180),
                    }
                )

    nodes = list(graph_nodes.values())
    preview_nodes = nodes[:_GRAPH_PREVIEW_LIMIT]
    preview_ids = {node["id"] for node in preview_nodes}
    preview_edges = [
        edge
        for edge in edges
        if edge["from"] in preview_ids and edge["to"] in preview_ids
    ][:_GRAPH_PREVIEW_LIMIT]
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": preview_nodes,
        "edges": preview_edges,
        "truncated": len(nodes) > len(preview_nodes) or len(edges) > len(preview_edges),
    }


def _assignment_sides(node: Node, profile: LanguageProfile) -> tuple[Node | None, Node | None]:
    left = next(
        (node.child_by_field_name(field) for field in ("left", "pattern", "name", "declarator") if node.child_by_field_name(field) is not None),
        None,
    )
    right = next(
        (node.child_by_field_name(field) for field in ("right", "value") if node.child_by_field_name(field) is not None),
        None,
    )
    if left is None and profile.id == "solidity":
        declarations = [child for child in _walk(node) if child.type in {"variable_declaration", "state_variable_declaration"}]
        if declarations:
            left = declarations[0].child_by_field_name("name") or declarations[0]
    return left, right


def _first_field(node: Node, *names: str) -> Node | None:
    return next((value for name in names if (value := node.child_by_field_name(name)) is not None), None)


def _first_cfg_member(root: Node | None, members: list[Node]) -> Node | None:
    if root is None:
        return None
    root_key = _node_key(root)
    return next(
        (
            member
            for member in members
            if _node_key(member) == root_key or _is_descendant(member, root)
        ),
        None,
    )


def _identifier_names(node: Node | None, source: bytes) -> list[str]:
    if node is None:
        return []
    names = [
        _compact_text(child, source, limit=120)
        for child in _walk(node)
        if child.type in {"identifier", "field_identifier", "property_identifier", "package_identifier"}
    ]
    return list(dict.fromkeys(name for name in names if name))


def _scope_name(node: Node, profile: LanguageProfile, source: bytes) -> str:
    parent = node.parent
    while parent is not None:
        if parent.type in profile.functions:
            return _declaration_name(parent, source)
        parent = parent.parent
    return "<module>"


def _is_loop_control(node: Node) -> bool:
    return "loop" in node.type or node.type.startswith(("for", "while", "do_"))


def _is_descendant(node: Node, ancestor: Node) -> bool:
    ancestor_key = _node_key(ancestor)
    parent = node.parent
    while parent is not None:
        if _node_key(parent) == ancestor_key:
            return True
        parent = parent.parent
    return False


def _node_key(node: Node) -> tuple[int, int, str]:
    return (node.start_byte, node.end_byte, node.type)
