from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    from tree_sitter import Language, Node, Parser
    import tree_sitter_go
except Exception:  # pragma: no cover - optional runtime dependency
    Language = None
    Node = Any
    Parser = None
    tree_sitter_go = None


_CONTEXT_RE = re.compile(
    r"(?P<context>[A-Za-z_]\w*)\s*,\s*(?P<cancel>[A-Za-z_]\w*|_)\s*(?::=|=)\s*"
    r"context\.(?P<kind>WithCancel(?:Cause)?|WithTimeout(?:Cause)?|WithDeadline(?:Cause)?)\s*\("
)
_DECLARED_INTEGER_RE = re.compile(
    r"\bvar\s+(?P<name>[A-Za-z_]\w*)\s+(?P<type>u?int(?:8|16|32|64)?)\s*=\s*(?P<value>[^\n;]+)"
)
_ASSIGNED_INTEGER_RE = re.compile(
    r"(?m)^\s*(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<value>"
    r"[-+]?(?:0[xX][0-9A-Fa-f]+|\d+)|math\.(?:Max|Min)(?:U?Int)(?:8|16|32|64)?)\s*(?:$|;|//)"
)
_CONVERSION_RE = re.compile(
    r"\b(?P<target>u?int(?:8|16|32|64))\s*\(\s*(?P<value>"
    r"[A-Za-z_]\w*|[-+]?(?:0[xX][0-9A-Fa-f]+|\d+)|math\.(?:Max|Min)(?:U?Int)(?:8|16|32|64)?)\s*\)"
)
_MAKE_SLICE_RE = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*)\s*(?::=|=)\s*make\s*\(\s*\[\][^,]+,\s*"
    r"(?P<length>\d+)\s*(?:,\s*(?P<capacity>\d+)\s*)?\)"
)
_ARRAY_RE = re.compile(r"\bvar\s+(?P<name>[A-Za-z_]\w*)\s*\[\s*(?P<length>\d+)\s*\][^\n]+")
_NOSEC_RE = re.compile(r"#\s*nosec\b|nolint(?::[^\s]+)?", flags=re.IGNORECASE)


@dataclass(frozen=True)
class _SequenceBounds:
    length: int
    capacity: int


def analyze_go_semantics(code_files: list[dict[str, str]]) -> dict[str, Any]:
    parser = _parser()
    if parser is None:
        return {
            "status": "unavailable",
            "findings": [],
            "diagnostics": ["Go 语义分析器缺少 Tree-sitter Go 语法包。"],
        }

    findings: list[dict[str, Any]] = []
    diagnostics: list[str] = []
    for code_file in code_files:
        file_name = str(code_file.get("file_name") or "")
        if Path(file_name).suffix.lower() != ".go":
            continue
        content = str(code_file.get("content") or "")
        source = content.encode("utf-8", errors="replace")
        tree = parser.parse(source)
        if tree.root_node.has_error:
            diagnostics.append(f"{file_name}: Go 语义分析遇到语法错误，结果可能不完整。")
        functions = [
            node
            for node in _walk(tree.root_node)
            if node.type in {"function_declaration", "method_declaration", "func_literal"}
        ]
        for function in functions:
            body = function.child_by_field_name("body") or function
            function_text = source[body.start_byte : body.end_byte].decode("utf-8", errors="replace")
            base_line = body.start_point.row + 1
            findings.extend(_context_findings(file_name, content, function_text, base_line))
            findings.extend(_integer_findings(file_name, content, function_text, base_line))
            findings.extend(_bounds_findings(file_name, content, function_text, base_line))

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for finding in findings:
        sink = finding.get("sink") or {}
        key = (str(finding.get("rule_id") or ""), str(sink.get("file") or ""), int(sink.get("line") or 0))
        if key in seen:
            continue
        seen.add(key)
        finding["id"] = f"go-semantic-{len(deduped) + 1}"
        deduped.append(finding)
    return {
        "status": "completed",
        "findings": deduped,
        "diagnostics": diagnostics,
    }


def _context_findings(file_name: str, content: str, text: str, base_line: int) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for match in _CONTEXT_RE.finditer(text):
        line = base_line + text.count("\n", 0, match.start())
        if _is_suppressed(content, line):
            continue
        cancel = match.group("cancel")
        remainder = text[match.end() :]
        if cancel != "_":
            called = re.search(rf"\b(?:defer\s+)?{re.escape(cancel)}\s*\(", remainder)
            returned = re.search(rf"\breturn\b[^\n]*\b{re.escape(cancel)}\b", remainder)
            if called or returned:
                continue
        snippet = _line(content, line)
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.context-cancel-leak",
                scenario="resource_exhaustion",
                title="context cancel 函数未调用",
                cwes=["CWE-400"],
                severity="medium",
                confidence="high" if cancel == "_" else "medium",
                file_name=file_name,
                line=line,
                snippet=snippet,
                dfg=f"context.{match.group('kind')} -> {cancel} -> 未调用/未返回",
                remediation="创建 context 后立即 defer cancel()，或把 cancel 返回给明确负责释放的调用方。",
            )
        )
    return findings


def _integer_findings(file_name: str, content: str, text: str, base_line: int) -> list[dict[str, Any]]:
    values: dict[str, int] = {}
    source_types: dict[str, str] = {}
    for match in _DECLARED_INTEGER_RE.finditer(text):
        value = _integer_value(match.group("value").strip())
        if value is not None:
            values[match.group("name")] = value
            source_types[match.group("name")] = match.group("type")
    for match in _ASSIGNED_INTEGER_RE.finditer(text):
        value = _integer_value(match.group("value").strip())
        if value is not None:
            values[match.group("name")] = value

    findings: list[dict[str, Any]] = []
    for match in _CONVERSION_RE.finditer(text):
        target = match.group("target")
        raw_value = match.group("value")
        value = values.get(raw_value)
        if value is None:
            value = _integer_value(raw_value)
        if value is None:
            continue
        lower, upper = _integer_bounds(target)
        if lower <= value <= upper:
            continue
        line = base_line + text.count("\n", 0, match.start())
        if _is_suppressed(content, line):
            continue
        source_type = source_types.get(raw_value, "constant")
        findings.append(
            _finding(
                rule_id="secflow.go.semantic.integer-conversion-overflow",
                scenario="integer_overflow",
                title="整数窄化转换确定超出目标范围",
                cwes=["CWE-190"],
                severity="high",
                confidence="high",
                file_name=file_name,
                line=line,
                snippet=_line(content, line),
                dfg=f"{raw_value}({source_type})={value} -> {target} 范围 [{lower}, {upper}]",
                remediation="转换前显式检查上下界，超界时返回错误；避免把宽整数直接转换为窄整数。",
            )
        )
    return findings


def _bounds_findings(file_name: str, content: str, text: str, base_line: int) -> list[dict[str, Any]]:
    sequences: dict[str, _SequenceBounds] = {}
    constants: dict[str, int] = {}
    findings: list[dict[str, Any]] = []
    lines = text.splitlines()
    for offset, source_line in enumerate(lines):
        line = base_line + offset
        for match in _MAKE_SLICE_RE.finditer(source_line):
            length = int(match.group("length"))
            capacity = int(match.group("capacity") or length)
            sequences[match.group("name")] = _SequenceBounds(length=length, capacity=capacity)
        for match in _ARRAY_RE.finditer(source_line):
            length = int(match.group("length"))
            sequences[match.group("name")] = _SequenceBounds(length=length, capacity=length)
        assigned = _ASSIGNED_INTEGER_RE.match(source_line)
        if assigned and (value := _integer_value(assigned.group("value"))) is not None:
            constants[assigned.group("name")] = value

        if _is_suppressed(content, line) or _has_nearby_length_guard(lines, offset):
            continue
        for name, bounds in sequences.items():
            index_re = re.compile(rf"\b{re.escape(name)}\s*\[\s*(?P<index>[^\]:]+)\s*\]")
            for match in index_re.finditer(source_line):
                index = _resolved_integer(match.group("index"), constants)
                if index is None or 0 <= index < bounds.length:
                    continue
                findings.append(
                    _finding(
                        rule_id="secflow.go.semantic.static-index-out-of-bounds",
                        scenario="memory_safety",
                        title="静态索引确定超出序列边界",
                        cwes=["CWE-118"],
                        severity="high",
                        confidence="high",
                        file_name=file_name,
                        line=line,
                        snippet=_line(content, line),
                        dfg=f"{name} 长度={bounds.length} -> index={index}",
                        remediation="访问前验证 0 <= index < len(slice)，并确保校验覆盖同一执行分支。",
                    )
                )
            slice_re = re.compile(rf"\b{re.escape(name)}\s*\[\s*:\s*(?P<high>[^\]:]+)\s*\]")
            for match in slice_re.finditer(source_line):
                high = _resolved_integer(match.group("high"), constants)
                if high is None or 0 <= high <= bounds.capacity:
                    continue
                findings.append(
                    _finding(
                        rule_id="secflow.go.semantic.static-slice-out-of-bounds",
                        scenario="memory_safety",
                        title="静态切片上界确定超过容量",
                        cwes=["CWE-118"],
                        severity="high",
                        confidence="high",
                        file_name=file_name,
                        line=line,
                        snippet=_line(content, line),
                        dfg=f"{name} capacity={bounds.capacity} -> high={high}",
                        remediation="切片前验证上界不超过 cap(slice)，并限制来自外部的边界值。",
                    )
                )
    return findings


def _finding(
    *,
    rule_id: str,
    scenario: str,
    title: str,
    cwes: list[str],
    severity: str,
    confidence: str,
    file_name: str,
    line: int,
    snippet: str,
    dfg: str,
    remediation: str,
) -> dict[str, Any]:
    source = {"kind": "source", "file": file_name, "line": line, "label": title, "snippet": snippet}
    sink = {"kind": "sink", "file": file_name, "line": line, "label": title, "snippet": snippet}
    return {
        "id": "",
        "engine": "go-semantic-analysis",
        "rule_id": rule_id,
        "scenario": scenario,
        "title": title,
        "record_id": "",
        "component": "Go standard library",
        "severity": severity,
        "cwes": cwes,
        "confidence": confidence,
        "source": source,
        "sink": sink,
        "path": [source, sink],
        "ast": {"parser": "tree-sitter", "language": "go"},
        "cfg": "函数内确定路径；需要命中的释放、范围或边界保护未出现。",
        "dfg": dfg,
        "evidence": snippet,
        "remediation": remediation,
        "fixed_snippet": "",
    }


def _parser() -> Any | None:
    if Parser is None or Language is None or tree_sitter_go is None:
        return None
    try:
        return Parser(Language(tree_sitter_go.language()))
    except Exception:  # noqa: BLE001
        return None


def _walk(root: Node) -> Iterable[Node]:
    stack = [root]
    while stack:
        node = stack.pop()
        if node.is_named:
            yield node
        stack.extend(reversed(node.named_children))


def _integer_value(value: str) -> int | None:
    normalized = value.strip().replace("_", "")
    named = {
        "math.MaxUint8": 2**8 - 1,
        "math.MaxUint16": 2**16 - 1,
        "math.MaxUint32": 2**32 - 1,
        "math.MaxUint64": 2**64 - 1,
        "math.MaxInt8": 2**7 - 1,
        "math.MaxInt16": 2**15 - 1,
        "math.MaxInt32": 2**31 - 1,
        "math.MaxInt64": 2**63 - 1,
        "math.MinInt8": -(2**7),
        "math.MinInt16": -(2**15),
        "math.MinInt32": -(2**31),
        "math.MinInt64": -(2**63),
    }
    if normalized in named:
        return named[normalized]
    try:
        return int(normalized, 0)
    except ValueError:
        return None


def _integer_bounds(integer_type: str) -> tuple[int, int]:
    unsigned = integer_type.startswith("uint")
    bits = int(integer_type.removeprefix("uint").removeprefix("int"))
    return (0, 2**bits - 1) if unsigned else (-(2 ** (bits - 1)), 2 ** (bits - 1) - 1)


def _resolved_integer(value: str, constants: dict[str, int]) -> int | None:
    normalized = value.strip()
    return constants.get(normalized, _integer_value(normalized))


def _has_nearby_length_guard(lines: list[str], offset: int) -> bool:
    context = "\n".join(lines[max(0, offset - 4) : offset + 1])
    return bool(re.search(r"\bif\b[^\n]*\blen\s*\(", context))


def _is_suppressed(content: str, line: int) -> bool:
    lines = content.splitlines()
    context = "\n".join(lines[max(0, line - 3) : min(len(lines), line + 1)])
    return bool(_NOSEC_RE.search(context))


def _line(content: str, line: int) -> str:
    lines = content.splitlines()
    return lines[line - 1].strip() if 0 < line <= len(lines) else ""
