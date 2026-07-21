from __future__ import annotations

from pathlib import Path


EXCLUDED_SOURCE_PARTS = {
    ".git",
    ".gradle",
    ".idea",
    ".mvn",
    "benchmark",
    "benchmarks",
    "build",
    "dev-support",
    "dist",
    "examples",
    "fuzz",
    "fuzzing",
    "generated",
    "integration",
    "jmh",
    "node_modules",
    "perf",
    "performance",
    "playground",
    "target",
    "test",
    "tests",
}

EXCLUDED_DEEP_PACKAGE_PARTS = {
    "demo",
    "demos",
    "example",
    "sample",
    "samples",
    "tutorial",
    "tutorials",
}

EXCLUDED_SOURCE_PART_SUFFIXES = (
    "test",
    "tests",
    "testing",
    "benchmark",
    "benchmarks",
    "dunit",
    "jmh",
    "fuzz",
    "fuzzing",
    "playground",
)

EXCLUDED_SOURCE_FILE_SUFFIXES = (
    "_test.go",
    "_fuzz.go",
    "_test.py",
    "_test.rs",
    ".t.sol",
)

SEMGREP_EXCLUDE_PATTERNS = [
    "**/.git/**",
    "**/.gradle/**",
    "**/.idea/**",
    "**/.mvn/**",
    "**/build/**",
    "**/target/**",
    "**/generated/**",
    "**/dev-support/**",
    "**/examples/**",
    "**/demo/src/main/**",
    "**/demos/src/main/**",
    "**/example/src/main/**",
    "**/sample/src/main/**",
    "**/samples/src/main/**",
    "**/tutorial/src/main/**",
    "**/tutorials/src/main/**",
    "**/it/**/src/main/**",
    "**/src/integration/**",
    "**/*dunit*/**",
    "**/src/main/java/*/*/*/**/demo/**",
    "**/src/main/java/*/*/*/**/demos/**",
    "**/src/main/java/*/*/*/**/example/**",
    "**/src/main/java/*/*/*/**/sample/**",
    "**/src/main/java/*/*/*/**/samples/**",
    "**/src/main/java/*/*/*/**/tutorial/**",
    "**/src/main/java/*/*/*/**/tutorials/**",
    "**/src/test/**",
    "**/src/it/**",
    "**/src/*Test/**",
    "**/src/*Tests/**",
    "**/test/**",
    "**/tests/**",
    "**/*_test.go",
    "**/*_fuzz.go",
    "**/*fuzz*/**",
    "**/*playground*/**",
    "**/*Test/**",
    "**/*Tests/**",
    "**/*Testing/**",
    "**/benchmark/**",
    "**/benchmarks/**",
    "**/jmh/**",
    "**/perf/**",
    "**/performance/**",
]


def is_excluded_source_path(path: str | Path) -> bool:
    """Return whether a source path should be skipped for production-code auditing."""
    parts = _normalized_parts(path)
    if parts and parts[-1].endswith(EXCLUDED_SOURCE_FILE_SUFFIXES):
        return True
    for part in parts:
        if part in EXCLUDED_SOURCE_PARTS:
            return True
        if any(part.endswith(suffix) for suffix in EXCLUDED_SOURCE_PART_SUFFIXES):
            return True
    if _is_integration_test_module(parts):
        return True
    if _is_top_level_example_module(parts):
        return True
    if _has_deep_example_package(parts):
        return True
    return False


def is_analyzable_source_path(path: str | Path) -> bool:
    return not is_excluded_source_path(path)


def _normalized_parts(path: str | Path) -> list[str]:
    return [
        part.strip().lower()
        for part in Path(str(path).replace("\\", "/")).parts
        if part not in {"", ".", "..", "/"}
    ]


def _is_integration_test_module(parts: list[str]) -> bool:
    for index, part in enumerate(parts):
        if part == "it" and parts[index + 1 : index + 4] and "src" in parts[index + 1 :]:
            return True
    return False


def _is_top_level_example_module(parts: list[str]) -> bool:
    for index, part in enumerate(parts[:-1]):
        if part in EXCLUDED_DEEP_PACKAGE_PARTS and "src" in parts[index + 1 :]:
            return True
    return False


def _has_deep_example_package(parts: list[str]) -> bool:
    java_root = _java_source_root_index(parts)
    if java_root < 0:
        return False
    package_parts = parts[java_root + 1 : -1]
    for index, part in enumerate(package_parts):
        if part in EXCLUDED_DEEP_PACKAGE_PARTS and index >= 3:
            return True
    return False


def _java_source_root_index(parts: list[str]) -> int:
    for index in range(len(parts) - 2):
        if parts[index : index + 3] == ["src", "main", "java"]:
            return index + 2
    return -1
