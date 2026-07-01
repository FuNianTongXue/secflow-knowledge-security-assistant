#!/usr/bin/env bash
set -euo pipefail

python -m py_compile app/*.py
python - <<'PY'
from app.main import app
from app.graph import knowledge_graph

assert app.title == "SecFlow Knowledge Security Assistant"
result = knowledge_graph.invoke("Explain CVE-2021-44228", 5)
assert result["mode"] == "vulnerability_lookup"
assert result["records"]
print("smoke-ok")
PY

