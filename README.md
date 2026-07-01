# SecFlow Knowledge Security Assistant

**Author:** ShenSiQi

SecFlow Knowledge Security Assistant is a simplified AI security knowledge-base assistant with a LangGraph workflow, a FastAPI backend, and a lightweight web UI.

It focuses on:

- AI security Q&A for vulnerability and security knowledge.
- LangGraph-based assistant routing and execution trace.
- CVE vulnerability collection configuration.
- GitHub Advisory collection configuration.
- Local JSON knowledge storage for quick deployment and testing.

## License

This repository is publicly visible for source review and evaluation, but it is **not an OSI open-source license**.

The source code is released under the **SecFlow Source-Available Commercial Non-Redistribution License**. You may read, run, and evaluate the code. Redistribution, resale, sublicensing, SaaS resale, or republishing is not allowed without written commercial permission from ShenSiQi.

See [LICENSE](./LICENSE).

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 18081
```

Open:

```text
http://127.0.0.1:18081
```

## Features

### Knowledge Assistant

The assistant runs a compact LangGraph workflow:

```text
classify_query -> retrieve_local_knowledge -> fetch_live_vulnerability -> compose_answer
```

If LangGraph is unavailable, the backend falls back to the same deterministic sequential flow.

### CVE Collector

The CVE collector keeps configuration for:

- NVD API URL
- NVD API Key
- Target collection name
- Severity filter
- Deduplication key
- Max results
- Enable/disable flag

### GitHub Advisory Collector

The GitHub Advisory collector keeps configuration for:

- GitHub Advisory API URL
- GitHub token
- Target collection name
- Severity filter
- Ecosystem filter
- Deduplication key
- Max results
- Enable/disable flag

## API Overview

```text
GET    /health
GET    /api/config
PATCH  /api/config/{collector_id}
POST   /api/config/{collector_id}/test
POST   /api/collect/{collector_id}
GET    /api/vulnerabilities
POST   /api/ask
GET    /api/graph
```

Collector IDs:

```text
cve
github_advisory
```

## Data Storage

Runtime data is stored in:

```text
data/state.json
```

This file is ignored by Git so API keys and runtime records are not committed.

## Security Notes

- Secrets are masked in API responses.
- Collector tokens are stored only in local runtime state.
- No external database is required.
- Public repository visibility does not grant redistribution rights.

