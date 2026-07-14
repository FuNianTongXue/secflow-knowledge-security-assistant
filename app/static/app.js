const state = {
  config: null,
  userId: localStorage.getItem("secflowUserId") || "default",
  sessionId: localStorage.getItem("secflowSessionId") || newSessionId(),
};

localStorage.setItem("secflowUserId", state.userId);
localStorage.setItem("secflowSessionId", state.sessionId);

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

function newSessionId() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  return `session-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail || payload.message || `HTTP ${response.status}`);
  }
  return payload.data;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function loadConfig() {
  state.config = await api("/api/config");
  fillCollector("cve", state.config.collectors.cve);
  fillCollector("github_advisory", state.config.collectors.github_advisory);
  renderRecords(state.config.records, state.config.stats);
  renderRuntime(state.config.runtime || {});
}

function fillCollector(id, config) {
  const form = $(`form[data-collector="${id}"]`);
  if (!form || !config) return;
  form.enabled.checked = Boolean(config.enabled);
  form.api_url.value = config.api_url || "";
  if (form.api_key) form.api_key.value = "";
  if (form.token) form.token.value = "";
  form.collection_name.value = config.collection_name || "";
  form.severity_filter.value = (config.severity_filter || []).join(",");
  if (form.ecosystem) form.ecosystem.value = config.ecosystem || "";
  form.max_results.value = config.max_results || 20;
  form.sync_interval_minutes.value = config.sync_interval_minutes || 60;
  $(".status", form).textContent = config.last_test?.message || config.last_collect?.message || "";
}

function payloadFromForm(form) {
  const severity = form.severity_filter.value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const payload = {
    enabled: form.enabled.checked,
    api_url: form.api_url.value.trim(),
    collection_name: form.collection_name.value.trim(),
    severity_filter: severity,
    max_results: Number(form.max_results.value || 20),
    sync_interval_minutes: Number(form.sync_interval_minutes.value || 60),
  };
  if (form.api_key && form.api_key.value.trim()) payload.api_key = form.api_key.value.trim();
  if (form.token && form.token.value.trim()) payload.token = form.token.value.trim();
  if (form.ecosystem) payload.ecosystem = form.ecosystem.value.trim();
  return payload;
}

async function saveCollector(form) {
  const id = form.dataset.collector;
  const result = await api(`/api/config/${id}`, {
    method: "PATCH",
    body: JSON.stringify(payloadFromForm(form)),
  });
  $(".status", form).textContent = result.message;
  await loadConfig();
}

async function collectorAction(form, action) {
  const id = form.dataset.collector;
  const target = $(".status", form);
  target.textContent = action === "test" ? "正在验证..." : "正在采集...";
  const path = action === "test" ? `/api/config/${id}/test` : `/api/collect/${id}`;
  const result = await api(path, { method: "POST" });
  target.textContent = result.message || "已完成";
  await loadConfig();
}

async function askAssistant(event) {
  event.preventDefault();
  const question = $("#question").value.trim();
  if (!question) return;
  $("#answer").textContent = "正在读取长期记忆并调用安全专家模型...";
  renderTrace([
    { node: "load_memory_context", message: "正在读取长期记忆...", status: "running", time: "" },
    { node: "call_llm", message: "正在判断是否需要漏洞检索...", status: "pending", time: "" },
  ]);
  const result = await api("/api/ask", {
    method: "POST",
    body: JSON.stringify({
      question,
      top_k: Number($("#topK").value || 5),
      user_id: state.userId,
      session_id: state.sessionId,
    }),
  });
  renderAnswer(result);
  await refreshRuntime();
}

async function refreshRuntime() {
  try {
    renderRuntime(await api("/api/runtime"));
  } catch (error) {
    $("#runtimeStatus").textContent = error.message;
  }
}

function renderRuntime(runtime) {
  const memory = runtime.memory || {};
  const llm = runtime.llm || {};
  const memoryText = `长期记忆 · ${memory.backend || "json"} · ${memory.historyCount || 0} 条`;
  const llmText = llm.configured ? `模型可用 · ${llm.model || "-"}` : `模型未就绪 · ${llm.message || "-"}`;
  $("#runtimeStatus").innerHTML = `
    <span class="stat-pill ${llm.configured ? "ok" : "warn"}">${escapeHtml(llmText)}</span>
    <span class="stat-pill">${escapeHtml(memoryText)}</span>
  `;
}

function renderAnswer(result) {
  $("#answer").classList.remove("empty");
  const card = result.vulnerability_card || null;
  if (card) {
    $("#answer").innerHTML = renderVulnerabilityCard(card);
    renderTrace(result.trace || []);
    return;
  }
  const fields = result.fields || {};
  $("#answer").innerHTML = `
    <b>${escapeHtml(modeLabel(result.mode || "security_knowledge"))}</b>
    <p>${escapeHtml(result.summary || "")}</p>
    <div class="meta-grid">
      ${Object.entries(fields)
        .map(([key, value]) => `<span><b>${escapeHtml(key)}</b>${escapeHtml(value)}</span>`)
        .join("")}
    </div>
  `;
  renderTrace(result.trace || []);
}

function severityMeta(value) {
  const normalized = String(value || "未知").trim().toUpperCase();
  const map = {
    CRITICAL: { label: "严重", tone: "critical" },
    SEVERE: { label: "严重", tone: "critical" },
    严重: { label: "严重", tone: "critical" },
    HIGH: { label: "高危", tone: "high" },
    高危: { label: "高危", tone: "high" },
    MEDIUM: { label: "中危", tone: "medium" },
    MODERATE: { label: "中危", tone: "medium" },
    中危: { label: "中危", tone: "medium" },
    LOW: { label: "低危", tone: "low" },
    低危: { label: "低危", tone: "low" },
  };
  return map[normalized] || { label: "未知", tone: "unknown" };
}

function renderVulnerabilityCard(card) {
  const severity = severityMeta(card["严重等级"]);
  const textFields = [
    "漏洞编号",
    "漏洞名称",
    "漏洞描述",
    "CVSS评分",
    "涉及版本",
    "修复版本",
    "修复方案",
    "缓释措施",
  ];
  return `
    <section class="vulnerability-card severity-${severity.tone}">
      <header class="vulnerability-card__head">
        <div>
          <span>安全知识分析</span>
          <h3>${escapeHtml(card["漏洞编号"] || "漏洞详情")}</h3>
        </div>
        <span class="severity-badge severity-badge--${severity.tone}">${escapeHtml(severity.label)}</span>
      </header>
      <div class="vulnerability-card__grid">
        ${textFields
          .map(
            (key) => `
              <div class="vulnerability-field vulnerability-field--${key === "漏洞描述" || key === "修复方案" || key === "缓释措施" ? "wide" : "compact"}">
                <span>${escapeHtml(key)}</span>
                <b>${escapeHtml(card[key] ?? "未明确")}</b>
              </div>
            `,
          )
          .join("")}
      </div>
      ${card["代码片段"] ? `<div class="vulnerability-code"><span>代码片段</span><pre><code>${escapeHtml(card["代码片段"])}</code></pre></div>` : ""}
    </section>
  `;
}

function renderTrace(trace) {
  $("#trace").innerHTML = trace.length
    ? trace
        .map(
          (item) => `
            <div class="trace-item ${escapeHtml(item.status || "")}">
              <b>${escapeHtml(nodeLabel(item.node))}</b>
              <span>${escapeHtml(item.message)}</span>
              <span>${escapeHtml(item.status)} · ${escapeHtml(item.time)}</span>
            </div>
          `,
        )
        .join("")
    : `<div class="empty">暂无执行记录。</div>`;
}

function renderRecords(records = [], stats = {}) {
  $("#recordStats").textContent = `${stats.total || records.length || 0} 条记录`;
  $("#records").innerHTML = records.length
    ? records
        .map((record) => {
          const severity = severityMeta(record.severity);
          return `
            <div class="record-item">
              <b>${escapeHtml(record.id)} <span class="severity-badge severity-badge--${severity.tone}">${escapeHtml(severity.label)}</span></b>
              <span>${escapeHtml(record.title)}</span>
              <small>${escapeHtml(record.collection)} · ${escapeHtml(record.source)} · ${escapeHtml(record.updated_at)}</small>
            </div>
          `;
        })
        .join("")
    : `<div class="empty">暂无记录。</div>`;
}

async function showGraph() {
  const graph = await api("/api/graph");
  renderTrace(graph.nodes.map((node) => ({ node: node.id, message: node.label, status: "graph-node", time: graph.name })));
}

function bind() {
  $("#askForm").addEventListener("submit", askAssistant);
  $("#reloadConfig").addEventListener("click", loadConfig);
  $("#refreshGraph").addEventListener("click", showGraph);
  $$(".collector-card").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        await saveCollector(form);
      } catch (error) {
        $(".status", form).textContent = error.message;
      }
    });
    $$("button[data-action]", form).forEach((button) => {
      button.addEventListener("click", async () => {
        try {
          await collectorAction(form, button.dataset.action);
        } catch (error) {
          $(".status", form).textContent = error.message;
        }
      });
    });
  });
}

function modeLabel(mode) {
  return {
    vulnerability_lookup: "漏洞情报回答",
    vulnerability_year_lookup: "年份漏洞情报回答",
    supply_chain: "供应链安全回答",
    compliance: "合规安全回答",
    security_knowledge: "安全知识回答",
  }[mode] || mode;
}

function nodeLabel(node) {
  return {
    classify_query: "识别问题意图",
    load_memory_context: "加载长期记忆",
    retrieve_local_knowledge: "漏洞知识库检索",
    fetch_live_vulnerability: "实时补充漏洞记录",
    call_llm: "调用安全专家模型",
    translate_vulnerability_card: "中文整理漏洞卡片",
    compose_answer: "生成回答",
    persist_memory: "保存长期记忆",
  }[node] || node;
}

bind();
loadConfig().catch((error) => {
  $("#answer").textContent = error.message;
});
