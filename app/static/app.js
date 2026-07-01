const state = {
  config: null,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

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
  target.textContent = action === "test" ? "Testing..." : "Collecting...";
  const path = action === "test" ? `/api/config/${id}/test` : `/api/collect/${id}`;
  const result = await api(path, { method: "POST" });
  target.textContent = result.message || `${action} finished`;
  await loadConfig();
}

async function askAssistant(event) {
  event.preventDefault();
  const question = $("#question").value.trim();
  if (!question) return;
  $("#answer").textContent = "Thinking through LangGraph...";
  const result = await api("/api/ask", {
    method: "POST",
    body: JSON.stringify({ question, top_k: Number($("#topK").value || 5) }),
  });
  renderAnswer(result);
}

function renderAnswer(result) {
  $("#answer").classList.remove("empty");
  $("#answer").innerHTML = `
    <b>${escapeHtml(result.mode || "security_knowledge")}</b>
    <p>${escapeHtml(result.summary || "")}</p>
    <small>Confidence: ${escapeHtml(result.confidence ?? "-")} · ${escapeHtml(result.generated_at || "")}</small>
  `;
  renderTrace(result.trace || []);
}

function renderTrace(trace) {
  $("#trace").innerHTML = trace.length
    ? trace
        .map(
          (item) => `
            <div class="trace-item">
              <b>${escapeHtml(item.node)}</b>
              <span>${escapeHtml(item.message)}</span>
              <span>${escapeHtml(item.status)} · ${escapeHtml(item.time)}</span>
            </div>
          `,
        )
        .join("")
    : `<div class="empty">No trace yet.</div>`;
}

function renderRecords(records = [], stats = {}) {
  $("#recordStats").textContent = `${stats.total || records.length || 0} records`;
  $("#records").innerHTML = records.length
    ? records
        .map(
          (record) => `
            <div class="record-item">
              <b>${escapeHtml(record.id)} · ${escapeHtml(record.severity)}</b>
              <span>${escapeHtml(record.title)}</span>
              <small>${escapeHtml(record.collection)} · ${escapeHtml(record.source)} · ${escapeHtml(record.updated_at)}</small>
            </div>
          `,
        )
        .join("")
    : `<div class="empty">No records yet.</div>`;
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

bind();
loadConfig().catch((error) => {
  $("#answer").textContent = error.message;
});

