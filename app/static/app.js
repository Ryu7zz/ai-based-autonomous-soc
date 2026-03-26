async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json();
}

function setText(id, value) {
  document.getElementById(id).textContent = value;
}

function renderActions(items, targetId) {
  const target = document.getElementById(targetId);
  target.innerHTML = "";
  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    target.appendChild(li);
  });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function truncate(value, maxLength = 80) {
  const text = String(value ?? "");
  if (text.length <= maxLength) {
    return text;
  }
  return `${text.slice(0, maxLength - 1)}...`;
}

function renderDecisionTable(rows) {
  const body = document.getElementById("decision-table-body");
  body.innerHTML = "";
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    const howBlocked = row.blocked_by_wazuh
      ? `Wazuh blocked (rule ${row.block_event_rule_id || "651"})`
      : row.response_command || "No block executed";
    tr.innerHTML = `
      <td title="${escapeHtml(row.timestamp || "")}">${escapeHtml(truncate(row.timestamp || "-", 22))}</td>
      <td title="${escapeHtml(row.wazuh_rule_description || "")}">${escapeHtml((row.wazuh_rule_id || "-") + " " + truncate(row.wazuh_rule_description || "", 38))}</td>
      <td>${escapeHtml(row.source_ip || "-")}</td>
      <td>${escapeHtml((row.destination_ip || "-") + (row.destination_port ? `:${row.destination_port}` : ""))}</td>
      <td>${escapeHtml(`${row.model_label} (${(row.model_confidence * 100).toFixed(1)}%)`)}</td>
      <td>${escapeHtml(String(row.risk_score))}</td>
      <td><span class="decision-pill decision-${escapeHtml(row.decision)}">${escapeHtml(row.decision)}</span><br/><small>${escapeHtml(truncate(row.decision_reason || "", 62))}</small></td>
      <td title="${escapeHtml(row.full_log || "")}">${escapeHtml(truncate(howBlocked, 75))}</td>
    `;
    body.appendChild(tr);
  });
}

async function refreshWazuhDecisionBoard() {
  const statusNode = document.getElementById("wazuh-board-status");
  const limit = Number.parseInt(document.getElementById("wazuh-board-limit").value, 10) || 200;
  const time_range = (document.getElementById("wazuh-board-range").value || "24h").trim();

  statusNode.textContent = `Loading ${limit} Wazuh logs and AI decisions...`;
  try {
    const params = new URLSearchParams({
      limit: String(limit),
      time_range,
    });
    const board = await fetchJson(`/api/wazuh/decision-board?${params.toString()}`);
    setText("board-analyzed", `${board.analyzed_count}`);
    setText("board-blocked", `${board.blocked_count}`);
    setText("board-should-block", `${board.should_block_count}`);
    setText("board-monitor", `${board.monitor_count}`);
    renderDecisionTable(board.rows || []);
    statusNode.textContent = `Loaded ${board.analyzed_count} logs from Wazuh. Blocked: ${board.blocked_count}, should_block: ${board.should_block_count}, monitor: ${board.monitor_count}.`;
  } catch (error) {
    statusNode.textContent = "Could not load Wazuh decision board. Check Wazuh API settings and backend logs.";
  }
}

function loadSample(event) {
  document.getElementById("event-json").value = JSON.stringify(event, null, 2);
  setText("error-text", "");
}

async function refreshModelCard() {
  const model = await fetchJson("/api/model");
  setText("metric-model", model.model_name);
  setText("metric-accuracy", `${(model.metrics.accuracy * 100).toFixed(1)}%`);
  setText("metric-features", `${model.feature_count}`);
  return model;
}

async function loadSamples() {
  const samples = await fetchJson("/api/demo/events");
  const target = document.getElementById("sample-buttons");
  target.innerHTML = "";
  samples.forEach((sample, index) => {
    const button = document.createElement("button");
    button.className = "sample-button";
    button.textContent = sample.name;
    button.title = sample.description;
    button.addEventListener("click", () => loadSample(sample.event));
    target.appendChild(button);
    if (index === 0) {
      loadSample(sample.event);
    }
  });
}

async function analyzeCurrentEvent() {
  const errorNode = document.getElementById("error-text");
  errorNode.textContent = "";
  try {
    const payload = JSON.parse(document.getElementById("event-json").value);
    const result = await fetchJson("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setText("result-label", result.label);
    setText("result-confidence", `${(result.confidence * 100).toFixed(1)}%`);
    setText("result-risk", `${result.risk_score}`);
    setText("result-severity", result.severity);
    setText("result-summary", result.summary);
    setText(
      "result-command",
      result.response_command || "No automated command was generated for this event."
    );
    renderActions(result.recommended_actions, "result-actions");
    renderActions(result.rationale, "result-rationale");
  } catch (error) {
    errorNode.textContent = "The JSON could not be analyzed. Check the format and try again.";
  }
}

async function retrainModel() {
  const statusNode = document.getElementById("train-status");
  statusNode.textContent = "Training the demo model...";
  try {
    await fetchJson("/api/train/demo", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ samples: 2200, seed: 7 }),
    });
    const model = await refreshModelCard();
    statusNode.textContent = `Model refreshed. Accuracy: ${(model.metrics.accuracy * 100).toFixed(1)}%.`;
  } catch (error) {
    statusNode.textContent = "Model retraining failed. Check the server logs.";
  }
}

async function retrainFromWazuh() {
  const statusNode = document.getElementById("train-status");
  const limit = Number.parseInt(document.getElementById("wazuh-train-limit").value, 10) || 100000;
  statusNode.textContent = `Training from Wazuh (${limit} alerts)...`;
  try {
    const model = await fetchJson("/api/train/wazuh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ limit, time_range: "30d", seed: 7 }),
    });
    setText(
      "train-status",
      `Wazuh retraining complete. Rows: ${model.dataset_rows}, accuracy: ${(model.metrics.accuracy * 100).toFixed(1)}%.`
    );
    await refreshModelCard();
  } catch (error) {
    setText("train-status", "Wazuh retraining failed. Check WAZUH_API_URL and credentials.");
  }
}

async function analyzeWazuhBulk() {
  const statusNode = document.getElementById("train-status");
  const target_count = Number.parseInt(document.getElementById("wazuh-bulk-count").value, 10) || 100000;
  statusNode.textContent = `Running Wazuh bulk analysis for ${target_count} alerts...`;
  try {
    const summary = await fetchJson("/api/analyze/wazuh/bulk", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target_count,
        batch_size: 5000,
        time_range: "30d",
        include_samples: false,
      }),
    });
    setText(
      "train-status",
      `Bulk analysis complete. Analyzed ${summary.analyzed_count}/${summary.requested_count}. Avg risk: ${summary.average_risk_score}. High risk: ${summary.high_risk_count}.`
    );
  } catch (error) {
    setText("train-status", "Wazuh bulk analysis failed. Check API connectivity and credentials.");
  }
}

window.addEventListener("DOMContentLoaded", async () => {
  document.getElementById("analyze-button").addEventListener("click", analyzeCurrentEvent);
  document.getElementById("train-model").addEventListener("click", retrainModel);
  document.getElementById("train-wazuh").addEventListener("click", retrainFromWazuh);
  document.getElementById("analyze-wazuh-bulk").addEventListener("click", analyzeWazuhBulk);
  document
    .getElementById("refresh-wazuh-board")
    .addEventListener("click", refreshWazuhDecisionBoard);
  try {
    await Promise.all([refreshModelCard(), loadSamples()]);
    await refreshWazuhDecisionBoard();
  } catch (error) {
    setText("train-status", "The backend is not reachable yet. Start the FastAPI server first.");
  }
});

