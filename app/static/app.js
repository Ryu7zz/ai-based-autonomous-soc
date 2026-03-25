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

window.addEventListener("DOMContentLoaded", async () => {
  document.getElementById("analyze-button").addEventListener("click", analyzeCurrentEvent);
  document.getElementById("train-model").addEventListener("click", retrainModel);
  try {
    await Promise.all([refreshModelCard(), loadSamples()]);
  } catch (error) {
    setText("train-status", "The backend is not reachable yet. Start the FastAPI server first.");
  }
});

