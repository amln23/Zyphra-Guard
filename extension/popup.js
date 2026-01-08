chrome.runtime.connect({ name: "popup" });
document.addEventListener("DOMContentLoaded", () => {
  let ENABLED = true;
  let t = 0;
  let animationId = null;
   setInterval(() => {
  if (ENABLED) checkBackendAlerts();
  }, 3000);

  const LIVE_WINDOW_MS = 30 * 1000;
  const SERVER_URL = "http://localhost:5000";

  const resultDiv = document.getElementById("result");
  const currentSiteDiv = document.getElementById("current-site");
  const scanBtn = document.getElementById("scan");
  const toggle = document.getElementById("toggle");
  const statusBox = document.getElementById("status");

  function safeDecode(url) {
    try {
      return decodeURIComponent(url);
    } catch {
      return url;
    }
  }

  function show(msg, cls) {
    resultDiv.className = `result ${cls || ""}`;
    resultDiv.innerHTML = `<p>${msg}</p>`;
  }

  function resetUI() {
    resultDiv.className = "result";
    resultDiv.innerHTML = "";
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = String(str ?? "");
    return div.innerHTML;
  }

  function getSeverityColor(sev) {
    return (
      {
        CRITICAL: "#e74c3c",
        HIGH: "#e67e22",
        MEDIUM: "#f1c40f",
        LOW: "#3498db",
      }[sev] || "#95a5a6"
    );
  }

  function normalizeSeverityByType(type, originalSeverity) {
  const t = String(type || "").toLowerCase();

  if (t.includes("ddos")) return "CRITICAL";

  if (t.includes("dos") && !t.includes("ddos")) return "MEDIUM";

  return originalSeverity || "MEDIUM";
}

function normalizeDetection(d) {
  if (!d) return null;

  let payload = d.payload || "";
  let source = d.source;

  if (!source && Array.isArray(d.sources) && d.sources.length > 0) {
    source = d.sources[0]; // dom | url | post
  }

  return {
    type: d.type || d.attack || "Unknown",
    severity: normalizeSeverityByType(
    d.type || d.attack,
   (d.severity || "LOW").toUpperCase()
  ),

    payload,
    url: d.url || "",
    time: d.time || d.timestamp || new Date().toISOString(),
    source: source || "unknown",
  };
}

  function renderDetection(raw) {
    const d = normalizeDetection(raw);
    if (!d) return;

    const severityClass = d.severity.toLowerCase();
  const payloadBlock = d.payload
  ? `<div class="payload">${
      d.source === "backend" ? escapeHtml(d.payload) : `Payload: ${escapeHtml(d.payload)}`
    }</div>`
  : "";
    resultDiv.innerHTML = `
      <div class="threat-card ${severityClass}">
        <div class="threat-header">
          <span class="threat-type">${escapeHtml(d.type)}</span>
        </div>

        <div class="threat-body">
         ${d.url ? `<div>URL:${escapeHtml(d.url)}</div>` : ""}
          ${payloadBlock}
          <div class="time">${new Date(d.time).toLocaleString()}</div>
        </div>
      </div>
    `;

    statusBox.textContent = ` ${d.severity} Threat Detected`;
    statusBox.style.background = "";
  }

  async function getLatestDetection() {
    return new Promise((resolve) => {
      chrome.storage.local.get(["detections"], (res) => {
        const list = Array.isArray(res.detections) ? res.detections : [];
        resolve(list[0] || null);
      });
    });
  }

  async function refreshLiveStatus() {
    const latest = normalizeDetection(await getLatestDetection());

    if (!latest) {
      show("Connection secure. No threats detected.", "safe");
      statusBox.textContent = " Secure page";
      statusBox.style.background = "";
      return;
    }

    const age = Date.now() - new Date(latest.time).getTime();

    if (age > LIVE_WINDOW_MS) {
      show("Connection secure. No active threats.", "safe");
      statusBox.textContent = " Secure page";
      statusBox.style.background = "";
      return;
    }

    renderDetection(latest);
  }

  function runLiveScan() {
    if (!ENABLED) return;

    statusBox.textContent = " Analyzing...";
    show("Analyzing current page activity…", "safe");
       statusBox.style.background = "";

    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      if (!tab?.id) return;
      chrome.tabs.sendMessage(tab.id, { type: "FORCE_SCAN" }, () => {
        // give content.js a moment to write detections into storage
        setTimeout(refreshLiveStatus, 350);
      });
    });
  }

function normalizeAttackType(type) {
  const t = String(type || "").toLowerCase();

  if (t.includes("ftp") && t.includes("brute")) return "FTP Brute Force";
  if (t.includes("ssh") && t.includes("brute")) return "SSH Brute Force";

  if (t.includes("ddos")) return "DDoS";
  if (t.includes("dos")) return "DoS";

  return type || "Unknown";
}

  async function checkBackendAlerts() {
    try {
      const res = await fetch(`${SERVER_URL}/alerts`);
      const data = await res.json();
      if (!data?.success || !data?.count) return false;
      const alert = data.alerts[data.alerts.length - 1];
      if (!alert?.timestamp) return false;

      const alertAge = Date.now() - new Date(alert.timestamp).getTime();
      if (alertAge > LIVE_WINDOW_MS) return false;

      const rawType = alert.attack || "Network Attack";

const normalizedType = normalizeAttackType(rawType);

  const detection = {
  type: normalizedType,
  severity: (alert.severity || "HIGH").toUpperCase(), 
  url: "",
  payload: "", 
  source: "backend",
  sources: ["backend"], 
  time: alert.timestamp,
};


    chrome.storage.local.get(["detections"], (res) => {
      const list = Array.isArray(res.detections) ? res.detections : [];
      
      if (list[0]?.time === detection.time) return; 
      chrome.storage.local.set({
        detections: [detection, ...list].slice(0, 10),
      });
    });

      return true;
    } catch {
      return false;
    }
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.detections) {
      refreshLiveStatus();
    }
    if (area === "local" && changes.enabled) {
      ENABLED = changes.enabled.newValue !== false;
      updateUI();
    }
  });

  chrome.runtime.onMessage.addListener((msg) => {
    if (!ENABLED || !msg) return;

    if (msg.type === "PAYLOAD_DETECTED") {
      const d = msg.data || {
        type: msg.attack,
        severity: msg.severity,
        payload: msg.payload,
        time: msg.time,
        url: msg.url,
      };
      renderDetection(d);
    }

    if (msg.type === "NETWORK_ALERT" && msg.data) {
      renderDetection({
        type: msg.data.attack || "Network Alert",
        severity: msg.data.severity || "HIGH",
        payload: `Confidence: ${Math.round((msg.data.confidence || 0) * 100)}%`,
        url: "(backend)",
        time: msg.data.timestamp,
      });
    }
  });

  scanBtn.addEventListener("click", () => {
    if (!ENABLED) return;
    runLiveScan();
  });

  // WAVES ANIMATION 
  function animateMorph() {
    if (!ENABLED) {
      animationId = null;
      return;
    }
    t += 0.003;

    const ids = [
      "wave1",
      "wave2",
      "wave3",
      "wave4",
      "wave5",
      "wave6",
      "wave7",
      "wave8",
      "wave9",
      "wave10",
    ];

    ids.forEach((id, i) => {
      const wave = document.getElementById(id);
      if (!wave) return;

      const baseY = 30 + i * 7;
      const amp = 14 + i * 3;
      const freq = 200 - i * 17;
      const phase = t * (0.2 + i * 0.12);

      let d = `M0,${baseY} `;

      for (let x = 0; x <= 1440; x += 16) {
        const y =
          baseY +
          Math.sin(x / freq + phase) * amp +
          Math.cos(x / (freq * 1.5) + phase * 0.7) * (amp * 0.4);

        d += `L${x},${y} `;
      }
      wave.setAttribute("d", d);
      wave.setAttribute("stroke", "url(#gradWave)");
      wave.setAttribute("fill", "none");
    });

    animationId = requestAnimationFrame(animateMorph);
  }

  function startWaves() {
    cancelAnimationFrame(animationId);
    animateMorph();
  }

  function stopWaves() {
    cancelAnimationFrame(animationId);
    animationId = null;
  }

  // TOGGLE LOGIC
  chrome.storage.local.get(["enabled"], (res) => {
    ENABLED = res.enabled !== false;
    updateUI();

    // Always render from storage first, then trigger a scan (so popup matches safety)
    refreshLiveStatus().finally(() => {
      if (ENABLED) {
        startWaves();
        runLiveScan();
        // also: if backend alerts exist, show them if storage has nothing
        setTimeout(async () => {
          const latest = await getLatestDetection();
          if (!latest) await checkBackendAlerts();
        }, 500);
      }
    });
  });

  toggle.addEventListener("click", () => {
    ENABLED = !ENABLED;
    chrome.storage.local.set({ enabled: ENABLED });
    updateUI();
    if (ENABLED) {
      resetUI();
      startWaves();
      runLiveScan();
    } else {
      stopWaves();
      show("Scanning disabled", "warning");
    }
  });

  function updateUI() {
    if (ENABLED) {
      toggle.classList.add("active");
      statusBox.textContent = " Protection ON";
      statusBox.style.background = "";
      scanBtn.disabled = false;
    } else {
      toggle.classList.remove("active");
      statusBox.textContent = " Protection OFF";
      statusBox.style.background = "";
      scanBtn.disabled = true;
      show("Scanning disabled", "warning");
    }
  }
});

chrome.runtime.onMessage.addListener((msg) => {
  if (!ENABLED) return;

  if (msg.type === "PAGE_CLEAN") {
    resetUI();
    show("Connection secure. No active threats.", "safe");
    statusBox.textContent = " Secure page";
   statusBox.style.background = "";
  }

  if (msg.type === "PAYLOAD_DETECTED") {
    renderDetection(msg);
  }
});
