const DETECTION_TTL_MS = 90 * 1000; 
const LIVE_WINDOW_MS = DETECTION_TTL_MS; 

const ATTACK_KB = {
  "SQL Injection": {
    desc: "Injection of malicious SQL queries via user input, allowing attackers to read, modify, or delete database data.",
    defenses: [
      "Prepared Statements (Parameterized Queries)",
      "Stored Procedures",
      "Allow-list Input Validation",
      "Least Privilege"
    ],
    risks: [
      "Data theft or modification",
      "Full database compromise",
      "Common & easily exploitable"
    ]
  },

  "XSS": {
    desc: "Injection of malicious client-side scripts into trusted web pages.",
    defenses: [
      "Context-aware output encoding",
      "Content Security Policy (CSP)",
      "Avoid dangerous APIs",
      "Input validation & sanitization"
    ],
    risks: [
      "Session hijacking",
      "Cookie theft",
      "Client-side code execution"
    ]
  },

  "Command Injection": {
    desc: "Execution of arbitrary system commands via vulnerable application interfaces.",
    defenses: [
      "Avoid OS command execution",
      "Strict input validation",
      "Parameterization"
    ],
    risks: [
      "Server takeover",
      "Privilege escalation"
    ]
  },

  "RCE": {
    desc: "Allows attackers to execute arbitrary code remotely on the target system.",
    defenses: [
      "Input sanitization",
      "Sandboxing & containerization",
      "Secure memory management"
    ],
    risks: [
      "Complete system compromise"
    ]
  },

  "SSRF": {
    desc: "Abuse of server functionality to access internal or restricted resources.",
    defenses: [
      "URL allowlists",
      "Block internal IP ranges",
      "Restrict outbound traffic"
    ],
    risks: [
      "Internal network exposure"
    ]
  },

  "Path Traversal": {
    desc: "Accessing files outside the web root via manipulated paths.",
    defenses: [
      "Normalize paths",
      "Allow-list validation",
      "Chroot environments"
    ],
    risks: [
      "Sensitive file disclosure"
    ]
  },

  "CSRF": {
    desc: "Forces authenticated users to execute unwanted actions.",
    defenses: [
      "CSRF tokens",
      "SameSite cookies",
      "Custom headers"
    ],
    risks: [
      "Unauthorized actions"
    ]
  },

  "NoSQL Injection": {
    desc: "Injection attacks targeting NoSQL databases.",
    defenses: [
      "Schema validation",
      "Avoid dynamic queries"
    ],
    risks: [
      "Authentication bypass"
    ]
  },

  "JWT Tampering": {
    desc: "Manipulating JWT tokens to bypass authentication.",
    defenses: [
      "Signature verification",
      "Strong algorithms",
      "Reject unsigned tokens"
    ],
    risks: [
      "Account takeover"
    ]
  },

  "API Abuse": {
    desc: "Misuse of APIs for unauthorized or malicious activities.",
    defenses: [
      "Rate limiting",
      "Strong authentication",
      "Monitoring & anomaly detection"
    ],
    risks: [
      "Financial loss",
      "Service disruption"
    ]
  },

  "GraphQL Injection": {
    desc: "Abuse of GraphQL queries or introspection to extract schema or sensitive data.",
    defenses: [
      "Disable introspection in production",
      "Query depth limiting",
      "Strong schema validation"
    ],
    risks: [
      "Sensitive data exposure",
      "Unauthorized API access"
    ]
  },

  "WebSocket Injection": {
    desc: "Manipulation of WebSocket messages to bypass validation or inject malicious payloads.",
    defenses: [
      "Strict message schema validation",
      "Use WSS (TLS)",
      "Authenticate every connection"
    ],
    risks: [
      "Session hijacking",
      "Real-time data manipulation"
    ]
  },

  "JS Exploitation": {
    desc: "Client-side vulnerabilities caused by insecure JavaScript logic.",
    defenses: [
      "Enforce CSP",
      "Avoid eval()",
      "Secure coding practices"
    ],
    risks: [
      "Client-side compromise"
    ]
  },

  "LFI": {
    desc: "Local File Inclusion allows attackers to read sensitive files from the server by manipulating file path parameters.",
    defenses: [
      "Strict path allow-listing",
      "Disable directory traversal",
      "Use fixed file mappings"
    ],
    risks: [
      "Disclosure of sensitive system files",
      "Credential leakage"
    ]
  },

  "RFI": {
    desc: "Remote File Inclusion occurs when external files are included and executed on the server.",
    defenses: [
      "Disable remote file inclusion",
      "Input sanitization",
      "Restrict execution permissions"
    ],
    risks: [
      "Remote code execution",
      "Malware injection"
    ]
  },

  "SSTI": {
    desc: "Server-Side Template Injection occurs when user input is rendered inside template engines without proper sanitization.",
    defenses: [
      "Never render raw user input",
      "Use sandboxed template engines",
      "Strict input validation"
    ],
    risks: [
      "Data disclosure",
      "Remote code execution"
    ]
  },

  "XXE": {
    desc: "XML External Entity attacks abuse XML parsers to read local files, perform SSRF, or cause denial of service.",
    defenses: [
      "Disable external entities",
      "Disallow DOCTYPE declarations",
      "Use secure XML parsers"
    ],
    risks: [
      "Sensitive file disclosure",
      "Internal service access"
    ]
  },

  "Serialization": {
    desc: "Insecure Deserialization allows attackers to manipulate serialized objects to execute code or alter application logic.",
    defenses: [
      "Validate serialized data",
      "Apply integrity checks",
      "Isolate deserialization logic"
    ],
    risks: [
      "Remote code execution",
      "Privilege escalation"
    ]
  },

"FTP Brute Force": {
  desc: "An attack that attempts to gain unauthorized access to an FTP service by repeatedly trying different username and password combinations.",
  defenses: [
    "Disable FTP and use SFTP or FTPS",
    "Enforce strong password policies",
    "Account lockout after failed attempts",
    "IP whitelisting",
    "Deploy IDS/IPS to detect repeated login failures"
  ],
  risks: [
    "Unauthorized access to sensitive files",
    "Data theft, modification, or deletion",
    "Server compromise",
    "Service disruption due to excessive login attempts"
  ]
},

"SSH Brute Force": {
  desc: "An attack where automated tools attempt to compromise an SSH service by guessing credentials.",
  defenses: [
    "Disable password-based authentication",
    "Use SSH key-based authentication",
    "Change default SSH port",
    "Deploy Fail2Ban or similar tools",
    "Restrict SSH access to trusted IPs"
  ],
  risks: [
    "Full remote system access",
    "Execution of malicious commands",
    "Malware or backdoor installation",
    "Privilege escalation and lateral movement"
  ]
},


"DoS": {
  desc: "Denial of Service (DoS) attacks aim to make a service unavailable by overwhelming server resources. This category includes multiple attack techniques.",
  
  types: {
    "DoS – Hulk": {
      desc: "A high-volume HTTP flooding attack that sends dynamically generated requests to exhaust server resources.",
      defenses: [
        "Request rate limiting",
        "Web Application Firewall (WAF)",
        "Caching mechanisms",
        "Monitoring abnormal HTTP traffic patterns"
      ],
      risks: [
        "Temporary service unavailability",
        "High CPU and memory consumption",
        "Performance degradation for legitimate users",
        "Financial and reputational damage"
      ]
    },

    "DoS – SlowHTTPTest": {
      desc: "A low-and-slow DoS attack that keeps many HTTP connections open by sending partial requests very slowly.",
      defenses: [
        "Strict connection and request timeouts",
        "Limit concurrent connections per client",
        "Reverse proxies and load balancers",
        "IDS to detect anomalous connection behavior"
      ],
      risks: [
        "Exhaustion of server connection pools",
        "Hard-to-detect due to low traffic volume",
        "Denial of service for legitimate users"
      ]
    }
  }
},


"DDoS": {
  desc: "Distributed Denial of Service (DDoS) attacks aim to disrupt service availability by flooding the target with traffic from multiple distributed sources, making mitigation and source identification difficult.",

  types: {
    "DDoS – HOIC": {
      desc: "A DDoS attack tool that generates massive HTTP traffic from multiple sources to overwhelm the target.",
      defenses: [
        "Dedicated DDoS mitigation services",
        "Traffic filtering and anomaly detection",
        "Load balancing and redundancy",
        "Continuous traffic behavior analysis"
      ],
      risks: [
        "Complete service outage",
        "Application and network layer saturation",
        "Difficulty identifying attack sources",
        "Infrastructure overload"
      ]
    },

    "DDoS – LOIC (UDP Flood)": {
      desc: "A DDoS attack that floods the target with large volumes of UDP packets to exhaust bandwidth and network resources.",
      defenses: [
        "Firewall rules to block unnecessary UDP traffic",
        "Network-level rate limiting",
        "Service segmentation",
        "Upstream DDoS protection providers"
      ],
      risks: [
        "Network bandwidth exhaustion",
        "Service degradation or total outage",
        "Collateral impact on co-hosted services"
      ]
    }
  }
}
};

function normalizeSeverityByType(type, originalSeverity) {
  const t = String(type || "").toLowerCase();
 if (
    t.includes("dos") &&
    !t.includes("ddos") 
  ) {
    return "MEDIUM";
  }

  if (t.includes("ddos")) {
    return "CRITICAL";
  }

  return originalSeverity || "MEDIUM";
}

function formatSources(d) {
  if (Array.isArray(d.sources) && d.sources.length) {
    return d.sources.join(" • ");
  }
  if (d.source) return d.source;
  return "unknown";
}

const ATTACK_HOLD_MS = 2 * 60 * 1000; 
let pinnedAttack = null;
let pinnedAt = 0;

function severityRank(sev) {
  const s = String(sev || "").toUpperCase();
  if (s === "CRITICAL") return 4;
  if (s === "HIGH") return 3;
  if (s === "MEDIUM") return 2;
  if (s === "LOW") return 1;
  return 0;
}

function pickPinnedAttack(latest) {
  const now = Date.now();

  if (!pinnedAttack) {
    pinnedAttack = latest;
    pinnedAt = now;
    return pinnedAttack;
  }

  if (now - pinnedAt >= ATTACK_HOLD_MS) {
    pinnedAttack = latest;
    pinnedAt = now;
    return pinnedAttack;
  }

  if (severityRank(latest?.severity) > severityRank(pinnedAttack?.severity)) {
    pinnedAttack = latest;
    pinnedAt = now;
  }

  return pinnedAttack;
}
function setPinnedAttack(detection) {
  const attackBtns = document.querySelectorAll(".attack-pill");

  attackBtns.forEach(btn => {
    btn.querySelector(".live-dot")?.classList.add("hidden");
    btn.querySelector(".live-badge")?.remove();
  });

  if (!detection) return;

  const kbType = mapStatusToKBType(detection.type);
  if (!kbType) return;

  attackBtns.forEach(btn => {
    if (btn.dataset.attack !== kbType) return;

    btn.querySelector(".live-dot")?.classList.remove("hidden");

    const live = document.createElement("span");
    live.className = "live-badge";
    live.textContent = "LIVE";
    btn.appendChild(live);
  });
}

function clearLiveAttacks() {
  document.querySelectorAll(".attack-pill").forEach(btn => {
    btn.querySelector(".live-dot")?.classList.add("hidden");
    btn.querySelector(".live-badge")?.remove();
  });
}

function mapStatusToKBType(type) {
  const t = String(type || "").toLowerCase();

  if (t.includes("ftp") && t.includes("brute")) return "FTP Brute Force";
  if (t.includes("ssh") && t.includes("brute")) return "SSH Brute Force";

  if (
    t.includes("ddos") ||
    t.includes("hoic") ||
    t.includes("loic")
  ) {
    return "DDoS";
  }
 
  if (
    t.includes("dos") ||
    t.includes("hulk") ||
    t.includes("slow")
  ) {
    return "DoS";
  }

  if (t.includes("nosql")) return "NoSQL Injection";
  if (t.includes("sql")) return "SQL Injection";
  if (t.includes("xss")) return "XSS";
  if (t.includes("command")) return "Command Injection";
  if (t.includes("rce")) return "RCE";
  if (t.includes("ssrf")) return "SSRF";
  if (t.includes("csrf")) return "CSRF";
  if (t.includes("jwt")) return "JWT Tampering";
  if (t.includes("graphql")) return "GraphQL Injection";
  if (t.includes("websocket")) return "WebSocket Injection";
  if (t.includes("api")) return "API Abuse";
  if (t.includes("lfi")) return "LFI";
  if (t.includes("rfi")) return "RFI";
  if (t.includes("ssti")) return "SSTI";
  if (t.includes("xxe")) return "XXE";
  if (t.includes("deserial")) return "Serialization";
  if (t.includes("js")) return "JS Exploitation";
  if (t.includes("path")) return "Path Traversal";

  return null;
}

document.addEventListener("DOMContentLoaded", () => {
  const attackBtns = document.querySelectorAll(".attack-pill"); 

  const canvas = document.getElementById("riskChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  const captionEl = document.getElementById("chartCaption");
  const blockedEl = document.getElementById("blocked");
  const statusPill = document.getElementById("statusPill");
  const statusDot = document.getElementById("statusDot");
  const statusText = document.getElementById("statusText");
  const chipsCurrent = document.getElementById("chipsCurrent");
  const detectionsContainer = document.getElementById("detections-container");
  const panel = document.getElementById("attackInfoPanel");
  const titleEl = document.getElementById("attackInfoTitle");
  const contentEl = document.getElementById("attackInfoContent");
  const closeBtn = document.getElementById("closeAttackInfo");

  const overlay = document.getElementById("attackOverlay");

function showAttackPanel() {
  panel.classList.remove("panel-hidden");
  document.body.classList.add("panel-open");
  overlay.classList.remove("hidden");
}

function closeAttackPanel() {
  panel.classList.add("panel-hidden");
  document.body.classList.remove("panel-open");
  overlay.classList.add("hidden");
}

closeBtn.addEventListener("click", closeAttackPanel);
overlay.addEventListener("click", closeAttackPanel);

  if (panel && titleEl && contentEl && closeBtn) {
    function openAttackPanel(type) {
      const info = ATTACK_KB[type];
      if (!info) return;

      titleEl.textContent = type;

      contentEl.innerHTML = `
        <p>${info.desc}</p>

        <h4>PRIMARY DEFENSES</h4>
        <ul>${info.defenses.map(x => `<li>${x}</li>`).join("")}</ul>

        <h4>RISK FACTORS</h4>
        <ul>${info.risks.map(x => `<li>${x}</li>`).join("")}</ul>
      `;

      showAttackPanel();

    }

    function openGroupedAttackPanel(type) {
  const info = ATTACK_KB[type];
  if (!info || !info.types) return;

  titleEl.textContent = type;

  let html = `<p>${info.desc}</p><h4>ATTACK TYPES</h4>`;

  Object.entries(info.types).forEach(([name, sub]) => {
    html += `
      <div class="attack-subtype">
        <h5>${name}</h5>
        <p>${sub.desc}</p>

        <strong>Defenses</strong>
        <ul>${sub.defenses.map(d => `<li>${d}</li>`).join("")}</ul>

        <strong>Risks</strong>
        <ul>${sub.risks.map(r => `<li>${r}</li>`).join("")}</ul>
      </div>
    `;
  });

  contentEl.innerHTML = html;
  showAttackPanel();

}

    document.querySelectorAll(".attack-pill").forEach(pill => {
      pill.addEventListener("click", () => {
  const type = pill.dataset.attack;
  if (!type) return;

  const info = ATTACK_KB[type];

  if (info?.types) {
    openGroupedAttackPanel(type);
  } else {
    openAttackPanel(type);
  }
});

    });
  }

  const viewMode = "live_all";

  refreshFromStorage();
  const refreshBtn = document.getElementById("btnUrl");
if (refreshBtn) {
  refreshBtn.addEventListener("click", () => {
    refreshBtn.disabled = true;
    refreshBtn.textContent = "Refreshing…";

    refreshFromStorage();

    setTimeout(() => {
      refreshBtn.disabled = false;
      refreshBtn.textContent = "▶ Live Security Overview";
    }, 400);
  });
}
  setInterval(refreshFromStorage, 1000);

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.detections) {
      refreshFromStorage();
    }

  });

function refreshFromStorage() {
  chrome.storage.local.get(["detections"], (res) => {
    const detections = Array.isArray(res.detections) ? res.detections : [];

    const now = Date.now();
    const liveDetections = detections
  .filter(d => {
    const t = Date.parse(d.time || "");
    return Number.isFinite(t) && (now - t) <= LIVE_WINDOW_MS;
  })
  .map(d => ({
    ...d,
    severity: normalizeSeverityByType(
      d.type,
      (d.severity || "MEDIUM").toUpperCase()
    )
  }))
  .sort((a, b) => Date.parse(b.time) - Date.parse(a.time));

  const latest = liveDetections[0] || null;

updateStatus(latest, !!latest);

if (!latest) {
  pinnedAttack = null;
  pinnedAt = 0;
  clearLiveAttacks();
} else {
  const pinned = pickPinnedAttack(latest);
  setPinnedAttack(pinned);
}

   updateExplainChips(latest);

    if (blockedEl) blockedEl.textContent = String(detections.length);

    const filtered = filterDetections(detections, viewMode);
    const series = buildTimeBuckets(filtered);

    const anyAttack = series.some(v => v >= 0.6);
    drawChart(series, anyAttack);

    if (captionEl) {
      captionEl.textContent =
        filtered.length === 0
          ? "No detections yet."
          : "Live risk timeline (last 30 minutes, 5-minute buckets).";
    }

    const stats = deriveSystemStats(detections);
    document.getElementById("coverage").textContent = stats.coverage;
    document.getElementById("engine").textContent = stats.engine;
    document.getElementById("privacy").textContent = stats.privacy;

    renderDetectionsList(filtered.slice(0, 8));
  });
}

function setActiveAttacks(detections) {
  const activeTypes = new Set();

  detections.forEach(d => {
    const kbType = mapStatusToKBType(d.type);
    if (kbType) activeTypes.add(kbType);
  });

  ACTIVE_ATTACK_TYPE = null;

  document.querySelectorAll(".attack-pill").forEach(btn => {
    const dot = btn.querySelector(".live-dot");
    btn.querySelector(".live-badge")?.remove();

    if (activeTypes.has(btn.dataset.attack)) {
      dot?.classList.remove("hidden");

      const live = document.createElement("span");
      live.className = "live-badge";
      live.textContent = "LIVE";
      btn.appendChild(live);
    } else {
      dot?.classList.add("hidden");
    }
  });
}

  function filterDetections(detections, mode) {
    if (mode === "live_url") {
      return detections.filter(d => (d.source || "unknown") === "url");
    }
    if (mode === "live_future") {
      return detections.filter(d => ["dom", "post"].includes(d.source || "unknown"));
    }
    return detections;
  }

  function buildTimeBuckets(detections) {
    const NOW = Date.now();
    const WINDOW_MS = 30 * 60 * 1000; // 30 minutes
    const BUCKET_MS = 5 * 60 * 1000;  // 5 minutes
    const BUCKET_COUNT = 6;

    // Initialize buckets with baseline risk
    const buckets = new Array(BUCKET_COUNT).fill(0.12);

    detections.forEach(d => {
      if (!d.time) return;

      const t = new Date(d.time).getTime();
      const age = NOW - t;

      if (age < 0 || age > WINDOW_MS) return;

      const index = Math.floor((WINDOW_MS - age) / BUCKET_MS);
      if (index < 0 || index >= BUCKET_COUNT) return;

      const sevRisk = severityToRisk(d.severity);

      let risk = sevRisk;
      if (typeof d.score === "number") {
        const mlRisk = normalizeScore(d.score);
        risk = Math.max(sevRisk, mlRisk);
      }

      buckets[index] = Math.max(buckets[index], risk);
    });

    return buckets;
  }

  function severityToRisk(sev) {
    const s = String(sev || "").toUpperCase();
    if (s === "CRITICAL") return 1.0;
    if (s === "HIGH") return 0.8;
    if (s === "MEDIUM") return 0.55;
    if (s === "LOW") return 0.3;
    return 0.12; 
  }

  function normalizeScore(score) {
    if (score === null || score === undefined || score === "") return 0;
    const n = Number(score);
    if (Number.isNaN(n)) return 0;
    const v = n > 1 ? (n / 100) : n;
    return clamp01(v);
  }

  function clamp01(x) {
    return Math.max(0, Math.min(1, x));
  }

  function drawChart(data, isAttack) {
    if (!Array.isArray(data) || data.length < 2) {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      return;
    }

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // axes
    ctx.strokeStyle = "rgba(255,255,255,0.12)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(44, 16);
    ctx.lineTo(44, 238);
    ctx.lineTo(canvas.width - 16, 238);
    ctx.stroke();

    // line
    ctx.strokeStyle = isAttack ? "#FF6A6A" : "#00FFAA";
    ctx.lineWidth = 3;
    ctx.beginPath();

    data.forEach((v, i) => {
      const x = 44 + i * ((canvas.width - 80) / (data.length - 1));
      const y = 238 - v * 190;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });

    ctx.stroke();

    // points
    data.forEach((v, i) => {
      const x = 44 + i * ((canvas.width - 80) / (data.length - 1));
      const y = 238 - v * 190;
      ctx.fillStyle = isAttack ? "#FF6A6A" : "#00FFAA";
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fill();
    });
  }

function updateStatus(latestDetection, hasRecentAttack) {
  if (!statusPill || !statusText) return;
  if (!latestDetection || !hasRecentAttack) {
    statusPill.className = "status-pill safe";
    statusText.textContent = "Secure";
    return;
  }

  let sev = "MEDIUM"; 
  
if (latestDetection.score) {
    const s = latestDetection.score;
      
      if (s >= 9.0) sev = "CRITICAL";
      else if (s >= 7.0) sev = "HIGH";
      else if (s >= 4.0) sev = "MEDIUM";
      else sev = "LOW";
  } 
  else {
      sev = normalizeSeverityByType(
        latestDetection.type,
        (latestDetection.severity || "MEDIUM").toUpperCase()
      );
  }

  const type = latestDetection.type || "Threat";

  statusPill.className = `status-pill ${sev.toLowerCase()}`;
  statusText.textContent = `${sev} • ${type}`;
}

  function deriveSystemStats(detections) {
    let hasML = false;
    let hasDOM = false;

    detections.forEach(d => {
      if (typeof d.score === "number") hasML = true;
      if (d.payload && /<|script|onerror|onload/i.test(d.payload)) {
        hasDOM = true;
      }
    });

    return {
      coverage: hasDOM ? "URL + DOM (Active)" : "GET Requests (Active)",
      engine: hasML ? "Heuristic + ML (Hybrid)" : "Heuristic Only",
      privacy: "Local-First (Verified)"
    };
  }

  function updateExplainChips(latest) {
    if (!chipsCurrent) return;

    if (viewMode === "live_future") {
      setExplain([
        "POST payload inspection (planned)",
        "DOM mutation correlation (planned)",
        "Behavior-based anomaly scoring (planned)",
        "CVSS severity mapping (planned)"
      ]);
      return;
    }

    if (!latest) {
      setExplain([
        "No suspicious URL patterns",
        "Baseline risk stable",
        "No rule triggers",
        "Normal input distribution"
      ]);
      return;
    }

    setExplain([
  `Latest type: ${latest.type || "N/A"}`,
  `Severity: ${latest.severity || "N/A"}`,
  `Sources detected: ${formatSources(latest)}`,
  "Detection based on behavioral indicators",
  "Rule-based correlation (live)"
]);

  }

  function setExplain(items) {
    chipsCurrent.innerHTML = "";
    items.forEach(t => {
      const s = document.createElement("span");
      s.textContent = t;
      chipsCurrent.appendChild(s);
    });
  }

  function getProtocolRisk(url) {
    if (!url) return "unknown";
    if (url.startsWith("https://")) return "secure";
    if (url.startsWith("http://")) return "insecure";
    return "unknown";
  }


function renderDetectionsList(list) {
  if (!detectionsContainer) return;

  if (list.length === 0) {
    detectionsContainer.innerHTML = `<div class="no-detections"><p>No security threats detected yet.</p></div>`;
    return;
  }

  detectionsContainer.innerHTML = "";
  list.forEach(d => {
    const card = document.createElement("div");
    
    let finalScore = d.score;
    if ((finalScore === null || finalScore === undefined) && typeof ZGSScoringEngine !== 'undefined') {
        const result = ZGSScoringEngine.calculate({
            type: d.type,
            vector: (d.source === 'url' ? 'Network' : 'Local'),
            severity: d.severity // Fallback
        });
        finalScore = result.score;
    }
        const scoreDisplay = finalScore ? Number(finalScore).toFixed(1) : "N/A";

   
    let dynamicSeverity = "LOW";
    const numScore = Number(finalScore || 0);
    
    if (numScore >= 9.0) dynamicSeverity = "CRITICAL";
    else if (numScore >= 7.0) dynamicSeverity = "HIGH";
    else if (numScore >= 4.0) dynamicSeverity = "MEDIUM";
    else dynamicSeverity = "LOW";

   
    card.className = `stat ${dynamicSeverity.toLowerCase()}`; 
    card.innerHTML = `
      <div class="k" style="font-weight: 700; font-size: 14px;">${escapeHTML(d.type || "Unknown")}</div>

      <div class="small-note" style="display:flex; gap:10px; align-items:center; margin-top:5px;">
        <span style="color:#ffffff; font-size:13px; font-weight: 600;">
           Score: ${scoreDisplay}
        </span>
        
        <span style="color:#bbbbbb; font-size:13px;">
           | Severity: ${dynamicSeverity} </span>
      </div>

      <div class="small-note">Source=${escapeHTML(formatSources(d))}</div>
      <div class="small-note event-url">${escapeHTML(d.url || "")}</div>
      <div class="small-note">${new Date(d.time).toLocaleString()}</div>
    `;

    detectionsContainer.appendChild(card);
  });
}

  function escapeHTML(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
