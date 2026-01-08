const LIVE_WINDOW_MS = 60 * 1000; 
const SEVERITY_COLORS = {
  CRITICAL: "#FF4D4D",
  HIGH:     "#FF9F1A",
  MEDIUM:   "#FFD500",
  LOW:      "#3498DB"
};

const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

function updateBadge() {
  chrome.storage.local.get(["detections", "lastSeenTime"], (res) => {
    const detections = Array.isArray(res.detections) ? res.detections : [];
    const lastSeenTime = res.lastSeenTime || 0;
    const now = Date.now();

    const newDetections = detections.filter(d => {
      const t = Date.parse(d.time);
      return t > lastSeenTime && (now - t) <= LIVE_WINDOW_MS;
    });

    if (newDetections.length > 0) {
      chrome.action.setBadgeText({ text: "!" }); 
      
      const topThreat = newDetections.sort((a, b) => {
        const rankA = SEVERITY_RANK[a.severity] || 0;
        const rankB = SEVERITY_RANK[b.severity] || 0;
        return rankB - rankA;
      })[0];

      chrome.action.setBadgeBackgroundColor({ 
        color: SEVERITY_COLORS[topThreat.severity] || "#FFD500" 
      });
    } else {
      chrome.action.setBadgeText({ text: "" }); 
    }
  });
}

chrome.runtime.onConnect.addListener((port) => {
    if (port.name === "popup") {
        chrome.storage.local.set({ lastSeenTime: Date.now() });
        updateBadge();
    }
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && (changes.detections || changes.enabled)) {
    updateBadge();
  }
});

chrome.alarms.create("cleanup", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(updateBadge);