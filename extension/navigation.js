document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("openSafety");

  if (!btn) return;

  btn.addEventListener("click", () => {
    chrome.tabs.create({
      url: chrome.runtime.getURL("safety.html")
    });
  });
});
