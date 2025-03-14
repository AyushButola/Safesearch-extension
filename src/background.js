chrome.webNavigation.onBeforeNavigate.addListener((details)=>{
  fetch(`https://phish.sinking.yachts/v2/check/url?url=${encodeURIComponent(details.url)}`,
  {method: "GET",
    headers:{"X-Identity":"Safe-search/1.0"}
  })
  .then(response=> response.json())
  .then(data=> {
    console.warn("🚨 Phishing site detected:", url);
    chrome.tabs.update(details.tabId, { url: "about:blank" });
    alert("⚠️ Warning: This site is flagged as phishing!");
  })
  .catch(error=>{
    console.error("❌ API Error:", error);  })
})

