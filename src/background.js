

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

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    if (changeInfo.url.startsWith("http://")) {
      chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: () => {
          alert("⚠️ Warning: This site is not secure. (No HTTPS)");
        }
      });
    }
  }
  if (changeInfo.status === 'complete' && tab.url) {
    chrome.scripting.executeScript({
      target: { tabId: tabId },
      func: startMutationObserver
    });
  }
});



function startMutationObserver(){
  const observer=new MutationObserver(mutations=>{
    mutations.forEach(mutation=>{
      mutation.addedNodes.forEach(node=>{
        console.log("Added node:", node); // Debugging log
        if (node.tagName === 'FORM' || node.tagName === 'INPUT') {
          if(isHidden(node)) alert("Warning: Hidden form added!");
        }
        if (node.tagName === 'SCRIPT') {
          checkScriptInjection(node);
        }
        if (node.tagName === 'IFRAME') {
          checkForClickjacking(node);
        }
        if (node.tagName === 'DIV' && node.style.zIndex === '99999') {
          checkForOverlay(node); // Example: Detecting hidden overlays
        }
      });
    });
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}


function checkScriptInjection(node){
  if (!node.src) {
    console.warn("⚠️ Inline script detected:", node);
    alert("Warning: Inline script injected!");
  }
  else{
    //to do later
  }
}

function checkForClickjacking(node) {
  if (
    node.tagName === 'IFRAME' &&
    (
      node.style.visibility === 'hidden' ||
      node.style.display === 'none' ||
      node.style.opacity === '0' ||
      node.width < 5 || node.height < 5
    )
  ) {
    console.warn("⚠️ Suspicious iframe detected (possible clickjacking):", node);
    alert("Warning: Hidden iframe detected — possible clickjacking!");
  }
}

function checkForOverlay(node){
  //to do later
}

function isHidden(el) {
  console.log(el); // Check which element is being passed
  const style = window.getComputedStyle(el);
  const rect = el.getBoundingClientRect();
  
  return (
    style.display === 'none' ||
    style.visibility === 'hidden' ||
    style.opacity === '0' ||
    rect.width === 0 ||
    rect.height === 0
  );
}
