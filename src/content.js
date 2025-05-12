function onDOMReady() {
  startMutationObserver();
  
  const hiddenData = hiddendata_check();

  if(hiddenData.visibleFormHiddenPasswordField){
    chrome.runtime.sendMessage({
      type: 'alert',
      message: '⚠️ Suspicious hidden password field in a visible form detected!',
    });
    chrome.runtime.sendMessage({ type: 'addThreatPoints', points: 4 });
  }
  else if(hiddenData.hiddenFormHiddenPasswordField){
    chrome.runtime.sendMessage({ type: 'addThreatPoints', points: 2 });
  }
  else if(hiddenData.totalHiddenInputs){
    chrome.runtime.sendMessage({ type: 'addThreatPoints', points: 1 });
  }
  console.log("Hidden form data:", hiddenData);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", onDOMReady);
} else {
  onDOMReady();
}

