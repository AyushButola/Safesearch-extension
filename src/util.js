
function isHidden(el) {
  const style = window.getComputedStyle(el);
  const rect = el.getBoundingClientRect();

  return (
    style.display === 'none' ||
    style.visibility === 'hidden' ||
    style.opacity === '0' ||
    rect.width === 0 ||
    rect.height === 0 ||
    el.hasAttribute('hidden') ||
    el.getAttribute('aria-hidden') === 'true'
  );
}

// functon that checks static dom content when the page loads
function hiddendata_check(){
  let hiddendata={
    totalHiddenPasswordFields:0,
    totalHiddenInputs:0,
    visibleFormHiddenPasswordField:false,
    hiddenFormHiddenPasswordField:false,
  }
  const forms=document.querySelectorAll('form');
  forms.forEach(form=>{
    let hashiddenpassword=false;
    const inputs=form.querySelectorAll('input');
    inputs.forEach(input=>{
      if(isHidden(input)){
        hiddendata.totalHiddenInputs++;
        if(input.type.toLowerCase()=='password'){
          hashiddenpassword=true;
          hiddendata.totalHiddenPasswordFields++;
        }
      }
    })
    let isformhidden=isHidden(form);
    if(isformhidden && hashiddenpassword) hiddendata.hiddenFormHiddenPasswordField=true;
    else if(!isformhidden && hashiddenpassword) hiddendata.visibleFormHiddenPasswordField=true;
  })
  return hiddendata;
}


//Mutation observer to check js activity 
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


//trusted sources to whitelist 
const SAFE_SCRIPT_SOURCES = [
  "https://ajax.googleapis.com",        // Google CDN
  "https://cdnjs.cloudflare.com",       // Cloudflare CDN
  "https://cdn.jsdelivr.net",           // jsDelivr CDN
  "https://unpkg.com",                  // npm CDN
  "https://code.jquery.com",            // jQuery CDN
  "https://apis.google.com",            // Google services
  "https://connect.facebook.net",       // Facebook SDK
  "https://platform.twitter.com",       // Twitter widgets
  "https://www.google-analytics.com",   // Google Analytics
  "https://static.cloudflareinsights.com", // Cloudflare Analytics
  "https://cdn.datatables.net",         // DataTables CDN
  "https://cdn.jsdelivr.net",           // Again, common for modern libs
  "https://kit.fontawesome.com",        // FontAwesome
  "https://www.recaptcha.net",          // Google reCAPTCHA
  "https://hcaptcha.com",               // hCaptcha
  "https://static.zdassets.com",        // Zendesk
];

function checkScriptInjection(node) {
  if (!node || !(node instanceof HTMLScriptElement)) return;

  if (!node.src) {
    // Inline script — most dangerous if injected after page load
    console.warn("⚠️ Inline script dynamically injected:", node.textContent.slice(0, 100));
    chrome.runtime.sendMessage({ type: 'addThreatPoints', points: 5 });
    chrome.runtime.sendMessage({ type: 'suspiciousActivity', message: '⚠️ Inline script dynamically added to page!' });
  } 
  else {
    const src = node.src;
    const isSafe = SAFE_SCRIPT_SOURCES.some(safeDomain => {
      try {
        return new URL(src).hostname.endsWith(safeDomain);
      } catch (e) {
        return false;
      }
    });

    if(isSafe) return;

    // Heuristic check: is the source URL suspicious?
    try {
    const url = new URL(node.src);
    const suspiciousTLDs = [
      "xyz", "tk", "gq", "ml", "cf", "ga", "ru", "cn"
    ];

    const isIP = /^[\d.]+$/.test(url.hostname);
    const tld = url.hostname.split('.').pop();

    if (isIP || suspiciousTLDs.includes(tld)) {
      console.warn("⚠️ Suspicious script source detected:", url.href);
      chrome.runtime.sendMessage({ type: 'addThreatPoints', points: 3 });
      chrome.runtime.sendMessage({
        type: 'alertUser',
        message: `⚠️ Suspicious external script loaded from ${url.hostname}`
      });
    }
  } catch (e) {
    console.error("Invalid script URL:", node.src);
  }
  }
}