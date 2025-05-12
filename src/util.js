// function to cehck if the element is hidden
function isHidden(el) {
  if (!el || !(el instanceof HTMLElement)) return true;

  const style = window.getComputedStyle(el);
  const rect = el.getBoundingClientRect();
  
  // Check visual and semantic hiding
  return (
    style.display === 'none' ||
    style.visibility === 'hidden' ||
    parseFloat(style.opacity) < 0.1 ||
    rect.width + rect.height === 0 || // Zero area
    el.hidden ||
    el.getAttribute('aria-hidden') === 'true' ||
    // Off-screen detection
    rect.top + rect.height < 0 ||
    rect.left + rect.width < 0 ||
    // Content visibility (new CSS properties)
    style.contentVisibility === 'hidden'||
    //Nested inside invisible containers 
    el.offsetParent === null
  );
}

// Enhanced form analysis with common false positive avoidance
function hiddendata_check() {
  const hiddendata = {
    totalHiddenPasswordFields: 0,
    totalHiddenInputs: 0,
    visibleFormHiddenPasswordField: false,
    hiddenFormHiddenPasswordField: false,
  };

  const SAFE_HIDDEN_INPUT_NAMES = new Set([
    'csrf_token', 'authenticity_token', 
    'nonce', '__requestverificationtoken'
  ]);

  document.querySelectorAll('form').forEach(form => {
    let hasHiddenPassword = false;
    const isFormHidden = isHidden(form);// to do later: check where the form is being submitted to 

    form.querySelectorAll('input').forEach(input => {
      if (!isHidden(input)) return;

      hiddendata.totalHiddenInputs++;
      
      // Skip common security tokens
      if (SAFE_HIDDEN_INPUT_NAMES.has(input.name?.toLowerCase())) return;

      if (input.type.toLowerCase() === 'password') {
        hasHiddenPassword = true;
        hiddendata.totalHiddenPasswordFields++;
      }
    });

    if (hasHiddenPassword) {
      isFormHidden 
        ? hiddendata.hiddenFormHiddenPasswordField = true
        : hiddendata.visibleFormHiddenPasswordField = true;
    }
  });

  return hiddendata;
}

//function to check if the dynamically added form has hidden password fields
function check_dynamic_form(form){
  const hiddendata = {
    visibleFormHiddenPasswordField: false,
    hiddenFormHiddenPasswordField: false,
  };
  let hasHiddenPassword = false;
  const isFormHidden = isHidden(form);// to do later: check where the form is being submitted to 

  form.querySelectorAll('input').forEach(input => {
      if (input.type.toLowerCase() === 'password' && isHidden(input)){
        hasHiddenPassword = true;
      }
  });

  if (hasHiddenPassword) {
    isFormHidden 
      ? hiddendata.hiddenFormHiddenPasswordField = true
      : hiddendata.visibleFormHiddenPasswordField = true;
  }
  return hiddendata;
}

// Optimized mutation observer with debouncing
function startMutationObserver() {
  const DEBOUNCE_DELAY = 500;
  let timeoutId;

  const observer = new MutationObserver(mutations => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => {
      let clickJackingScore=0;
      let formScore=0;
      let scriptInjectionScore=0;
      let inputScore=0;
      mutations.forEach(({ addedNodes }) => {
        addedNodes.forEach(node => {
          if (!(node instanceof HTMLElement)) return;

          // Check all potential risk elements
          switch(node.tagName) {
            case 'FORM':
              info=check_dynamic_form(node);
              if(info.visibleFormHiddenPasswordField){
                chrome.runtime.sendMessage({
                  type: 'alert',
                  message: '⚠️ Suspicious hidden password field in a visible form detected!',
                });
                chrome.runtime.sendMessage({ type: 'addThreatPoints', points: 4 });
              }
              else if(info.hiddenFormHiddenPasswordField)
                 formScore++;
              break;
            case 'INPUT':
              if (isHidden(node)) {
                inputScore=1;
              }
              break;
              
            case 'SCRIPT':
              scriptInjectionScore=Math.max(scriptInjectionScore,checkScriptInjection(node));
              break;
              
            case 'IFRAME':
              clickJackingScore=Math.max(clickJackingScore,checkForClickjacking(node));
              break;
          }
        });
      });
      chrome.runtime.sendMessage({ type: 'addThreatPoints', points: clickJackingScore+scriptInjectionScore+inputScore+formScore });
    }, DEBOUNCE_DELAY);
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['style', 'hidden']
  });
}

// Enhanced clickjacking detection
function checkForClickjacking(node) {
  if (node.tagName !== 'IFRAME') return;

  const style = window.getComputedStyle(node);
  const rect = node.getBoundingClientRect();
  
  const clickjackingIndicators = {
    hiddenVisibility: style.visibility === 'hidden',
    noDisplay: style.display === 'none',
    transparent: parseFloat(style.opacity) < 0.1,
    tinySize: rect.width < 5 || rect.height < 5,
    offScreen: rect.top + rect.height < 0 || rect.left + rect.width < 0,
    sandboxMissing: !node.hasAttribute('sandbox'),
    riskySandbox: node.getAttribute('sandbox')?.includes('allow-scripts'),
    suspiciousSrc: isSuspiciousDomain(node.src)
  };

  const threatScore = Object.values(clickjackingIndicators)
    .filter(Boolean).length ;

  return Math.min(4,threatScore);
}

// Domain reputation system
function isSuspiciousDomain(urlString) {
  try {
    const url = new URL(urlString);
    const hostname = url.hostname;
    
    // Domain pattern analysis
    const isIP = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^\[[a-f0-9:]+\]$/i.test(hostname);
    const tld = hostname.split('.').pop() || '';
    
    const SUSPICIOUS_TLDS = new Set([
      'xyz', 'tk', 'gq', 'ml', 'cf', 'ga', 'top',
      'loan', 'club', 'click', 'bid', 'win', 'vip'
    ]);
    
    const RISKY_KEYWORDS = /(?:admin|login|secure|account|auth)/i;
    
    return isIP || 
           SUSPICIOUS_TLDS.has(tld) ||
           RISKY_KEYWORDS.test(hostname);
  } catch {
    return true; // Invalid URL
  }
}

// Enhanced script validation
const TRUSTED_HOSTS = new Set([
  'googleapis.com',
  'cloudflare.com',
  'jsdelivr.net',
  'unpkg.com',
  'jquery.com',
  'facebook.net',
  'twitter.com',
  'gstatic.com',
  'recaptcha.net',
  'hcaptcha.com'
]);

function checkScriptInjection(node) {
  if (!(node instanceof HTMLScriptElement)) return;

  const threatAnalysis = {
    inlineScript: !node.src,
    unsafeSource: false,
    dynamicInjection: true,
    suspiciousContent: false
  };

  if (node.src) {
    // Analyze inline script content
    const scriptContent = node.textContent.toLowerCase();
    hasSusContent = /(?:document\.cookie|localStorage|XMLHttpRequest)/.test(scriptContent);
    
    if(hasSusContent) {
      chrome.runtime.sendMessage({
        type: 'alert',
        details: "Inline script with suspicious content was added"
      })
      return 4;
    }
    else return 3;
  } 
  else {
    try {
      const srcUrl = new URL(node.src);
      const hostParts = srcUrl.hostname.split('.');
      
      // Check if domain or subdomain is trusted
      const isTrusted = hostParts.some(part => TRUSTED_HOSTS.has(part));
      
      if (!isTrusted) {
        if(isSuspiciousDomain(srcUrl.href)){
          chrome.runtime.sendMessage({
            type:'alert',
            details:'script with unknown source was added'
          })
          return 4;
        }
        else return 3;
      }
    } catch (e) {
      console.log("error:",e);
      return 1;
    }
  }
}




























// function isHidden(el) {
//   const style = window.getComputedStyle(el);
//   const rect = el.getBoundingClientRect();

//   return (
//     style.display === 'none' ||
//     style.visibility === 'hidden' ||
//     style.opacity === '0' ||
//     rect.width === 0 ||
//     rect.height === 0 ||
//     el.hasAttribute('hidden') ||
//     el.getAttribute('aria-hidden') === 'true'
//   );
// }

// // functon that checks static dom content when the page loads
// function hiddendata_check(){
//   let hiddendata={
//     totalHiddenPasswordFields:0,
//     totalHiddenInputs:0,
//     visibleFormHiddenPasswordField:false,
//     hiddenFormHiddenPasswordField:false,
//   }
//   const forms=document.querySelectorAll('form');
//   forms.forEach(form=>{
//     let hashiddenpassword=false;
//     const inputs=form.querySelectorAll('input');
//     inputs.forEach(input=>{
//       if(isHidden(input)){
//         hiddendata.totalHiddenInputs++;
//         if(input.type.toLowerCase()=='password'){
//           hashiddenpassword=true;
//           hiddendata.totalHiddenPasswordFields++;
//         }
//       }
//     })
//     let isformhidden=isHidden(form);
//     if(isformhidden && hashiddenpassword) hiddendata.hiddenFormHiddenPasswordField=true;
//     else if(!isformhidden && hashiddenpassword) hiddendata.visibleFormHiddenPasswordField=true;
//   })
//   return hiddendata;
// }


// //Mutation observer to check js activity 
// function startMutationObserver(){
//   const observer=new MutationObserver(mutations=>{
//     mutations.forEach(mutation=>{
//       mutation.addedNodes.forEach(node=>{
//         console.log("Added node:", node); // Debugging log
//         if (node.tagName === 'FORM' || node.tagName === 'INPUT') {
//           if(isHidden(node)) alert("Warning: Hidden form added!");
//         }
//         if (node.tagName === 'SCRIPT') {
//           checkScriptInjection(node);
//         }
//         if (node.tagName === 'IFRAME') {
//           checkForClickjacking(node);
//         }
//         if (node.tagName === 'DIV' && node.style.zIndex === '99999') {
//           checkForOverlay(node); // Example: Detecting hidden overlays
//         }
//       });
//     });
//   });

//   observer.observe(document.body, {
//     childList: true,
//     subtree: true
//   });
// }









// function checkForClickjacking(node) {
//   if (
//     node.tagName === 'IFRAME' &&
//     (
//       node.style.visibility === 'hidden' ||
//       node.style.display === 'none' ||
//       node.style.opacity === '0' ||
//       node.width < 5 || node.height < 5
//     )
//   ) {
//     console.warn("⚠️ Suspicious iframe detected (possible clickjacking):", node);
//     alert("Warning: Hidden iframe detected — possible clickjacking!");
//   }
// }

// function checkForOverlay(node){
//   //to do later
// }


// //trusted sources to whitelist 
// const SAFE_SCRIPT_SOURCES = [
//   "https://ajax.googleapis.com",        // Google CDN
//   "https://cdnjs.cloudflare.com",       // Cloudflare CDN
//   "https://cdn.jsdelivr.net",           // jsDelivr CDN
//   "https://unpkg.com",                  // npm CDN
//   "https://code.jquery.com",            // jQuery CDN
//   "https://apis.google.com",            // Google services
//   "https://connect.facebook.net",       // Facebook SDK
//   "https://platform.twitter.com",       // Twitter widgets
//   "https://www.google-analytics.com",   // Google Analytics
//   "https://static.cloudflareinsights.com", // Cloudflare Analytics
//   "https://cdn.datatables.net",         // DataTables CDN
//   "https://cdn.jsdelivr.net",           // Again, common for modern libs
//   "https://kit.fontawesome.com",        // FontAwesome
//   "https://www.recaptcha.net",          // Google reCAPTCHA
//   "https://hcaptcha.com",               // hCaptcha
//   "https://static.zdassets.com",        // Zendesk
// ];

// function checkScriptInjection(node) {
//   if (!node || !(node instanceof HTMLScriptElement)) return;

//   if (!node.src) {
//     // Inline script — most dangerous if injected after page load
//     console.warn("⚠️ Inline script dynamically injected:", node.textContent.slice(0, 100));
//     chrome.runtime.sendMessage({ type: 'addThreatPoints', points: 5 });
//     chrome.runtime.sendMessage({ type: 'suspiciousActivity', message: '⚠️ Inline script dynamically added to page!' });
//   } 
//   else {
//     const src = node.src;
//     const isSafe = SAFE_SCRIPT_SOURCES.some(safeDomain => {
//       try {
//         return new URL(src).hostname.endsWith(safeDomain);
//       } catch (e) {
//         return false;
//       }
//     });

//     if(isSafe) return;

//     // Heuristic check: is the source URL suspicious?
//     try {
//     const url = new URL(node.src);
//     const suspiciousTLDs = [
//       "xyz", "tk", "gq", "ml", "cf", "ga", "ru", "cn"
//     ];

//     const isIP = /^[\d.]+$/.test(url.hostname);
//     const tld = url.hostname.split('.').pop();

//     if (isIP || suspiciousTLDs.includes(tld)) {
//       console.warn("⚠️ Suspicious script source detected:", url.href);
//       chrome.runtime.sendMessage({ type: 'addThreatPoints', points: 3 });
//       chrome.runtime.sendMessage({
//         type: 'alertUser',
//         message: `⚠️ Suspicious external script loaded from ${url.hostname}`
//       });
//     }
//   } catch (e) {
//     console.error("Invalid script URL:", node.src);
//   }
//   }
// }