function onDOMReady() {
  startMutationObserver();
  const hiddenData = hiddendata_check();

  if(hiddenData.visibleFormHiddenPasswordField){
    injectWarningBanner("Suspicious hidden password field in a visible form detected!")
    chrome.runtime.sendMessage({
      type: 'alert',
      details: '⚠️ Suspicious hidden password field in a visible form detected!',
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






//redirect preventions
(function () {
  const currentHost = location.hostname;

  function showWarning(targetUrl, proceedCallback) {
    console.log("not working")
    const modal = document.createElement('div');
    modal.innerHTML = `
      <div style="
        position: fixed;
        top: 0; left: 0; right: 0; bottom: 0;
        background: rgba(0,0,0,0.7);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 9999999;
      ">
        <div style="
          background: white;
          padding: 20px;
          max-width: 400px;
          border-radius: 10px;
          text-align: center;
          font-family: sans-serif;
        ">
          <h2>⚠️ Leaving Site</h2>
          <p>You are about to leave <strong>${currentHost}</strong> and visit:</p>
          <p style="word-break: break-all;">${targetUrl}</p>
          <button id="continueNav" style="margin-right:10px">Proceed</button>
          <button id="cancelNav">Cancel</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);

    modal.querySelector("#continueNav").onclick = () => {
      modal.remove();
      proceedCallback();
    };
    modal.querySelector("#cancelNav").onclick = () => modal.remove();
  }

  // Intercept all anchor clicks
  document.addEventListener('click', (e) => {
    const a = e.target.closest('a[href]');
    if (!a) return;

    const url = new URL(a.href);
    if (url.hostname !== currentHost) {
      e.preventDefault();
      showWarning(a.href, () => window.location.href = a.href);
    }
  });

  // Intercept form submits
  document.addEventListener('submit', (e) => {
    const form = e.target;
    const action = form.action || location.href;
    const url = new URL(action, location.href);

    if (url.hostname !== currentHost) {
      e.preventDefault();
      showWarning(url.href, () => form.submit());
    }
  });

  // Monitor JS-triggered redirects (window.location etc.)
  const originalAssign = window.location.assign;
  const originalReplace = window.location.replace;

  function interceptNavigation(method) {
    return function (url) {
      const target = new URL(url, location.href);
      if (target.hostname !== currentHost) {
        showWarning(target.href, () => method.call(window.location, url));
      } else {
        method.call(window.location, url);
      }
    };
  }

  window.location.assign = interceptNavigation(originalAssign);
  window.location.replace = interceptNavigation(originalReplace);

  Object.defineProperty(window.location, 'href', {
    set: function (url) {
      const target = new URL(url, location.href);
      if (target.hostname !== currentHost) {
        showWarning(target.href, () => { window.location = url; });
      } else {
        window.location = url;
      }
    },
    get: function () {
      return location.href;
    }
  });

})();




//cookie intervention

(function monitorCookieAccess() {
  const originalCookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie') ||
                                   Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'cookie');

  if (!originalCookieDescriptor) return;

  Object.defineProperty(document, 'cookie', {
    configurable: true,
    enumerable: true,
    
    get: function () {
      chrome.runtime?.sendMessage?.({
        type: 'alert',
        details: '⚠️ Suspicious access to document.cookie detected (read)'
      });
      injectWarningBanner('Script tried to READ document.cookie!');
      console.warn('[SafeSearch] ⚠️ document.cookie read access detected');
      return originalCookieDescriptor.get.call(document);
    },
    
    set: function (val) {
      chrome.runtime?.sendMessage?.({
        type: 'alert',
        details: `⚠️ Script tried to set document.cookie → ${val}`
      });

      injectWarningBanner(`Script tried to SET document.cookie → ${val}`);
      console.warn('[SafeSearch] ⚠️ document.cookie write attempt:', val);

      // Optionally, score risk based on what is being written
      if (/session|token|auth|jwt/i.test(val)) {
        chrome.runtime.sendMessage({ type: 'addThreatPoints', points: 3 });
      } else {
        chrome.runtime.sendMessage({ type: 'addThreatPoints', points: 1 });
      }

      return originalCookieDescriptor.set.call(document, val);
    }
  });
})();




//Intercept & Detect Cookie Exfiltration

//Hook fetch
(function hookFetch() {
  const originalFetch = window.fetch;
  
  window.fetch = async function (...args) {
    try {
      const [input, init = {}] = args;
      const url = typeof input === 'string' ? input : input.url;
      const headers = init.headers || {};

      const isCrossSite = isSuspiciousDomain(url);

      // Heuristic: Warn only if it might send cookies (credentials included)
      const credentials = init.credentials || 'same-origin';
      if (credentials !== 'omit' && isCrossSite) {
        injectWarningBanner(`⚠️ Potential cross-site cookie leak via fetch to ${url}`);
        chrome.runtime.sendMessage({
          type: 'alert',
          details: `⚠️ Fetch call may be leaking cookies to ${url}`
        });
        chrome.runtime.sendMessage({ type: 'addThreatPoints', points: 3 });
      }
    } catch (e) {
      console.warn('[SafeSearch] Fetch hook error:', e);
    }
    
    return originalFetch.apply(this, args);
  };
})();

//Hook XMLHttpRequest

(function hookXHR() {
  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url) {
    this._safeSearch_url = url;
    return originalOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function (body) {
    const url = this._safeSearch_url || '';
    const isCrossSite = isSuspiciousDomain(url);

    if (isCrossSite && this.withCredentials) {
      injectWarningBanner(`⚠️ XMLHttpRequest with credentials to suspicious domain: ${url}`);
      chrome.runtime.sendMessage({
        type: 'alert',
        details: `⚠️ XMLHttpRequest with credentials sent to ${url}`
      });
      chrome.runtime.sendMessage({ type: 'addThreatPoints', points: 3 });
    }

    return originalSend.apply(this, arguments);
  };
})();

