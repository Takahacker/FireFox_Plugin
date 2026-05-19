'use strict';

function getDomain(url) {
  try {
    const host = new URL(url).hostname;
    return host.startsWith('www.') ? host.slice(4) : host;
  } catch {
    return '';
  }
}

// Inject hook script into the page's JS context so it can intercept native APIs
function injectHookScript() {
  const script = document.createElement('script');
  script.src = browser.runtime.getURL('inject.js');
  script.onload = () => script.remove();
  (document.head || document.documentElement).appendChild(script);
}

// Forward fingerprinting and hijacking events from inject.js to background
window.addEventListener('message', (event) => {
  if (!event.data || event.data.source !== 'PRIVACY_GUARD') return;

  if (event.data.type === 'FINGERPRINT') {
    browser.runtime.sendMessage({
      type: 'FINGERPRINT_DETECTED',
      payload: { api: event.data.api, method: event.data.method }
    }).catch(() => {});
  }

  if (event.data.type === 'HIJACK') {
    browser.runtime.sendMessage({
      type: 'HIJACK_DETECTED',
      payload: event.data.data
    }).catch(() => {});
  }
});

// Watch for dynamically injected external scripts after page load (hijacking indicator)
function watchForDynamicScripts() {
  const pageDomain = getDomain(window.location.href);
  let initialLoadDone = false;

  const observer = new MutationObserver((mutations) => {
    if (!initialLoadDone) return;

    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;

        const scripts = node.tagName === 'SCRIPT'
          ? [node]
          : (node.querySelectorAll ? Array.from(node.querySelectorAll('script[src]')) : []);

        for (const script of scripts) {
          if (!script.src) continue;
          const srcDomain = getDomain(script.src);
          if (!srcDomain || srcDomain === pageDomain) continue;

          // External script injected dynamically after page load
          browser.runtime.sendMessage({
            type: 'HIJACK_DETECTED',
            payload: {
              type: 'dynamic-script',
              domain: srcDomain,
              url: script.src.substring(0, 150),
              reason: 'External script dynamically injected post-load'
            }
          }).catch(() => {});
        }
      }
    }
  });

  observer.observe(document.documentElement, { childList: true, subtree: true });

  // Only flag scripts injected AFTER initial page load
  if (document.readyState === 'complete') {
    initialLoadDone = true;
  } else {
    window.addEventListener('load', () => { initialLoadDone = true; }, { once: true });
  }
}

// Read localStorage and sessionStorage contents
function collectWebStorage() {
  const local = {};
  const session = {};

  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      const value = localStorage.getItem(key) || '';
      local[key] = { size: key.length + value.length, preview: value.substring(0, 80) };
    }
  } catch { /* storage may be disabled */ }

  try {
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      const value = sessionStorage.getItem(key) || '';
      session[key] = { size: key.length + value.length, preview: value.substring(0, 80) };
    }
  } catch { /* storage may be disabled */ }

  return { local, session };
}

// List available IndexedDB databases
async function collectIndexedDB() {
  const databases = [];
  try {
    if (typeof indexedDB !== 'undefined' && indexedDB.databases) {
      const dbs = await indexedDB.databases();
      for (const db of dbs) {
        databases.push({ name: db.name, version: db.version });
      }
    }
  } catch { /* may not be available */ }
  return databases;
}

async function collectAndReport() {
  const { local, session } = collectWebStorage();
  const idb = await collectIndexedDB();

  browser.runtime.sendMessage({
    type: 'STORAGE_DATA',
    payload: {
      domain: window.location.hostname,
      localStorage: local,
      sessionStorage: session,
      indexedDB: idb
    }
  }).catch(() => {});
}

// Initialize
injectHookScript();
watchForDynamicScripts();

// Collect storage data once the page has fully loaded
if (document.readyState === 'complete') {
  collectAndReport();
} else {
  window.addEventListener('load', collectAndReport, { once: true });
}
