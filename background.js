'use strict';

// Per-tab data store (in-memory)
const tabData = new Map();

// Known tracking/advertising domains
const KNOWN_TRACKERS = [
  'google-analytics.com', 'googletagmanager.com', 'googletagservices.com',
  'doubleclick.net', 'googlesyndication.com', 'adservice.google.com',
  'facebook.com', 'fbcdn.net', 'facebook.net', 'connect.facebook.net',
  'amazon-adsystem.com', 'hotjar.com', 'mixpanel.com',
  'segment.io', 'segment.com', 'chartbeat.com', 'quantserve.com',
  'scorecardresearch.com', 'outbrain.com', 'taboola.com',
  'criteo.com', 'criteo.net', 'adroll.com', 'bat.bing.com',
  'mc.yandex.ru', 'clarity.ms', 'newrelic.com', 'nr-data.net',
  'optimizely.com', 'amplitude.com', 'cdn.amplitude.com',
  'intercom.io', 'ads.twitter.com', 'static.ads-twitter.com',
  'snap.licdn.com', 'px.ads.linkedin.com', 'analytics.tiktok.com',
  'analytics.pinterest.com', 'ct.pinterest.com', 'sc-static.net',
  'mouseflow.com', 'fullstory.com', 'heap.io', 'heapanalytics.com',
  'logrocket.com', 'crazyegg.com', 'kissmetrics.com', 'hubspot.com',
  'hs-analytics.net', 'hs-scripts.com', 'pardot.com', 'marketo.net',
  'braze.com', 'branch.io', 'adjust.com', 'appsflyer.com'
];

function getDomain(url) {
  try {
    const host = new URL(url).hostname;
    return host.startsWith('www.') ? host.slice(4) : host;
  } catch {
    return '';
  }
}

function isSubdomainOf(host, domain) {
  return host === domain || host.endsWith('.' + domain);
}

function isThirdParty(requestUrl, pageUrl) {
  const reqDomain = getDomain(requestUrl);
  const pageDomain = getDomain(pageUrl);
  if (!reqDomain || !pageDomain) return false;
  return !isSubdomainOf(reqDomain, pageDomain) && !isSubdomainOf(pageDomain, reqDomain);
}

function isKnownTracker(domain) {
  return KNOWN_TRACKERS.some(t => isSubdomainOf(domain, t));
}

function createTabEntry(url) {
  return {
    pageUrl: url,
    pageDomain: getDomain(url),
    thirdPartyRequests: [],
    supercookies: [],
    storage: null,
    fingerprinting: [],
    hijacking: { suspiciousScripts: [], redirects: [] },
    lastUpdate: Date.now()
  };
}

// Reset data when tab navigates to a new page
browser.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    tabData.set(tabId, createTabEntry(changeInfo.url));
  }
});

browser.tabs.onRemoved.addListener((tabId) => {
  tabData.delete(tabId);
});

// Track all network requests to identify third-party connections
browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    const { tabId, url, type } = details;
    if (tabId < 0) return;

    if (type === 'main_frame') {
      tabData.set(tabId, createTabEntry(url));
      return;
    }

    const data = tabData.get(tabId);
    if (!data || !data.pageUrl) return;
    if (!isThirdParty(url, data.pageUrl)) return;

    const domain = getDomain(url);
    const existing = data.thirdPartyRequests.find(
      r => r.domain === domain && r.type === type
    );

    if (existing) {
      existing.count++;
    } else {
      data.thirdPartyRequests.push({
        domain,
        type,
        url: url.length > 120 ? url.substring(0, 120) + '...' : url,
        isTracker: isKnownTracker(domain),
        count: 1,
        timestamp: Date.now()
      });
    }
  },
  { urls: ['<all_urls>'] }
);

// Inspect response headers for ETag/HSTS supercookies and suspicious redirects
browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    const { tabId, url, responseHeaders, statusCode, type } = details;
    if (tabId < 0 || !responseHeaders) return;

    const data = tabData.get(tabId);
    if (!data || !data.pageUrl) return;

    const domain = getDomain(url);
    const third = isThirdParty(url, data.pageUrl);

    for (const header of responseHeaders) {
      const name = header.name.toLowerCase();
      const value = (header.value || '').substring(0, 120);

      // ETag supercookie: third-party resources set ETags that persist across sessions
      if (name === 'etag' && third) {
        if (!data.supercookies.find(s => s.domain === domain && s.type === 'ETag')) {
          data.supercookies.push({
            type: 'ETag',
            domain,
            value,
            description: 'ETag identifiers persist across cookie clearing and can re-identify users'
          });
        }
      }

      // HSTS supercookie: encodes bits by forcing HTTPS on specific subdomains
      if (name === 'strict-transport-security' && third) {
        if (!data.supercookies.find(s => s.domain === domain && s.type === 'HSTS')) {
          data.supercookies.push({
            type: 'HSTS',
            domain,
            value,
            description: 'HSTS headers from third parties can encode a persistent tracking identifier'
          });
        }
      }

      // Cross-origin redirects on main page navigation (potential hijacking)
      if (name === 'location' && type === 'main_frame' &&
          (statusCode === 301 || statusCode === 302 || statusCode === 307 || statusCode === 308)) {
        const toDomain = getDomain(value);
        if (toDomain && toDomain !== domain) {
          data.hijacking.redirects.push({
            statusCode,
            fromDomain: domain,
            toDomain,
            fromUrl: url.length > 100 ? url.substring(0, 100) + '...' : url,
            toUrl: value.length > 100 ? value.substring(0, 100) + '...' : value
          });
        }
      }
    }
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

// Fetch cookies for the current tab's page
async function getCookiesForTab(tabId) {
  const data = tabData.get(tabId);
  if (!data || !data.pageUrl) return [];

  try {
    const all = await browser.cookies.getAll({ url: data.pageUrl });
    const pageDomain = data.pageDomain;
    return all.map(c => {
      const cDomain = c.domain.replace(/^\./, '');
      const isFirst = isSubdomainOf(cDomain, pageDomain) || isSubdomainOf(pageDomain, cDomain);
      return {
        name: c.name,
        domain: c.domain,
        isFirstParty: isFirst,
        isSession: !c.expirationDate,
        httpOnly: c.httpOnly,
        secure: c.secure,
        sameSite: c.sameSite || 'no_restriction',
        size: (c.name + '=' + c.value).length
      };
    });
  } catch {
    return [];
  }
}

// Handle messages from content scripts and popup
browser.runtime.onMessage.addListener((message, sender) => {
  // Popup requests data for a specific tab
  if (message.type === 'GET_TAB_DATA') {
    const tid = message.tabId;
    const d = tabData.get(tid);
    if (!d) return Promise.resolve(null);
    return getCookiesForTab(tid).then(cookies => ({ ...d, cookies }));
  }

  // Messages from content scripts
  const tabId = sender.tab ? sender.tab.id : -1;
  if (tabId < 0) return;

  const data = tabData.get(tabId);
  if (!data) return;

  if (message.type === 'STORAGE_DATA') {
    data.storage = message.payload;
    data.lastUpdate = Date.now();
    return;
  }

  if (message.type === 'FINGERPRINT_DETECTED') {
    const { api, method } = message.payload;
    const existing = data.fingerprinting.find(f => f.api === api && f.method === method);
    if (existing) {
      existing.count++;
    } else {
      data.fingerprinting.push({ api, method, count: 1, timestamp: Date.now() });
    }
    data.lastUpdate = Date.now();
    return;
  }

  if (message.type === 'HIJACK_DETECTED') {
    data.hijacking.suspiciousScripts.push(message.payload);
    data.lastUpdate = Date.now();
  }
});
