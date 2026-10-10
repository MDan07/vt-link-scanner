importScripts('utils.js');

const VT_API = 'https://www.virustotal.com/api/v3';
const CACHE_MAX = 500;
const CACHE_TTL = {
  found: 24 * 60 * 60 * 1000,
  unknown: 30 * 60 * 1000
};
const MENU_ID = 'vt-scan-link';

const KEY_COOLDOWN_MS = 65 * 1000;
const KEY_INVALID_COOLDOWN_MS = 10 * 60 * 1000;

const inFlight = new Map();
const keyState = new Map();
let keyCursor = 0;
let historyQueue = Promise.resolve();
let cacheQueue = Promise.resolve();
let exceptionQueue = Promise.resolve();

// ---------- Setup ----------

function lockStorage() {
  if (chrome.storage.local.setAccessLevel) {
    chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }).catch(() => {});
  }
}

lockStorage();

function ensureContextMenu() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: MENU_ID,
      title: 'Scan link with VirusTotal',
      contexts: ['link']
    }, () => {
      // Ignore harmless duplicate/context-menu startup errors.
      void chrome.runtime.lastError;
    });
  });
}

chrome.runtime.onInstalled.addListener(() => {
  lockStorage();
  ensureContextMenu();
});

chrome.runtime.onStartup.addListener(() => {
  lockStorage();
  ensureContextMenu();
});

// ---------- Automatic download monitoring ----------
//
// Chrome exposes download metadata (filename, URL, size, state), but ordinary
// MV3 extensions do not receive arbitrary bytes from the Downloads folder.
// We therefore automatically detect completed downloads and queue them for the
// File Scanner. The actual file must still be selected by the user unless a
// Native Messaging helper is installed.
chrome.downloads.onChanged.addListener(async (delta) => {
  if (!delta || !delta.state || delta.state.current !== 'complete') return;

  try {
    const settings = await getSettings();
    if (!settings.autoDownloadMonitor) return;

    const items = await chrome.downloads.search({ id: delta.id });
    const item = items?.[0];
    if (!item) return;

    const entry = {
      id: item.id,
      filename: item.filename || '',
      url: item.url || '',
      size: item.fileSize || 0,
      endTime: item.endTime || new Date().toISOString(),
      detectedAt: Date.now()
    };

    const { recentDownloads = [] } = await chrome.storage.local.get('recentDownloads');
    await chrome.storage.local.set({
      recentDownloads: [
        entry,
        ...recentDownloads.filter((d) => d.id !== item.id)
      ].slice(0, 20)
    });

    // Do not open a tab automatically for every download. Notify the user
    // that the completed download was detected and provide a direct action.
    if (chrome.notifications?.create) {
      chrome.notifications.create(`vt-download-${item.id}`, {
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: 'VT Link Scanner',
        message: `Download detected: ${basename(item.filename)}. Click to scan it with VirusTotal.`,
        priority: 1
      }).catch(() => {});
    }
  } catch (e) {}
});

if (chrome.notifications?.onClicked) {
  chrome.notifications.onClicked.addListener((notificationId) => {
    const match = /^vt-download-(\d+)$/.exec(notificationId);
    if (!match) return;

    const downloadId = Number(match[1]);
    chrome.tabs.create({
      url: chrome.runtime.getURL(`file-scanner.html?downloadId=${downloadId}`)
    }).catch(() => {});

    chrome.notifications.clear(notificationId).catch(() => {});
  });
}

function basename(path) {
  const value = String(path || '');
  return value.split(/[\\/]/).pop() || value || 'download';
}

// ---------- Messages ----------

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return;

  switch (request.action) {
    case 'scanUrl':
      handleScan(request.url, sender.tab?.id, {
        force: false,
        pageUrl: request.pageUrl || sender.tab?.url || ''
      }).then(sendResponse);
      return true;

    case 'openTab':
      openTab(request.url, request.mode, sender.tab);
      sendResponse({ ok: true });
      return false;

    case 'addException':
      addException(request.domain).then(sendResponse);
      return true;

    case 'validateKey':
      validateKey(request.key).then(sendResponse);
      return true;

    case 'getApiKeyCount':
      getApiKeys().then((keys) => sendResponse({ count: keys.length }));
      return true;

    case 'deepScanUrl':
      deepScanUnknown(request.url, sender.tab?.id).then(sendResponse);
      return true;
  }
});

// Right-click -> Scan link with VirusTotal.
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== MENU_ID || !tab?.id || !info.linkUrl) return;

  const target = { frameId: info.frameId || 0 };

  chrome.tabs.sendMessage(
    tab.id,
    { action: 'showResult', url: info.linkUrl, pending: true },
    target
  ).catch(() => {});

  const result = await handleScan(info.linkUrl, tab.id, {
    force: true,
    pageUrl: tab.url || ''
  });

  chrome.tabs.sendMessage(
    tab.id,
    { action: 'showResult', url: info.linkUrl, result },
    target
  ).catch(() => {});
});

// ---------- API keys ----------

async function getApiKeys() {
  const data = await chrome.storage.local.get(['vtApiKeys', 'vtApiKey']);
  let keys = Array.isArray(data.vtApiKeys)
    ? data.vtApiKeys
    : [];

  // One-time migration from v1.x.
  if (keys.length === 0 && typeof data.vtApiKey === 'string' && data.vtApiKey.trim()) {
    keys = [data.vtApiKey.trim()];
    await chrome.storage.local.set({ vtApiKeys: keys });
  }

  keys = [...new Set(
    keys
      .filter((key) => typeof key === 'string')
      .map((key) => key.trim())
      .filter(Boolean)
  )];

  return keys;
}

function keyIsAvailable(key) {
  const state = keyState.get(key);
  if (!state) return true;
  return Date.now() >= Math.max(state.cooldownUntil || 0, state.invalidUntil || 0);
}

function markKeyRateLimited(key) {
  const state = keyState.get(key) || {};
  keyState.set(key, {
    ...state,
    cooldownUntil: Date.now() + KEY_COOLDOWN_MS
  });
}

function markKeyInvalid(key) {
  const state = keyState.get(key) || {};
  keyState.set(key, {
    ...state,
    invalidUntil: Date.now() + KEY_INVALID_COOLDOWN_MS
  });
}

function markKeyHealthy(key) {
  keyState.delete(key);
}

function nextAvailableKey(keys, attempted) {
  if (!keys.length) return null;

  for (let offset = 0; offset < keys.length; offset++) {
    const index = (keyCursor + offset) % keys.length;
    const key = keys[index];

    if (attempted.has(key)) continue;
    if (!keyIsAvailable(key)) continue;

    keyCursor = (index + 1) % keys.length;
    return key;
  }

  return null;
}

/*
 * Every VirusTotal request is allowed to rotate through the configured keys.
 * A 429 marks that key as cooling down and immediately tries another key.
 * A 401/403 temporarily disables that key and tries another one.
 */
async function vtRequest(path, options = {}) {
  const keys = await getApiKeys();

  if (!keys.length) {
    return {
      error: 'No VirusTotal API keys configured.',
      code: 'no_keys'
    };
  }

  const attempted = new Set();
  let sawRateLimit = false;
  let sawRejected = false;

  while (attempted.size < keys.length) {
    const key = nextAvailableKey(keys, attempted);
    if (!key) break;

    attempted.add(key);

    let response;
    try {
      response = await fetch(VT_API + path, {
        ...options,
        headers: {
          ...(options.headers || {}),
          'x-apikey': key,
          'Accept': 'application/json'
        }
      });
    } catch (e) {
      return {
        error: 'Could not reach VirusTotal (network error).',
        code: 'network'
      };
    }

    if (response.status === 429) {
      sawRateLimit = true;
      markKeyRateLimited(key);
      continue;
    }

    if (response.status === 401 || response.status === 403) {
      sawRejected = true;
      markKeyInvalid(key);
      continue;
    }

    markKeyHealthy(key);

    return {
      response,
      key
    };
  }

  if (sawRateLimit) {
    return {
      error: 'All configured VirusTotal API keys are currently rate-limited. Try again shortly.',
      code: 'rate_limited'
    };
  }

  if (sawRejected) {
    return {
      error: 'All configured VirusTotal API keys were rejected by VirusTotal. Check your keys in the extension popup.',
      code: 'keys_rejected'
    };
  }

  return {
    error: 'No usable VirusTotal API key is currently available.',
    code: 'no_usable_key'
  };
}

// ---------- Scanning ----------

async function handleScan(rawUrl, tabId, { force = false, pageUrl = '' } = {}) {
  try {
    const url = canonicalizeHttpUrl(rawUrl);
    if (!url) return { error: 'Invalid or unsupported URL.' };

    const [data, settings] = await Promise.all([
      chrome.storage.local.get(['exceptions']),
      getSettings()
    ]);

    if (!force && !settings.enabled) {
      return { status: 'skipped', reason: 'disabled' };
    }

    if (!force && isTrustedHost(url.hostname, data.exceptions)) {
      return { status: 'skipped', reason: 'trusted' };
    }

    if (!force && !settings.scanSameSite && pageUrl) {
      try {
        const page = new URL(pageUrl);
        if (page.origin === url.origin) {
          return { status: 'skipped', reason: 'sameSite' };
        }
      } catch (e) {}
    }

    const apiKeys = await getApiKeys();
    if (!apiKeys.length) {
      return force
        ? { error: 'No VirusTotal API keys set. Add one or more in the extension popup.', code: 'no_keys' }
        : { status: 'skipped', reason: 'nokey' };
    }

    const target = buildLookup(url, settings.privacyMode);
    const heuristics = analyzeUrlHeuristics(url);

    let report = await getCached(target.key);
    const cached = !!report;

    if (!report) {
      if (!inFlight.has(target.key)) {
        const p = lookup(target, settings)
          .finally(() => inFlight.delete(target.key));
        inFlight.set(target.key, p);
      }

      report = await inFlight.get(target.key);
      if (report.error) return report;

      await setCached(target.key, report);
    }

    // For genuinely unknown URLs, a domain reputation check adds useful
    // context without submitting the URL itself. It is cached independently.
    let domainReport = null;
    if (!report.found && target.kind === 'url') {
      domainReport = await getDomainReport(url.hostname);
    }

    let domainAge = null;
    if (!report.found || heuristics.score >= 35) {
      domainAge = await getDomainAge(url.hostname);
    }

    const enriched = applyRiskSignals(report, heuristics, domainReport, domainAge, settings.minDetections);
    const status = enriched.status;

    const result = {
      status,
      malicious: report.malicious || 0,
      suspicious: report.suspicious || 0,
      vtLink: target.vtLink,
      lookedUp: target.kind,
      domain: url.hostname,
      submitted: !!report.submitted,
      cached,
      warnOnUnknown: settings.warnOnUnknown,
      redirected: !!report.redirected,
      finalUrl: report.finalUrl || null,
      finalStatus: report.finalStatus || null,
      riskScore: enriched.riskScore,
      riskLevel: enriched.riskLevel,
      riskSignals: enriched.signals,
      domainMalicious: domainReport?.malicious || 0,
      domainSuspicious: domainReport?.suspicious || 0,
      domainFound: !!domainReport?.found,
      domainAgeDays: domainAge?.ageDays ?? null,
      domainCreatedAt: domainAge?.createdAt || null,
      domainAgeSource: domainAge?.source || null
    };

    const badge = {
      safe: ['✓', '#22c55e'],
      unknown: ['?', '#d97706'],
      suspicious: ['!', '#d97706'],
      malicious: ['✕', '#ef4444']
    }[status];

    setBadge(tabId, badge[0], badge[1]);

    await logScanHistory({
      url: url.href,
      status,
      malicious: report.malicious || 0,
      suspicious: report.suspicious || 0,
      vtLink: target.vtLink,
      lookedUp: target.kind,
      redirected: !!report.redirected,
      finalUrl: report.finalUrl || null,
      riskScore: enriched.riskScore,
      riskLevel: enriched.riskLevel,
      timestamp: Date.now()
    });

    return result;
  } catch (err) {
    return { error: err.message || String(err), code: 'unexpected' };
  }
}

// Explicit deep scan for an unknown URL. The user must choose this action,
// because submitting a URL to VirusTotal can make it visible there.
async function deepScanUnknown(rawUrl, tabId) {
  const url = canonicalizeHttpUrl(rawUrl);
  if (!url) return { error: 'Invalid or unsupported URL.', code: 'bad_url' };

  const settings = await getSettings();
  const target = buildLookup(url, settings.privacyMode);
  const submit = await submitUrl(target.url);
  if (!submit.ok) {
    return { error: submit.error || 'Could not submit this URL to VirusTotal.', code: submit.code || 'submit_failed' };
  }

  const analysisId = submit.analysisId;
  if (analysisId) {
    const completed = await waitForAnalysis(analysisId, 60000, 3000);
    if (completed.error) return completed;
  }

  // The URL report may become available immediately after analysis completes.
  const fresh = await lookup(target, { submitUnknown: false, checkRedirectDestination: settings.checkRedirectDestination, privacyMode: settings.privacyMode });
  if (fresh.error) return fresh;

  await setCached(target.key, fresh);

  const heuristics = analyzeUrlHeuristics(url);
  const domainReport = !fresh.found ? await getDomainReport(url.hostname) : null;
  const domainAge = !fresh.found || heuristics.score >= 35 ? await getDomainAge(url.hostname) : null;
  const enriched = applyRiskSignals(fresh, heuristics, domainReport, domainAge, settings.minDetections);

  const result = {
    status: enriched.status,
    malicious: fresh.malicious || 0,
    suspicious: fresh.suspicious || 0,
    vtLink: target.vtLink,
    lookedUp: 'url',
    domain: url.hostname,
    submitted: true,
    cached: false,
    warnOnUnknown: true,
    redirected: !!fresh.redirected,
    finalUrl: fresh.finalUrl || null,
    finalStatus: fresh.finalStatus || null,
    riskScore: enriched.riskScore,
    riskLevel: enriched.riskLevel,
    riskSignals: enriched.signals,
    domainMalicious: domainReport?.malicious || 0,
    domainSuspicious: domainReport?.suspicious || 0,
    domainFound: !!domainReport?.found,
    domainAgeDays: domainAge?.ageDays ?? null,
    domainCreatedAt: domainAge?.createdAt || null,
    domainAgeSource: domainAge?.source || null,
    deepScanned: true
  };

  const badge = {
    safe: ['✓', '#22c55e'], unknown: ['?', '#d97706'],
    suspicious: ['!', '#d97706'], malicious: ['✕', '#ef4444']
  }[result.status];
  setBadge(tabId, badge[0], badge[1]);

  await logScanHistory({
    url: url.href,
    status: result.status,
    malicious: result.malicious,
    suspicious: result.suspicious,
    vtLink: result.vtLink,
    lookedUp: 'url',
    riskScore: result.riskScore,
    riskLevel: result.riskLevel,
    timestamp: Date.now()
  });

  return result;
}

async function waitForAnalysis(analysisId, timeoutMs, intervalMs) {
  const started = Date.now();

  while (Date.now() - started < timeoutMs) {
    const result = await vtRequest(`/analyses/${encodeURIComponent(analysisId)}`, { method: 'GET' });
    if (result.error) return result;

    if (!result.response.ok) {
      if (result.response.status === 404) {
        await sleep(intervalMs);
        continue;
      }
      return { error: `VirusTotal analysis API error ${result.response.status}.`, code: 'analysis_api_error' };
    }

    let json;
    try {
      json = await result.response.json();
    } catch (e) {
      return { error: 'VirusTotal returned an invalid analysis response.', code: 'bad_analysis_response' };
    }

    const status = json?.data?.attributes?.status;
    if (status === 'completed') return { ok: true };
    if (status === 'failed') return { error: 'VirusTotal could not complete the analysis.', code: 'analysis_failed' };

    await sleep(intervalMs);
  }

  return {
    error: 'VirusTotal is still analyzing this URL. Try scanning again in a moment.',
    code: 'analysis_timeout'
  };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildLookup(url, privacyMode) {
  if (privacyMode && url.search) {
    const domain = url.hostname.toLowerCase();
    return {
      kind: 'domain',
      key: 'd:' + domain,
      apiPath: `/domains/${encodeURIComponent(domain)}`,
      vtLink: `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}/detection`,
      url: url.href
    };
  }

  const id = toVtUrlId(url.href);
  return {
    kind: 'url',
    key: 'u:' + url.href,
    apiPath: `/urls/${id}`,
    vtLink: `https://www.virustotal.com/gui/url/${id}/detection`,
    url: url.href
  };
}

function toVtUrlId(str) {
  let bin = '';
  for (const b of new TextEncoder().encode(str)) {
    bin += String.fromCharCode(b);
  }
  return btoa(bin)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// VirusTotal URL reports may contain the last known final URL after redirects.
// If configured, scan that final URL too. This does not perform a live redirect
// itself, so it remains conservative and never claims a future redirect is safe.
async function lookup(target, settings) {
  const responseResult = await vtRequest(target.apiPath, {
    method: 'GET'
  });

  if (responseResult.error) return responseResult;

  const response = responseResult.response;

  if (response.status === 404) {
    if (settings.submitUnknown && target.kind === 'url') {
      const submission = await submitUrl(target.url);
      if (submission.ok && submission.analysisId) {
        const completed = await waitForAnalysis(submission.analysisId, 60000, 3000);
        if (completed.ok) {
          const refreshed = await vtRequest(target.apiPath, { method: 'GET' });
          if (!refreshed.error && refreshed.response.ok) {
            try {
              const refreshedJson = await refreshed.response.json();
              const refreshedStats = refreshedJson?.data?.attributes?.last_analysis_stats;
              if (refreshedStats) {
                return {
                  found: true,
                  malicious: refreshedStats.malicious || 0,
                  suspicious: refreshedStats.suspicious || 0,
                  submitted: true
                };
              }
            } catch (e) {}
          }
        }
      }

      return {
        found: false,
        malicious: 0,
        suspicious: 0,
        submitted: !!submission.ok
      };
    }

    return {
      found: false,
      malicious: 0,
      suspicious: 0,
      submitted: false
    };
  }

  if (!response.ok) {
    return { error: `VirusTotal API error ${response.status}.`, code: 'api_error' };
  }

  let json;
  try {
    json = await response.json();
  } catch (e) {
    return { error: 'VirusTotal returned an invalid response.', code: 'bad_response' };
  }

  const attrs = json?.data?.attributes || {};
  const stats = attrs.last_analysis_stats;

  if (!stats) {
    return { found: false, malicious: 0, suspicious: 0 };
  }

  const report = {
    found: true,
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0
  };

  if (target.kind !== 'url' || !settings.checkRedirectDestination) {
    return report;
  }

  const finalUrl = extractFinalUrl(attrs);
  if (!finalUrl) return report;

  const original = canonicalizeHttpUrl(target.url);
  const final = canonicalizeHttpUrl(finalUrl);

  if (!original || !final || final.href === original.href) {
    return report;
  }

  const finalTarget = buildLookup(final, settings.privacyMode);
  const finalResult = await vtRequest(finalTarget.apiPath, { method: 'GET' });

  if (finalResult.error) {
    // Do not turn an otherwise useful initial result into a hard failure.
    return {
      ...report,
      redirected: true,
      finalUrl: final.href,
      finalStatus: 'unavailable'
    };
  }

  if (finalResult.response.status === 404) {
    return {
      ...report,
      redirected: true,
      finalUrl: final.href,
      finalStatus: 'unknown'
    };
  }

  if (!finalResult.response.ok) {
    return {
      ...report,
      redirected: true,
      finalUrl: final.href,
      finalStatus: 'unavailable'
    };
  }

  let finalJson;
  try {
    finalJson = await finalResult.response.json();
  } catch (e) {
    return {
      ...report,
      redirected: true,
      finalUrl: final.href,
      finalStatus: 'unavailable'
    };
  }

  const finalStats = finalJson?.data?.attributes?.last_analysis_stats;
  if (!finalStats) {
    return {
      ...report,
      redirected: true,
      finalUrl: final.href,
      finalStatus: 'unknown'
    };
  }

  const finalMalicious = finalStats.malicious || 0;
  const finalSuspicious = finalStats.suspicious || 0;

  // A malicious/suspicious final destination takes precedence.
  if (finalMalicious > 0 || finalSuspicious > 0) {
    return {
      found: true,
      malicious: Math.max(report.malicious, finalMalicious),
      suspicious: Math.max(report.suspicious, finalSuspicious),
      redirected: true,
      finalUrl: final.href,
      finalStatus: finalMalicious > 0 ? 'malicious' : 'suspicious'
    };
  }

  return {
    ...report,
    redirected: true,
    finalUrl: final.href,
    finalStatus: 'safe'
  };
}

function extractFinalUrl(attrs) {
  const candidates = [
    attrs.last_final_url,
    attrs.last_http_response?.url
  ];

  for (const value of candidates) {
    if (typeof value !== 'string' || !value) continue;
    const u = canonicalizeHttpUrl(value);
    if (u) return u.href;
  }

  return null;
}

async function submitUrl(url) {
  const body = new URLSearchParams({ url });

  const result = await vtRequest('/urls', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: body.toString()
  });

  if (result.error) return { error: result.error, code: result.code };

  if (!result.response.ok) {
    return { error: `VirusTotal submission failed (${result.response.status}).`, code: 'submit_failed' };
  }

  let json = {};
  try { json = await result.response.json(); } catch (e) {}

  return {
    ok: true,
    analysisId: json?.data?.id || null
  };
}

function classify(report, minDetections) {
  if (!report.found) return 'unknown';
  if (report.malicious >= Math.max(1, minDetections)) return 'malicious';
  if (report.malicious + report.suspicious > 0) return 'suspicious';
  if (report.finalStatus === 'unknown') return 'unknown';
  return 'safe';
}

function analyzeUrlHeuristics(url) {
  const signals = [];
  let score = 0;
  const host = url.hostname.toLowerCase();
  const href = url.href;

  if (url.protocol === 'http:') {
    score += 10;
    signals.push('Uses unencrypted HTTP');
  }

  if (host.includes('xn--')) {
    score += 20;
    signals.push('Punycode domain (possible look-alike domain)');
  }

  if (url.username || url.password || href.includes('@')) {
    score += 30;
    signals.push('URL contains a deceptive @/userinfo structure');
  }

  if (isIpHostname(host)) {
    score += 25;
    signals.push('Uses an IP address instead of a normal domain');
  }

  if (href.length > 180) {
    score += 10;
    signals.push('Unusually long URL');
  }

  const labels = host.split('.').filter(Boolean);
  if (labels.length >= 5) {
    score += 10;
    signals.push('Many subdomains');
  }

  const suspiciousTlds = new Set([
    'zip', 'mov', 'click', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq',
    'work', 'download', 'link', 'live', 'buzz', 'fit', 'cam', 'rest'
  ]);
  const tld = labels[labels.length - 1];
  if (tld && suspiciousTlds.has(tld)) {
    score += 10;
    signals.push(`Higher-risk TLD: .${tld}`);
  }

  const encodedCount = (href.match(/%[0-9a-f]{2}/gi) || []).length;
  if (encodedCount >= 6) {
    score += 8;
    signals.push('Heavy URL encoding');
  }

  if (Array.from(url.searchParams.keys()).length >= 8) {
    score += 7;
    signals.push('Many query parameters');
  }

  return {
    score: Math.min(100, score),
    signals
  };
}

function isIpHostname(host) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true;
  return host.includes(':');
}

async function getDomainReport(hostname) {
  const domain = String(hostname || '').toLowerCase();
  if (!domain || !domain.includes('.')) return null;

  const key = `d:${domain}`;
  let cached = await getCached(key);
  if (cached) return cached;

  const result = await vtRequest(`/domains/${encodeURIComponent(domain)}`, { method: 'GET' });
  if (result.error) return null;
  if (result.response.status === 404) return { found: false, malicious: 0, suspicious: 0 };
  if (!result.response.ok) return null;

  try {
    const json = await result.response.json();
    const stats = json?.data?.attributes?.last_analysis_stats;
    if (!stats) return { found: false, malicious: 0, suspicious: 0 };

    const report = {
      found: true,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0
    };
    await setCached(key, report);
    return report;
  } catch (e) {
    return null;
  }
}

async function getDomainAge(hostname) {
  const domain = String(hostname || '').toLowerCase();
  if (!domain || isIpHostname(domain) || !domain.includes('.')) return null;

  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      method: 'GET',
      headers: { 'Accept': 'application/rdap+json, application/json' }
    });
    if (!res.ok) return null;

    const json = await res.json();
    const events = Array.isArray(json.events) ? json.events : [];
    const created = events.find((e) => e.eventAction === 'registration') ||
      events.find((e) => e.eventAction === 'creation');
    if (!created?.eventDate) return null;

    const createdAt = new Date(created.eventDate);
    if (Number.isNaN(createdAt.getTime())) return null;

    const ageDays = Math.max(0, Math.floor((Date.now() - createdAt.getTime()) / 86400000));
    return {
      createdAt: createdAt.toISOString(),
      ageDays,
      source: 'RDAP'
    };
  } catch (e) {
    return null;
  }
}

function applyRiskSignals(report, heuristics, domainReport, domainAge, minDetections) {
  let score = heuristics.score;
  const signals = [...heuristics.signals];

  if (domainReport?.found) {
    if (domainReport.malicious >= Math.max(1, minDetections)) {
      score += 55;
      signals.push(`Domain flagged by ${domainReport.malicious} VirusTotal engine(s)`);
    } else if (domainReport.malicious + domainReport.suspicious > 0) {
      score += 30;
      signals.push('Domain has VirusTotal detections');
    }
  }

  if (domainAge?.ageDays != null) {
    if (domainAge.ageDays < 7) {
      score += 20;
      signals.push('Domain registered less than 7 days ago');
    } else if (domainAge.ageDays < 30) {
      score += 12;
      signals.push('Domain registered less than 30 days ago');
    } else if (domainAge.ageDays > 3650) {
      score = Math.max(0, score - 5);
    }
  }

  score = Math.min(100, Math.max(0, score));
  let riskLevel = 'low';
  if (score >= 80) riskLevel = 'critical';
  else if (score >= 60) riskLevel = 'high';
  else if (score >= 40) riskLevel = 'moderate';

  let status = classify(report, minDetections);

  // Heuristics never manufacture a malicious verdict. They can, however,
  // upgrade a clean/unknown result to a warning when enough risk signals exist.
  if (domainReport?.malicious >= Math.max(1, minDetections)) {
    status = 'malicious';
  } else if (status === 'safe' && score >= 60) {
    status = 'suspicious';
  } else if (status === 'unknown' && domainReport?.malicious + domainReport?.suspicious > 0) {
    status = 'suspicious';
  } else if (status === 'unknown' && score >= 60) {
    status = 'suspicious';
  }

  return {
    status,
    riskScore: score,
    riskLevel,
    signals: signals.slice(0, 8)
  };
}

// ---------- Cache ----------

async function getCached(key) {
  const { scanCache = {} } = await chrome.storage.local.get('scanCache');
  const entry = scanCache[key];
  if (!entry) return null;

  const ttl = entry.report?.found ? CACHE_TTL.found : CACHE_TTL.unknown;
  return Date.now() - entry.time < ttl ? entry.report : null;
}

function setCached(key, report) {
  cacheQueue = cacheQueue.then(async () => {
    const { scanCache = {} } = await chrome.storage.local.get('scanCache');

    scanCache[key] = {
      time: Date.now(),
      report: {
        found: !!report.found,
        malicious: report.malicious || 0,
        suspicious: report.suspicious || 0,
        submitted: !!report.submitted,
        redirected: !!report.redirected,
        finalUrl: report.finalUrl || null,
        finalStatus: report.finalStatus || null
      }
    };

    const keys = Object.keys(scanCache);
    if (keys.length > CACHE_MAX) {
      keys
        .sort((a, b) => scanCache[a].time - scanCache[b].time)
        .slice(0, keys.length - CACHE_MAX)
        .forEach((k) => delete scanCache[k]);
    }

    await chrome.storage.local.set({ scanCache });
  }).catch(() => {});

  return cacheQueue;
}

// ---------- History / exceptions ----------

function logScanHistory(entry) {
  historyQueue = historyQueue.then(async () => {
    const { scanHistory = [] } = await chrome.storage.local.get('scanHistory');
    await chrome.storage.local.set({
      scanHistory: [entry, ...scanHistory].slice(0, 50)
    });
  }).catch(() => {});

  return historyQueue;
}

function addException(rawDomain) {
  exceptionQueue = exceptionQueue.then(async () => {
    const domain = normalizeDomain(rawDomain);
    if (!domain) return { error: 'Invalid domain.' };

    const { exceptions = [] } = await chrome.storage.local.get('exceptions');

    if (!exceptions.includes(domain)) {
      await chrome.storage.local.set({
        exceptions: [domain, ...exceptions]
      });
    }

    return { ok: true, domain };
  }).catch((err) => ({
    error: err.message || String(err)
  }));

  return exceptionQueue;
}

async function getSettings() {
  const { settings = {} } = await chrome.storage.local.get('settings');
  return { ...DEFAULT_SETTINGS, ...settings };
}

// ---------- API-key validation ----------

async function validateKey(key) {
  key = String(key || '').trim();
  if (!key) return { valid: false, note: 'Empty key.' };

  try {
    const res = await fetch(`${VT_API}/users/current`, {
      method: 'GET',
      headers: {
        'x-apikey': key,
        'Accept': 'application/json'
      }
    });

    if (res.ok) return { valid: true };
    if (res.status === 429) return {
      valid: null,
      note: 'VirusTotal rate-limited this validation request; the key was not rejected.'
    };
    if (res.status === 401 || res.status === 403) return {
      valid: false,
      note: 'VirusTotal rejected the key.'
    };

    return {
      valid: null,
      note: `VirusTotal API returned ${res.status}.`
    };
  } catch (e) {
    return {
      valid: null,
      note: 'Could not reach VirusTotal.'
    };
  }
}

// ---------- Navigation ----------

function openTab(rawUrl, mode, tab) {
  const url = canonicalizeHttpUrl(rawUrl);
  if (!url) return;

  if (mode === 'window') {
    chrome.windows.create({
      url: url.href,
      incognito: !!tab?.incognito
    }).catch(() => {});
    return;
  }

  const props = {
    url: url.href,
    active: mode !== 'background'
  };

  if (tab) {
    props.index = tab.index + 1;
    props.openerTabId = tab.id;
    props.windowId = tab.windowId;
  }

  chrome.tabs.create(props).catch(() => {});
}

function setBadge(tabId, text, color) {
  if (tabId == null) return;
  chrome.action.setBadgeText({ tabId, text }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => {});
}
