// Shared helpers for background.js and popup.html.

function normalizeDomain(input) {
  let s = String(input || '').trim().toLowerCase().replace(/^\*\./, '');
  if (!s) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//.test(s)) s = 'http://' + s;

  let host;
  try {
    host = new URL(s).hostname;
  } catch (e) {
    return null;
  }

  host = host.replace(/\.$/, '');
  if (!host || (!host.includes('.') && host !== 'localhost')) return null;
  return host;
}

function isTrustedHost(hostname, list) {
  const host = String(hostname || '').toLowerCase().replace(/\.$/, '');
  return (list || []).some((entry) => {
    const d = normalizeDomain(entry);
    return d && (host === d || host.endsWith('.' + d));
  });
}

function canonicalizeHttpUrl(input) {
  try {
    const u = input instanceof URL ? new URL(input.href) : new URL(String(input));
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    u.hash = '';
    if (u.protocol === 'http:' && u.port === '80') u.port = '';
    if (u.protocol === 'https:' && u.port === '443') u.port = '';
    u.hostname = u.hostname.toLowerCase();
    return u;
  } catch (e) {
    return null;
  }
}

const DEFAULT_SETTINGS = {
  enabled: true,
  minDetections: 2,
  warnOnUnknown: true,
  submitUnknown: false,
  privacyMode: false,
  scanSameSite: true,
  checkRedirectDestination: true,
  autoDownloadMonitor: true
};
