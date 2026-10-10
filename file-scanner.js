const VT_API = 'https://www.virustotal.com/api/v3';
const MAX_DIRECT_UPLOAD = 32 * 1024 * 1024;
const MAX_FILE_SIZE = 100 * 1024 * 1024;
const KEY_COOLDOWN_MS = 65 * 1000;
const INVALID_COOLDOWN_MS = 10 * 60 * 1000;

const fileInput = document.getElementById('fileInput');
const chooseBtn = document.getElementById('chooseBtn');
const selectedFile = document.getElementById('selectedFile');
const statusEl = document.getElementById('status');
const actionsEl = document.getElementById('actions');
const progress = document.getElementById('progress');
const progressBar = document.getElementById('progressBar');
const downloadsList = document.getElementById('downloadsList');
const refreshDownloadsBtn = document.getElementById('refreshDownloadsBtn');
const historyList = document.getElementById('historyList');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');

let selected = null;
let pendingDownload = null;
const keyState = new Map();
let keyCursor = 0;

chooseBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', async () => {
  selected = fileInput.files?.[0] || null;
  if (!selected) return;

  selectedFile.textContent = `${selected.name} • ${formatBytes(selected.size)}`;
  clearStatus();

  // If this page was opened from an automatic download notification, start
  // scanning immediately after the user has selected the downloaded file.
  if (pendingDownload) {
    pendingDownload = null;
    await scanSelectedFile();
    return;
  }

  addAction('Scan file', scanSelectedFile, true);
});
refreshDownloadsBtn.addEventListener('click', loadRecentDownloads);
clearHistoryBtn.addEventListener('click', async () => {
  await chrome.storage.local.set({ fileScanHistory: [] });
  renderHistory([]);
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.fileScanHistory) {
    renderHistory(changes.fileScanHistory.newValue || []);
  }
});

loadRecentDownloads();
loadHistory();
loadPendingDownload();

async function loadPendingDownload() {
  const params = new URLSearchParams(location.search);
  const id = Number(params.get('downloadId'));
  if (!Number.isInteger(id) || id <= 0) return;

  try {
    const items = await chrome.downloads.search({ id });
    const item = items?.[0];
    if (!item || item.state !== 'complete') return;

    pendingDownload = item;
    const name = item.filename ? item.filename.split(/[\\/]/).pop() : `Download #${id}`;
    setStatus(
      `Download detected: ${name}. Choose that downloaded file below; scanning will start automatically.`,
      'info'
    );
    selectedFile.textContent = `${name} • ${formatBytes(item.fileSize || 0)}`;
    addAction('Choose detected file', () => fileInput.click(), true);
  } catch (e) {
    setStatus('Could not load the detected download.', 'danger');
  }
}

function clearStatus() {
  statusEl.textContent = '';
  statusEl.className = 'status';
  actionsEl.replaceChildren();
  progress.hidden = true;
  progressBar.style.width = '0%';
}

function setStatus(text, type = 'info') {
  statusEl.textContent = text;
  statusEl.className = `status ${type}`;
}

function addAction(label, handler, primary = false) {
  const btn = document.createElement('button');
  btn.textContent = label;
  if (!primary) btn.className = 'secondary';
  btn.addEventListener('click', handler, { once: true });
  actionsEl.append(btn);
  return btn;
}

async function scanSelectedFile() {
  const file = selected;
  if (!file) return;

  clearStatus();
  chooseBtn.disabled = true;
  setStatus('Hashing the file locally…', 'info');
  progress.hidden = false;
  progressBar.style.width = '10%';

  try {
    if (file.size > MAX_FILE_SIZE) {
      throw new Error(`This extension supports files up to ${formatBytes(MAX_FILE_SIZE)}.`);
    }

    const buffer = await file.arrayBuffer();
    progressBar.style.width = '25%';
    const hash = await sha256(buffer);
    progressBar.style.width = '35%';

    const known = await getFileReport(hash);
    if (known.kind === 'known') {
      progressBar.style.width = '100%';
      showReport(file, hash, known.report, false);
      await saveHistory(file, hash, known.report, false);
      return;
    }

    setStatus('VirusTotal does not know this file hash.', 'warn');
    addAction('Upload and scan with VirusTotal', () => uploadAndScan(file, hash), true);
    addAction('Cancel', clearStatus, false);
    progress.hidden = true;
  } catch (err) {
    progress.hidden = true;
    setStatus(err.message || String(err), 'danger');
  } finally {
    chooseBtn.disabled = false;
  }
}

async function uploadAndScan(file, hash) {
  clearStatus();
  chooseBtn.disabled = true;
  setStatus('Uploading the file to VirusTotal…', 'info');
  progress.hidden = false;
  progressBar.style.width = '45%';

  try {
    const upload = await uploadFile(file);
    if (!upload.ok) throw new Error(upload.error || 'File upload failed.');

    progressBar.style.width = '60%';
    setStatus('VirusTotal is analyzing the file…', 'info');

    if (upload.analysisId) {
      await waitForAnalysis(upload.analysisId);
    }

    progressBar.style.width = '90%';
    const reportResult = await getFileReport(hash, true);
    if (reportResult.kind !== 'known') {
      throw new Error('VirusTotal finished the upload but the file report is not available yet. Try scanning again shortly.');
    }

    progressBar.style.width = '100%';
    showReport(file, hash, reportResult.report, true);
    await saveHistory(file, hash, reportResult.report, true);
  } catch (err) {
    progress.hidden = true;
    setStatus(err.message || String(err), 'danger');
  } finally {
    chooseBtn.disabled = false;
  }
}

async function getFileReport(hash, forceRefresh = false) {
  const cacheKey = `file:${hash}`;
  if (!forceRefresh) {
    const { fileScanCache = {} } = await chrome.storage.local.get('fileScanCache');
    const cached = fileScanCache[cacheKey];
    if (cached && Date.now() - cached.time < 24 * 60 * 60 * 1000) {
      return { kind: 'known', report: { ...cached.report, cached: true } };
    }
  }

  const result = await vtRequest(`/files/${encodeURIComponent(hash)}`);
  if (result.error) throw new Error(result.error);

  if (result.response.status === 404) return { kind: 'unknown' };
  if (!result.response.ok) throw new Error(`VirusTotal file lookup failed (${result.response.status}).`);

  const json = await result.response.json();
  const attrs = json?.data?.attributes || {};
  const stats = attrs.last_analysis_stats;
  if (!stats) return { kind: 'unknown' };

  const report = {
    found: true,
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    total: Object.values(stats).reduce((sum, n) => sum + (Number(n) || 0), 0),
    sha256: json?.data?.id || hash,
    type: attrs.type_description || attrs.type_tag || 'Unknown file type',
    size: attrs.size || null,
    firstSeen: attrs.first_submission_date || null,
    reputation: attrs.reputation ?? null
  };

  const { fileScanCache = {} } = await chrome.storage.local.get('fileScanCache');
  fileScanCache[cacheKey] = { time: Date.now(), report };
  const keys = Object.keys(fileScanCache);
  if (keys.length > 200) {
    keys.sort((a, b) => fileScanCache[a].time - fileScanCache[b].time)
      .slice(0, keys.length - 200)
      .forEach((key) => delete fileScanCache[key]);
  }
  await chrome.storage.local.set({ fileScanCache });

  return { kind: 'known', report };
}

async function uploadFile(file) {
  const form = new FormData();
  form.append('file', file, file.name);

  let path = '/files';
  if (file.size > MAX_DIRECT_UPLOAD) {
    const uploadUrlResult = await vtRequest('/files/upload_url');
    if (uploadUrlResult.error) return uploadUrlResult;
    if (!uploadUrlResult.response.ok) {
      return { error: `VirusTotal could not create an upload URL (${uploadUrlResult.response.status}).` };
    }

    const json = await uploadUrlResult.response.json();
    const uploadUrl = json?.data;
    if (typeof uploadUrl !== 'string') return { error: 'VirusTotal returned an invalid upload URL.' };

    let u;
    try { u = new URL(uploadUrl); } catch (e) { return { error: 'VirusTotal returned an invalid upload URL.' }; }
    if (!/^(www\.)?virustotal\.com$/i.test(u.hostname) && !/\.virustotal\.com$/i.test(u.hostname)) {
      return { error: 'VirusTotal returned an unsupported upload destination.' };
    }

    try {
      const response = await fetch(uploadUrl, { method: 'POST', body: form });
      if (!response.ok) return { error: `VirusTotal file upload failed (${response.status}).` };
      const body = await response.json().catch(() => ({}));
      return { ok: true, analysisId: body?.data?.id || null };
    } catch (e) {
      return { error: 'Could not upload the file to VirusTotal.' };
    }
  }

  const result = await vtRequest(path, {
    method: 'POST',
    body: form
  });
  if (result.error) return result;
  if (!result.response.ok) return { error: `VirusTotal file upload failed (${result.response.status}).` };

  const json = await result.response.json().catch(() => ({}));
  return { ok: true, analysisId: json?.data?.id || null };
}

async function waitForAnalysis(analysisId) {
  const started = Date.now();
  while (Date.now() - started < 120000) {
    const result = await vtRequest(`/analyses/${encodeURIComponent(analysisId)}`);
    if (result.error) throw new Error(result.error);
    if (!result.response.ok) throw new Error(`VirusTotal analysis lookup failed (${result.response.status}).`);

    const json = await result.response.json();
    const status = json?.data?.attributes?.status;
    if (status === 'completed') return;
    if (status === 'failed') throw new Error('VirusTotal could not complete the file analysis.');

    await sleep(3000);
  }
  throw new Error('VirusTotal is still analyzing this file. Try again shortly.');
}

async function vtRequest(path, options = {}) {
  const { vtApiKeys = [], vtApiKey } = await chrome.storage.local.get(['vtApiKeys', 'vtApiKey']);
  let keys = Array.isArray(vtApiKeys) ? vtApiKeys.filter(Boolean) : [];
  if (!keys.length && typeof vtApiKey === 'string' && vtApiKey.trim()) keys = [vtApiKey.trim()];
  keys = [...new Set(keys)];
  if (!keys.length) return { error: 'No VirusTotal API keys configured.' };

  const attempted = new Set();
  let saw429 = false;
  let sawRejected = false;

  while (attempted.size < keys.length) {
    const key = nextKey(keys, attempted);
    if (!key) break;
    attempted.add(key);

    try {
      const response = await fetch(VT_API + path, {
        ...options,
        headers: {
          ...(options.headers || {}),
          'x-apikey': key,
          'Accept': 'application/json'
        }
      });

      if (response.status === 429) {
        saw429 = true;
        keyState.set(key, { cooldownUntil: Date.now() + KEY_COOLDOWN_MS });
        continue;
      }
      if (response.status === 401 || response.status === 403) {
        sawRejected = true;
        keyState.set(key, { invalidUntil: Date.now() + INVALID_COOLDOWN_MS });
        continue;
      }

      keyState.delete(key);
      return { response, key };
    } catch (e) {
      return { error: 'Could not reach VirusTotal (network error).' };
    }
  }

  if (saw429) return { error: 'All configured VirusTotal API keys are currently rate-limited.' };
  if (sawRejected) return { error: 'All configured VirusTotal API keys were rejected by VirusTotal.' };
  return { error: 'No usable VirusTotal API key is currently available.' };
}

function nextKey(keys, attempted) {
  for (let offset = 0; offset < keys.length; offset++) {
    const i = (keyCursor + offset) % keys.length;
    const key = keys[i];
    if (attempted.has(key)) continue;
    const state = keyState.get(key);
    if (state && Date.now() < Math.max(state.cooldownUntil || 0, state.invalidUntil || 0)) continue;
    keyCursor = (i + 1) % keys.length;
    return key;
  }
  return null;
}

function showReport(file, hash, report, uploaded) {
  const malicious = report.malicious || 0;
  const suspicious = report.suspicious || 0;
  getMinDetectionSetting().then((min) => {
    const status = malicious >= min ? 'malicious' : (malicious + suspicious > 0 ? 'suspicious' : 'safe');
    renderReportStatus(file, hash, report, uploaded, status);
  });
  return;
}

function renderReportStatus(file, hash, report, uploaded, status) {
  const malicious = report.malicious || 0;
  const suspicious = report.suspicious || 0;

  if (status === 'malicious') {
    setStatus(`⛔ Malicious — ${malicious} engine(s) flagged this file.`, 'danger');
  } else if (status === 'suspicious') {
    setStatus(`⚠️ Suspicious — ${malicious} malicious, ${suspicious} suspicious detection(s).`, 'warn');
  } else {
    setStatus(`✅ No engines flagged this file. ${report.total || 0} analysis results available.`, 'safe');
  }

  const meta = document.createElement('div');
  meta.className = 'muted';
  meta.textContent = `${file.name} • ${formatBytes(file.size)} • ${report.type || 'Unknown type'} • SHA-256: ${hash}`;
  statusEl.append(document.createElement('br'), meta);

  actionsEl.replaceChildren();
  const vtLink = `https://www.virustotal.com/gui/file/${encodeURIComponent(hash)}/detection`;
  addAction('View VirusTotal report', () => chrome.tabs.create({ url: vtLink }), true);
  if (uploaded) addAction('Scan again', scanSelectedFile, false);
  progress.hidden = true;
}

async function saveHistory(file, hash, report, uploaded) {
  const malicious = report.malicious || 0;
  const suspicious = report.suspicious || 0;
  const min = await getMinDetectionSetting();
  const status = malicious >= min ? 'malicious' : (malicious + suspicious > 0 ? 'suspicious' : 'safe');
  const { fileScanHistory = [] } = await chrome.storage.local.get('fileScanHistory');
  const entry = {
    name: file.name,
    size: file.size,
    hash,
    status,
    malicious,
    suspicious,
    uploaded,
    timestamp: Date.now(),
    vtLink: `https://www.virustotal.com/gui/file/${encodeURIComponent(hash)}/detection`
  };
  await chrome.storage.local.set({ fileScanHistory: [entry, ...fileScanHistory].slice(0, 50) });
}

async function getMinDetectionSetting() {
  const { settings = {} } = await chrome.storage.local.get('settings');
  return Math.max(1, Number(settings.minDetections) || 2);
}

async function loadHistory() {
  const { fileScanHistory = [] } = await chrome.storage.local.get('fileScanHistory');
  renderHistory(fileScanHistory);
}

function renderHistory(items) {
  if (!items.length) {
    historyList.innerHTML = '<div class="empty">No files scanned yet.</div>';
    return;
  }
  historyList.replaceChildren(...items.map((item) => {
    const row = document.createElement('div');
    row.className = 'item';
    const badge = document.createElement('div');
    badge.className = 'badge';
    badge.textContent = item.status === 'malicious' ? '⛔' : item.status === 'suspicious' ? '⚠️' : '✅';
    const main = document.createElement('div');
    main.className = 'item-main';
    const title = document.createElement('div');
    title.className = 'item-title';
    title.textContent = item.name;
    const meta = document.createElement('div');
    meta.className = 'item-meta';
    meta.textContent = `${formatBytes(item.size)} • ${item.malicious || 0} malicious • ${item.suspicious || 0} suspicious • ${new Date(item.timestamp).toLocaleString()}`;
    main.append(title, meta);
    row.append(badge, main);
    row.addEventListener('click', () => chrome.tabs.create({ url: item.vtLink }));
    return row;
  }));
}

async function loadRecentDownloads() {
  downloadsList.replaceChildren();
  try {
    const items = await chrome.downloads.search({ orderBy: ['-startTime'], limit: 12 });
    const completed = items.filter((d) => d.state === 'complete');
    if (!completed.length) {
      downloadsList.innerHTML = '<div class="empty">No completed downloads found.</div>';
      return;
    }

    for (const item of completed) {
      const row = document.createElement('div');
      row.className = 'item';
      const main = document.createElement('div');
      main.className = 'item-main';
      const title = document.createElement('div');
      title.className = 'item-title';
      title.textContent = item.filename ? item.filename.split(/[\\/]/).pop() : `Download #${item.id}`;
      const meta = document.createElement('div');
      meta.className = 'item-meta';
      meta.textContent = `${formatBytes(item.fileSize || 0)} • ${new Date(item.endTime || item.startTime).toLocaleString()}`;
      main.append(title, meta);
      const btn = document.createElement('button');
      btn.className = 'secondary';
      btn.textContent = 'Select';
      btn.addEventListener('click', () => {
        selectedFile.textContent = `Select: ${title.textContent}`;
        setStatus('Download detected. Choose the same local file; the scan starts automatically after selection.', 'info');
        pendingDownload = item;
        fileInput.click();
      });
      row.append(main, btn);
      downloadsList.append(row);
    }
  } catch (e) {
    downloadsList.innerHTML = '<div class="empty">Could not read Chrome download history.</div>';
  }
}

async function sha256(buffer) {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
}

function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
