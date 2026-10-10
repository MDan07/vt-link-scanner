document.addEventListener('DOMContentLoaded', () => {
  const apiKeyInput = document.getElementById('apiKey');
  const addKeyBtn = document.getElementById('addKeyBtn');
  const clearBtn = document.getElementById('clearBtn');
  const historyList = document.getElementById('historyList');
  const saveMsg = document.getElementById('saveMsg');
  const noKeyBanner = document.getElementById('noKeyBanner');
  const disabledBanner = document.getElementById('disabledBanner');
  const apiKeysList = document.getElementById('apiKeysList');
  const apiKeyCount = document.getElementById('apiKeyCount');
  const importEnvBtn = document.getElementById('importEnvBtn');
  const exportEnvBtn = document.getElementById('exportEnvBtn');
  const envFileInput = document.getElementById('envFileInput');
  const openFileScannerBtn = document.getElementById('openFileScannerBtn');

  const enabledToggle = document.getElementById('enabledToggle');
  const minDetectionsInput = document.getElementById('minDetections');
  const warnOnUnknownInput = document.getElementById('warnOnUnknown');
  const submitUnknownInput = document.getElementById('submitUnknown');
  const privacyModeInput = document.getElementById('privacyMode');
  const scanSameSiteInput = document.getElementById('scanSameSite');
  const checkRedirectDestinationInput = document.getElementById('checkRedirectDestination');
  const autoDownloadMonitorInput = document.getElementById('autoDownloadMonitor');
  const clearCacheBtn = document.getElementById('clearCacheBtn');
  const cacheMsg = document.getElementById('cacheMsg');

  const toggleViewBtn = document.getElementById('toggleViewBtn');
  const viewTitle = document.getElementById('viewTitle');
  const exceptionsContainer = document.getElementById('exceptionsContainer');
  const exceptionList = document.getElementById('exceptionList');
  const addExceptionBtn = document.getElementById('addExceptionBtn');
  const newExceptionInput = document.getElementById('newException');
  const exceptionMsg = document.getElementById('exceptionMsg');

  let currentView = 'history';
  let currentKeys = [];
  let currentExceptions = [];
  let currentHistory = [];
  let currentSettings = { ...DEFAULT_SETTINGS };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function flash(node, text, cls = '', ms = 2500) {
    node.textContent = text;
    node.className = cls;
    clearTimeout(node._timer);
    node._timer = setTimeout(() => {
      node.textContent = '';
    }, ms);
  }

  function normalizeKeys(data) {
    let keys = Array.isArray(data.vtApiKeys) ? data.vtApiKeys : [];

    if (
      keys.length === 0 &&
      typeof data.vtApiKey === 'string' &&
      data.vtApiKey.trim()
    ) {
      keys = [data.vtApiKey.trim()];
    }

    return [...new Set(
      keys
        .filter((key) => typeof key === 'string')
        .map((key) => key.trim())
        .filter(Boolean)
    )];
  }

  function maskKey(key) {
    if (key.length <= 10) return '••••••••';
    return `${key.slice(0, 5)}••••••••${key.slice(-4)}`;
  }

  openFileScannerBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('file-scanner.html') });
  });

  // ---------- Initial load ----------

  chrome.storage.local.get(
    ['vtApiKeys', 'vtApiKey', 'scanHistory', 'exceptions', 'settings'],
    async (data) => {
      currentKeys = normalizeKeys(data);

      // Persist the v1.x migration in the popup as well.
      if (
        !Array.isArray(data.vtApiKeys) &&
        currentKeys.length > 0
      ) {
        await chrome.storage.local.set({ vtApiKeys: currentKeys });
      }

      currentHistory = data.scanHistory || [];
      currentExceptions = data.exceptions || [];
      currentSettings = {
        ...DEFAULT_SETTINGS,
        ...(data.settings || {})
      };

      renderSettings();
      renderBanners();
      renderApiKeys();
      renderHistory();
      renderExceptions();
    }
  );

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;

    if (changes.vtApiKeys || changes.vtApiKey) {
      const data = {
        vtApiKeys: changes.vtApiKeys?.newValue,
        vtApiKey: changes.vtApiKey?.newValue
      };

      if (changes.vtApiKeys) {
        currentKeys = Array.isArray(changes.vtApiKeys.newValue)
          ? changes.vtApiKeys.newValue
          : [];
      } else {
        currentKeys = normalizeKeys(data);
      }

      renderBanners();
      renderApiKeys();
    }

    if (changes.scanHistory) {
      currentHistory = changes.scanHistory.newValue || [];
      renderHistory();
    }

    if (changes.exceptions) {
      currentExceptions = changes.exceptions.newValue || [];
      renderExceptions();
      renderHistory();
    }

    if (changes.settings) {
      currentSettings = {
        ...DEFAULT_SETTINGS,
        ...(changes.settings.newValue || {})
      };
      renderSettings();
      renderBanners();
    }
  });

  function renderBanners() {
    noKeyBanner.hidden = currentKeys.length > 0;
    disabledBanner.hidden = currentSettings.enabled;
    apiKeyCount.textContent = String(currentKeys.length);
  }

  // ---------- API keys ----------

  addKeyBtn.addEventListener('click', addKey);

  apiKeyInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') addKey();
  });

  async function addKey() {
    const key = apiKeyInput.value.trim();

    if (!key) {
      flash(saveMsg, 'Paste a VirusTotal API key first.', 'err');
      return;
    }

    if (currentKeys.includes(key)) {
      flash(saveMsg, 'That API key is already added.', 'warn');
      apiKeyInput.select();
      return;
    }

    addKeyBtn.disabled = true;
    saveMsg.className = '';
    saveMsg.textContent = 'Checking key…';

    let check;

    try {
      check = await chrome.runtime.sendMessage({
        action: 'validateKey',
        key
      });
    } catch (e) {
      check = {
        valid: null,
        note: 'Could not contact the extension service worker.'
      };
    }

    if (check && check.valid === false) {
      addKeyBtn.disabled = false;
      flash(
        saveMsg,
        check.note || 'VirusTotal rejected this key. Not added.',
        'err',
        4500
      );
      return;
    }

    currentKeys = [...currentKeys, key];
    await chrome.storage.local.set({ vtApiKeys: currentKeys });

    apiKeyInput.value = '';
    addKeyBtn.disabled = false;

    if (check && check.valid) {
      flash(saveMsg, 'API key added and verified.', 'ok');
    } else {
      flash(
        saveMsg,
        `API key added, but VirusTotal could not verify it (${check?.note || 'unknown error'}).`,
        'warn',
        5000
      );
    }

    renderBanners();
    renderApiKeys();
  }

  // Remove exactly the selected key; do not mutate/filter twice.
  function removeKey(index) {
    currentKeys = currentKeys.filter((_, i) => i !== index);
    chrome.storage.local.set({ vtApiKeys: currentKeys });
  }

  // ---------- .env backup / restore ----------

  // Chrome extensions cannot silently read an arbitrary local .env file.
  // The user must explicitly choose the file when importing it.
  importEnvBtn.addEventListener('click', () => envFileInput.click());
  envFileInput.addEventListener('change', importEnvFile);
  exportEnvBtn.addEventListener('click', exportEnvFile);

  function escapeEnvValue(value) {
    return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  }

  function buildEnvFile(keys) {
    const lines = [
      '# VT Link Scanner API keys',
      '# Keep this file private. It contains your VirusTotal API keys.',
      '# Import this file from the VT Link Scanner popup on another device.',
      ''
    ];

    keys.forEach((key, index) => {
      lines.push(`VT_API_KEY_${index + 1}=\"${escapeEnvValue(key)}\"`);
    });

    lines.push('');
    return lines.join('\n');
  }

  function exportEnvFile() {
    if (currentKeys.length === 0) {
      flash(saveMsg, 'There are no API keys to export.', 'warn');
      return;
    }

    const blob = new Blob([buildEnvFile(currentKeys)], {
      type: 'text/plain;charset=utf-8'
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'vt-link-scanner.env';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);

    flash(saveMsg, 'API keys exported to vt-link-scanner.env. Keep it private.', 'ok', 4500);
  }

  function stripEnvQuotes(value) {
    let v = value.trim();

    if (v.length >= 2) {
      const first = v[0];
      const last = v[v.length - 1];

      if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
        v = v.slice(1, -1);
      }
    }

    return v.replace(/\\([\\"'])/g, '$1');
  }

  function parseEnvKeys(text) {
    const found = [];

    for (const rawLine of String(text || '').split(/\r?\n/)) {
      let line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;

      // Allow an optional leading "export " for normal shell-style .env files.
      line = line.replace(/^export\s+/i, '');

      const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
      if (!match) continue;

      const name = match[1].toUpperCase();
      if (
        name !== 'VT_API_KEY' &&
        !/^VT_API_KEY_\d+$/.test(name) &&
        name !== 'VIRUSTOTAL_API_KEY' &&
        !/^VIRUSTOTAL_API_KEY_\d+$/.test(name)
      ) {
        continue;
      }

      const value = stripEnvQuotes(match[2]);
      if (value) found.push(value);
    }

    return [...new Set(found)];
  }

  async function importEnvFile() {
    const file = envFileInput.files?.[0];
    envFileInput.value = '';
    if (!file) return;

    try {
      const text = await file.text();
      const imported = parseEnvKeys(text);

      if (imported.length === 0) {
        flash(saveMsg, 'No VirusTotal API keys were found in that .env file.', 'err', 4500);
        return;
      }

      const merged = [...new Set([...currentKeys, ...imported])];
      const added = merged.length - currentKeys.length;
      const duplicates = imported.length - added;

      currentKeys = merged;
      await chrome.storage.local.set({ vtApiKeys: currentKeys });

      renderBanners();
      renderApiKeys();

      const duplicateText = duplicates > 0 ? ` ${duplicates} duplicate${duplicates === 1 ? '' : 's'} skipped.` : '';
      flash(
        saveMsg,
        `Imported ${added} API key${added === 1 ? '' : 's'}.${duplicateText} Keys are ready to use.`,
        'ok',
        5000
      );
    } catch (err) {
      flash(saveMsg, `Could not read the .env file: ${err.message || err}`, 'err', 5000);
    }
  }

  function renderApiKeys() {
    apiKeysList.replaceChildren();

    currentKeys.forEach((key, index) => {
      const row = el('div', 'api-key-row');

      row.append(
        el('span', 'api-key-number', String(index + 1)),
        el('span', 'api-key-value', maskKey(key)),
        el('span', 'api-key-status', 'Ready')
      );

      const remove = el('button', 'remove-key', '✕');
      remove.title = 'Remove this API key';
      remove.setAttribute('aria-label', `Remove API key ${index + 1}`);
      remove.addEventListener('click', () => removeKey(index));

      row.append(remove);
      apiKeysList.append(row);
    });

    if (currentKeys.length === 0) {
      apiKeysList.append(el('div', 'hint', 'No API keys added yet.'));
    }

    apiKeyCount.textContent = String(currentKeys.length);
  }

  // ---------- Settings ----------

  function renderSettings() {
    enabledToggle.checked = currentSettings.enabled;
    minDetectionsInput.value = currentSettings.minDetections;
    warnOnUnknownInput.checked = currentSettings.warnOnUnknown;
    submitUnknownInput.checked = currentSettings.submitUnknown;
    privacyModeInput.checked = currentSettings.privacyMode;
    scanSameSiteInput.checked = currentSettings.scanSameSite;
    checkRedirectDestinationInput.checked = currentSettings.checkRedirectDestination;
    autoDownloadMonitorInput.checked = currentSettings.autoDownloadMonitor !== false;
    disabledBanner.hidden = currentSettings.enabled;
  }

  function saveSettings() {
    const min = parseInt(minDetectionsInput.value, 10);

    currentSettings = {
      enabled: enabledToggle.checked,
      minDetections: Number.isFinite(min)
        ? Math.min(50, Math.max(1, min))
        : DEFAULT_SETTINGS.minDetections,
      warnOnUnknown: warnOnUnknownInput.checked,
      submitUnknown: submitUnknownInput.checked,
      privacyMode: privacyModeInput.checked,
      scanSameSite: scanSameSiteInput.checked,
      checkRedirectDestination: checkRedirectDestinationInput.checked,
      autoDownloadMonitor: autoDownloadMonitorInput.checked
    };

    chrome.storage.local.set({ settings: currentSettings });
    renderBanners();
  }

  [
    enabledToggle,
    minDetectionsInput,
    warnOnUnknownInput,
    submitUnknownInput,
    privacyModeInput,
    scanSameSiteInput,
    checkRedirectDestinationInput,
    autoDownloadMonitorInput
  ].forEach((input) => input.addEventListener('change', saveSettings));

  clearCacheBtn.addEventListener('click', () => {
    chrome.storage.local.remove('scanCache', () => {
      flash(cacheMsg, 'Cache cleared.', 'hint');
    });
  });

  // ---------- History ----------

  clearBtn.addEventListener('click', () => {
    chrome.storage.local.set({ scanHistory: [] });
  });

  toggleViewBtn.addEventListener('click', () => {
    const showExceptions = currentView === 'history';

    currentView = showExceptions ? 'exceptions' : 'history';
    viewTitle.textContent = showExceptions ? 'Exceptions' : 'Scan History';
    toggleViewBtn.textContent = showExceptions ? 'History' : 'Exceptions';
    historyList.hidden = showExceptions;
    clearBtn.hidden = showExceptions;
    exceptionsContainer.hidden = !showExceptions;
  });

  function formatTime(ts) {
    if (typeof ts !== 'number') return ts || '';

    const d = new Date(ts);
    const time = d.toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit'
    });

    if (d.toDateString() === new Date().toDateString()) {
      return time;
    }

    return `${d.toLocaleDateString([], {
      month: 'short',
      day: 'numeric'
    })} ${time}`;
  }

  function statusView(item) {
    const malicious = item.malicious != null
      ? item.malicious
      : item.maliciousCount;

    switch (item.status) {
      case 'malicious':
        return ['❌', `Malicious (${malicious})`];

      case 'suspicious':
        return [
          '⚠️',
          `Suspicious (${malicious || 0}/${item.suspicious || 0})`
        ];

      case 'unknown':
        return ['❓', 'Not in VirusTotal'];

      default:
        return ['✅', 'Safe'];
    }
  }

  function renderHistory() {
    if (currentHistory.length === 0) {
      historyList.replaceChildren(
        el('div', 'empty-msg', 'No links scanned yet.')
      );
      return;
    }

    historyList.replaceChildren(...currentHistory.map((item) => {
      const row = el('div', 'history-item');

      let domain = '';

      try {
        domain = new URL(item.url).hostname.toLowerCase();
      } catch (e) {}

      const isExcepted = domain && isTrustedHost(
        domain,
        currentExceptions
      );

      if (item.vtLink) {
        row.classList.add('clickable');
        row.title = 'Click to view full VirusTotal report';

        row.addEventListener('click', (e) => {
          if (e.target.closest('button')) return;
          chrome.tabs.create({ url: item.vtLink });
        });
      }

      const [icon, label] = statusView(item);

      const details = el('div', 'history-details');

      details.append(
        el('div', 'history-url', item.url),
        el(
          'div',
          'history-meta',
          `${formatTime(item.timestamp)} • ${label}${item.lookedUp === 'domain' ? ' (domain)' : ''}${item.redirected ? ' • redirect checked' : ''}`
        )
      );

      details.firstChild.title = item.url;
      row.append(el('span', 'history-badge', icon), details);

      if (
        item.status === 'malicious' ||
        item.status === 'suspicious'
      ) {
        if (isExcepted) {
          const btn = el(
            'button',
            'action-btn allowed',
            'Allowed'
          );

          btn.disabled = true;
          row.append(btn);
        } else if (domain) {
          const btn = el(
            'button',
            'action-btn allow',
            'Allow'
          );

          btn.title = `Always allow ${domain}`;

          btn.addEventListener('click', (e) => {
            e.stopPropagation();
            addException(domain);
          });

          row.append(btn);
        }
      }

      return row;
    }));
  }

  // ---------- Exceptions ----------

  addExceptionBtn.addEventListener('click', submitException);

  newExceptionInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') submitException();
  });

  function submitException() {
    const raw = newExceptionInput.value;

    if (!raw.trim()) return;

    const domain = normalizeDomain(raw);

    if (!domain) {
      flash(
        exceptionMsg,
        "That doesn't look like a domain (e.g. example.com).",
        'hint'
      );
      return;
    }

    addException(domain);
    newExceptionInput.value = '';
    flash(
      exceptionMsg,
      `Added ${domain} (subdomains included).`,
      'hint'
    );
  }

  function addException(domain) {
    domain = normalizeDomain(domain);

    if (!domain || currentExceptions.includes(domain)) return;

    chrome.runtime.sendMessage({
      action: 'addException',
      domain
    }).catch(() => {});
  }

  function removeException(domain) {
    chrome.storage.local.set({
      exceptions: currentExceptions.filter((d) => d !== domain)
    });
  }

  function renderExceptions() {
    if (currentExceptions.length === 0) {
      exceptionList.replaceChildren(
        el('div', 'empty-msg', 'No exceptions added.')
      );
      return;
    }

    exceptionList.replaceChildren(...currentExceptions.map((domain) => {
      const row = el('div', 'history-item');
      const details = el('div', 'history-details');

      details.append(
        el('div', 'history-url', domain)
      );

      const removeBtn = el(
        'button',
        'action-btn remove',
        'Delete'
      );

      removeBtn.addEventListener('click', () => {
        removeException(domain);
      });

      row.append(
        el('span', 'history-badge', '🛡️'),
        details,
        removeBtn
      );

      return row;
    }));
  }
});
