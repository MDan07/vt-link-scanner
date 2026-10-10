// Intercepts HTTP(S) link clicks, scans them with VirusTotal, then performs
// the requested navigation without re-dispatching a synthetic click through
// the page. This avoids page JavaScript cancelling the post-scan navigation.
(() => {
  let ui = null;
  let hideTimer = null;
  let scanCounter = 0;
  let noKeyHintShown = false;

  // ---------- Dialog ----------

  const DIALOG_CSS = `
    .dialog {
      box-sizing: border-box;
      width: 350px;
      max-width: calc(100vw - 32px);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      color: #fff;
      border-radius: 10px;
      padding: 12px 14px;
      box-shadow: 0 12px 32px rgba(0, 0, 0, 0.5);
      display: flex;
      align-items: flex-start;
      gap: 12px;
      transition: transform 0.18s ease, opacity 0.18s ease;
      transform: translateY(-12px);
      opacity: 0;
      pointer-events: none;
      background: #18181b;
      border: 1px solid #3f3f46;
    }
    .dialog.show { transform: translateY(0); opacity: 1; pointer-events: auto; }
    .dialog.safe { background: #0f2e1b; border-color: #16a34a; }
    .dialog.danger { background: #361013; border-color: #dc2626; }
    .dialog.warn, .dialog.unknown, .dialog.info { background: #2d2006; border-color: #d97706; }
    .icon { font-size: 20px; line-height: 1.2; }
    .content { flex: 1; min-width: 0; }
    .title { font-size: 13px; font-weight: 600; margin-bottom: 3px; }
    .desc {
      font-size: 11px;
      color: #d4d4d8;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .actions { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
    .actions:empty { display: none; }
    button {
      font: inherit;
      font-size: 11px;
      border: none;
      border-radius: 5px;
      padding: 5px 9px;
      cursor: pointer;
      background: #3f3f46;
      color: #fff;
    }
    button:hover { background: #52525b; }
    button.primary { background: #2563eb; }
    button.primary:hover { background: #1d4ed8; }
    .close {
      background: transparent;
      color: #a1a1aa;
      padding: 0 2px;
      font-size: 13px;
    }
    .close:hover { background: transparent; color: #fff; }
  `;

  const ICONS = {
    scanning: '⏳',
    safe: '✅',
    danger: '⛔',
    warn: '⚠️',
    unknown: '❓',
    info: 'ℹ️'
  };

  function getUi() {
    if (ui && ui.host.isConnected) return ui;

    const host = document.createElement('vt-link-scanner');
    host.style.cssText =
      'all: initial !important; position: fixed !important; top: 16px !important; right: 16px !important; z-index: 2147483647 !important; pointer-events: none !important;';

    const root = host.attachShadow({ mode: 'closed' });

    root.innerHTML = `
      <style>${DIALOG_CSS}</style>
      <div class="dialog" role="alertdialog" aria-live="assertive">
        <div class="icon"></div>
        <div class="content">
          <div class="title"></div>
          <div class="desc"></div>
          <div class="actions"></div>
        </div>
        <button class="close" title="Close" aria-label="Close">✕</button>
      </div>
    `;

    (document.body || document.documentElement).appendChild(host);

    ui = {
      host,
      dialog: root.querySelector('.dialog'),
      icon: root.querySelector('.icon'),
      title: root.querySelector('.title'),
      desc: root.querySelector('.desc'),
      actions: root.querySelector('.actions')
    };

    root.querySelector('.close').addEventListener('click', hideAlert);
    return ui;
  }

  function displayAlert(type, title, desc, { actions = [], autoClose = 0 } = {}) {
    const u = getUi();
    clearTimeout(hideTimer);

    u.dialog.className = `dialog show ${type}`;
    u.icon.textContent = ICONS[type] || '🔍';
    u.title.textContent = title;
    u.desc.textContent = desc || '';
    u.desc.title = desc || '';

    u.actions.replaceChildren(...actions.filter(Boolean).map((a) => {
      const btn = document.createElement('button');
      btn.textContent = a.label;
      if (a.primary) btn.className = 'primary';

      btn.addEventListener('click', () => {
        hideAlert();
        if (a.onClick) a.onClick();
      });

      return btn;
    }));

    if (autoClose > 0) {
      hideTimer = setTimeout(hideAlert, autoClose);
    }
  }

  function hideAlert() {
    clearTimeout(hideTimer);
    if (ui) ui.dialog.classList.remove('show');
  }

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && ui && ui.dialog.classList.contains('show')) {
      hideAlert();
    }
  }, true);

  // ---------- Messaging ----------

  async function send(msg) {
    try {
      const response = await chrome.runtime.sendMessage(msg);
      return response || { error: 'Extension did not return a response.', code: 'no_response' };
    } catch (e) {
      return { error: 'Extension unavailable.', code: 'gone' };
    }
  }

  // ---------- Link handling ----------

  function findLink(e) {
    for (const node of e.composedPath()) {
      if (
        node instanceof Element &&
        (node.localName === 'a' || node.localName === 'area')
      ) {
        return node;
      }
    }
    return null;
  }

  function getLinkUrl(link) {
    let raw = link.href;

    if (raw && typeof raw === 'object') {
      raw = raw.baseVal;
    }

    if (!raw) {
      raw = link.getAttribute('href') || link.getAttribute('xlink:href');
    }

    if (!raw) return null;

    try {
      const url = new URL(raw, document.baseURI);
      if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
      return url;
    } catch (e) {
      return null;
    }
  }

  function isSameDocument(url) {
    try {
      const current = new URL(location.href);
      return (
        current.origin === url.origin &&
        current.pathname === url.pathname &&
        current.search === url.search
      );
    } catch (e) {
      return false;
    }
  }

  function getOpenMode(e, link) {
    if (e.button === 1 || e.ctrlKey || e.metaKey) return 'background';
    if (e.shiftKey) return 'window';

    let target = link.target;
    if (target && typeof target === 'object') target = target.baseVal;

    target = String(target || '').toLowerCase();

    if (target === '_blank') return 'foreground';
    if (target && !['_self', '_top', '_parent'].includes(target)) {
      // Named browsing contexts are difficult to reproduce after an async scan.
      // Opening a foreground tab is safer than dispatching the page click again.
      return 'foreground';
    }

    return target || 'native';
  }

  function onLinkClick(e) {
    if (e.type === 'click' && e.button !== 0) return;
    if (e.type === 'auxclick' && e.button !== 1) return;

    const link = findLink(e);
    if (!link) return;

    const url = getLinkUrl(link);
    if (!url) return;

    // Hash-only / same-document navigation does not need a network safety check.
    if (isSameDocument(url)) return;

    e.preventDefault();
    e.stopPropagation();

    scanAndProceed(link, url, getOpenMode(e, link));
  }

  window.addEventListener('click', onLinkClick, true);
  window.addEventListener('auxclick', onLinkClick, true);

  // ---------- Navigation ----------

  async function proceed(link, url, mode) {
    if (mode !== 'native') {
      const res = await send({
        action: 'openTab',
        url: url.href,
        mode
      });

      if (res && res.code === 'gone') {
        window.open(url.href, '_blank', 'noopener,noreferrer');
      }
      return;
    }

    /*
     * Do NOT dispatch another click on the original element.
     * Page JavaScript can cancel/rewrite that synthetic click.
     * Direct navigation preserves the user's destination after the scan.
     */
    let target = String(link.target || '').toLowerCase();

    try {
      if (target === '_top') {
        window.top.location.href = url.href;
      } else if (target === '_parent') {
        window.parent.location.href = url.href;
      } else {
        location.href = url.href;
      }
    } catch (e) {
      location.href = url.href;
    }
  }

  async function scanAndProceed(link, url, mode) {
    const scanId = ++scanCounter;

    const scanningTimer = setTimeout(() => {
      if (scanId === scanCounter) {
        displayAlert('scanning', 'Checking VirusTotal…', url.href);
      }
    }, 120);

    const res = await send({
      action: 'scanUrl',
      url: url.href,
      pageUrl: location.href
    });

    clearTimeout(scanningTimer);

    // If another link was clicked while this was being scanned, do not
    // let the older result overwrite the newer decision.
    if (scanId !== scanCounter) return;

    handleScanResult(res, link, url, mode);
  }

  function describe(res) {
    const prefix = res.lookedUp === 'domain'
      ? `Domain ${res.domain}: `
      : '';

    const suffix = res.cached ? ' (cached)' : '';

    if (res.status === 'safe') {
      return `${prefix}no engines flagged it${suffix}`;
    }

    if (res.status === 'malicious') {
      return `${prefix}flagged by ${res.malicious} engine(s)${suffix}`;
    }

    return `${prefix}${res.malicious || 0} malicious, ${res.suspicious || 0} suspicious`;
  }

  function reportAction(res) {
    if (!res.vtLink) return null;

    return {
      label: 'View report',
      onClick: () => send({
        action: 'openTab',
        url: res.vtLink,
        mode: 'foreground'
      })
    };
  }

  function redirectNote(res) {
    if (!res.redirected || !res.finalUrl) return '';

    if (res.finalStatus === 'unknown') {
      return ` Known redirect destination: ${res.finalUrl} (not analysed by VirusTotal).`;
    }

    if (res.finalStatus === 'safe') {
      return ` Known redirect destination was also clean.`;
    }

    if (res.finalStatus === 'malicious') {
      return ` Redirect destination was also flagged.`;
    }

    return '';
  }

  function riskNote(res) {
    if (typeof res.riskScore !== 'number') return '';

    const label = {
      low: 'Low',
      moderate: 'Moderate',
      high: 'High',
      critical: 'Critical'
    }[res.riskLevel] || 'Unknown';

    let note = ` Risk score: ${res.riskScore}/100 (${label}).`;

    if (res.domainAgeDays != null) {
      if (res.domainAgeDays < 7) note += ' Domain is less than 7 days old.';
      else if (res.domainAgeDays < 30) note += ' Domain is less than 30 days old.';
    }

    if (res.domainMalicious > 0 || res.domainSuspicious > 0) {
      note += ` Domain reputation: ${res.domainMalicious || 0} malicious, ${res.domainSuspicious || 0} suspicious.`;
    }

    if (Array.isArray(res.riskSignals) && res.riskSignals.length) {
      note += ` ${res.riskSignals.slice(0, 3).join(' • ')}.`;
    }

    return note;
  }

  function deepScanAction(link, url, mode) {
    return {
      label: 'Scan it now',
      primary: true,
      onClick: () => deepScanAndProceed(link, url, mode)
    };
  }

  async function deepScanAndProceed(link, url, mode) {
    displayAlert(
      'scanning',
      'Deep-scanning with VirusTotal…',
      'The URL will be submitted to VirusTotal. Analysis can take up to about a minute.'
    );

    const res = await send({
      action: 'deepScanUrl',
      url: url.href
    });

    handleScanResult(res, link, url, mode, { fromDeepScan: true });
  }

  function retryAction(link, url, mode) {
    return {
      label: 'Retry scan',
      primary: true,
      onClick: () => scanAndProceed(link, url, mode)
    };
  }

  function handleScanResult(res, link, url, mode, options = {}) {
    const go = () => proceed(link, url, mode);

    const openAnyway = {
      label: 'Open anyway',
      onClick: go
    };

    const cancel = { label: 'Cancel' };

    if (!res || res.code === 'gone') {
      hideAlert();
      go();
      return;
    }

    if (res.error) {
      displayAlert('danger', 'Scan failed', res.error, {
        actions: [retryAction(link, url, mode), openAnyway, cancel]
      });
      return;
    }

    switch (res.status) {
      case 'skipped':
        if (res.reason === 'nokey' && !noKeyHintShown) {
          noKeyHintShown = true;

          displayAlert(
            'info',
            'Link not scanned',
            'No VirusTotal API key is configured. Add one or more in the extension popup.',
            { autoClose: 4500 }
          );
        } else {
          hideAlert();
        }

        go();
        return;

      case 'safe':
        displayAlert(
          'safe',
          'Link looks safe',
          describe(res) + riskNote(res) + redirectNote(res),
          { autoClose: 1200 }
        );
        setTimeout(go, 350);
        return;

      case 'unknown': {
        let desc = options.fromDeepScan
          ? 'VirusTotal finished without enough detections to classify this URL.'
          : 'VirusTotal has no completed analysis for this URL.';

        desc += riskNote(res) + redirectNote(res);

        const actions = options.fromDeepScan
          ? [reportAction(res), openAnyway, cancel]
          : [
              deepScanAction(link, url, mode),
              openAnyway,
              cancel
            ];

        displayAlert('unknown', options.fromDeepScan ? 'Still unknown' : 'Unknown link', desc, {
          actions
        });
        return;
      }

      case 'suspicious':
        displayAlert(
          'warn',
          'Possibly unsafe link',
          describe(res) + riskNote(res) + redirectNote(res),
          {
            actions: [reportAction(res), openAnyway, cancel]
          }
        );
        return;

      case 'malicious':
        displayAlert(
          'danger',
          'Blocked malicious link',
          describe(res) + riskNote(res) + redirectNote(res),
          {
            actions: [
              { ...reportAction(res), primary: true },
              openAnyway,
              {
                label: `Always allow ${url.hostname}`,
                onClick: async () => {
                  await send({
                    action: 'addException',
                    domain: url.hostname
                  });
                  go();
                }
              }
            ].filter(Boolean)
          }
        );
        return;

      default:
        hideAlert();
        go();
    }
  }

  // ---------- Right-click scan ----------

  chrome.runtime.onMessage.addListener((msg) => {
    if (!msg || msg.action !== 'showResult') return;

    let url;
    try {
      url = new URL(msg.url);
    } catch (e) {
      return;
    }

    if (msg.pending) {
      displayAlert('scanning', 'Checking VirusTotal…', url.href);
      return;
    }

    const res = msg.result || { error: 'No response from VirusTotal.' };
    const openLink = {
      label: 'Open link',
      onClick: () => send({
        action: 'openTab',
        url: url.href,
        mode: 'foreground'
      })
    };

    if (res.error) {
      displayAlert('danger', 'Scan failed', res.error, {
        actions: [openLink, { label: 'Close' }]
      });
      return;
    }

    const view = {
      safe: ['safe', 'Link looks safe'],
      unknown: ['unknown', 'Unknown link'],
      suspicious: ['warn', 'Possibly unsafe link'],
      malicious: ['danger', 'Malicious link']
    }[res.status] || ['info', 'Scan complete'];

    const desc = (
      res.status === 'unknown'
        ? 'VirusTotal has no analysis for this link.'
        : describe(res)
    ) + riskNote(res) + redirectNote(res);

    displayAlert(view[0], view[1], desc, {
      actions: [reportAction(res), openLink, { label: 'Close' }]
    });
  });
})();
