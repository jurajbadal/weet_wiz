const content = document.getElementById('content');
const domainEl = document.getElementById('domain');

function riskClass(riskLevel) {
    return 'risk-' + (riskLevel || '').toLowerCase().replace(/\s+/g, '-');
}

function colorClass(riskLevel) {
    return 'color-' + (riskLevel || '').toLowerCase().replace(/\s+/g, '-');
}

function securityLabel(riskLevel) {
    const map = {
        'very low':  'Very High Security',
        'low':       'High Security',
        'medium':    'Medium',
        'high':      'Low Security',
        'very high': 'Very Low Security',
    };
    return map[(riskLevel || '').toLowerCase()] || riskLevel;
}

function renderCookies(cookies) {
    if (!cookies || cookies.count === 0) return '';
    const severityIcon = s => s === 'High' ? '❌' : '⚠️';
    const seen = new Set();
    const uniqueIssues = (cookies.issues || []).filter(i => {
        const key = `${i.name}|${i.flag}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
    const issueItems = uniqueIssues
        .map(i => `<div class="item">${severityIcon(i.severity)} <strong>${i.name}</strong> — missing <code>${i.flag}</code>: ${i.detail}</div>`)
        .join('');
    const strengthItems = (cookies.strengths || [])
        .map(s => `<div class="item strength">✅ ${s}</div>`)
        .join('');
    const body = (issueItems + strengthItems) || '<div class="no-items">All cookies secure</div>';
    return `<div class="section"><div class="section-title">Cookies (${cookies.count})</div>${body}</div>`;
}

function renderDetails(data) {
    const ip = data.connection?.serverIp;
    const hosting = data.connection?.hostingInfo;
    const serverType = data.server?.type;
    const poweredBy = data.server?.poweredBy;
    const ipStr = ip ? `${ip}${hosting ? ` — ${hosting}` : ''}` : null;
    const rows = [
        ipStr          && `<div class="item">🌐 Server IP: ${ipStr}</div>`,
        serverType     && serverType !== 'Not disclosed' && `<div class="item">🖥 Server: ${serverType}</div>`,
        poweredBy      && `<div class="item">⚡ Powered by: ${poweredBy}</div>`,
    ].filter(Boolean).join('');
    if (!rows) return '';
    return `<div class="section"><div class="section-title">Details</div>${rows}</div>`;
}

function renderResult(data) {
    const riskCls  = riskClass(data.riskLevel);
    const colorCls = colorClass(data.riskLevel);

    const issueItems = (data.issues || [])
        .map(i => `<div class="item">${i}</div>`)
        .join('') || '<div class="no-items">None detected</div>';

    const strengthItems = (data.strengths || [])
        .map(s => `<div class="item strength">${s}</div>`)
        .join('') || '<div class="no-items">None detected</div>';

    content.innerHTML = `
        <div class="score-row">
            <div class="score-circle ${colorCls}">
                <span class="score-num">${data.total ?? '?'}</span>
                <span class="score-max">/ ${data.maxScore ?? 20}</span>
            </div>
            <div class="score-meta">
                <div class="risk-badge ${riskCls}">${securityLabel(data.riskLevel) || 'Unknown'}</div>
                <div class="score-label">issues detected</div>
            </div>
        </div>
        <div class="section">
            <div class="section-title">Issues</div>
            ${issueItems}
        </div>
        <div class="section">
            <div class="section-title">Strengths</div>
            ${strengthItems}
        </div>
        ${renderDetails(data)}
        ${renderCookies(data.cookies)}
        ${renderSettings(false, true)}
    `;
    bindSave();
}

function renderSettings(showSavedMsg, collapsed = false) {
    if (collapsed) {
        return `
            <div class="settings-collapsed">
                <span class="settings-toggle" id="settingsToggle">⚙ API Key</span>
                <div class="settings-body" id="settingsBody" style="display:none">
                    <input type="password" id="apiKeyInput" placeholder="Paste your API key…">
                    <button class="save-btn" id="saveBtn">Save</button>
                    <div class="saved-msg" id="savedMsg">Saved ✓</div>
                </div>
            </div>
        `;
    }
    return `
        <div class="settings">
            <label>API Key</label>
            <input type="password" id="apiKeyInput" placeholder="Paste your API key…">
            <button class="save-btn" id="saveBtn">Save</button>
            <div class="saved-msg" id="savedMsg" style="${showSavedMsg ? 'display:block' : ''}">Saved ✓</div>
        </div>
    `;
}

function bindSave() {
    const input    = document.getElementById('apiKeyInput');
    const saveBtn  = document.getElementById('saveBtn');
    const savedMsg = document.getElementById('savedMsg');
    const toggle   = document.getElementById('settingsToggle');
    const body     = document.getElementById('settingsBody');

    if (toggle && body) {
        toggle.addEventListener('click', () => {
            const open = body.style.display !== 'none';
            body.style.display = open ? 'none' : 'block';
            if (!open) chrome.storage.local.get('apiKey', ({ apiKey }) => { if (apiKey && input) input.value = apiKey; });
        });
    } else if (input) {
        chrome.storage.local.get('apiKey', ({ apiKey }) => { if (apiKey) input.value = apiKey; });
    }

    if (!saveBtn) return;
    saveBtn.addEventListener('click', () => {
        const key = input?.value?.trim();
        if (!key) return;
        chrome.storage.local.set({ apiKey: key }, () => {
            if (savedMsg) { savedMsg.style.display = 'block'; setTimeout(() => savedMsg.style.display = 'none', 2000); }
        });
    });
}

function renderState(icon, message) {
    content.innerHTML = `
        <div class="state-msg">
            <div class="icon">${icon}</div>
            ${message}
        </div>
        ${renderSettings(false)}
    `;
    bindSave();
}

(async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    try {
        domainEl.textContent = new URL(tab.url).hostname;
    } catch { /* non-url tab */ }

    const key = `result_${tab.id}`;
    const stored = await chrome.storage.session.get(key);
    const result = stored[key];

    if (!result) {
        renderState('🔍', 'No data yet — navigate to a page');
        return;
    }
    if (result.loading) {
        renderState('⏳', 'Analysing…');
        return;
    }
    if (result.error) {
        renderState('⚠️', result.error);
        return;
    }

    renderResult(result);
})();
