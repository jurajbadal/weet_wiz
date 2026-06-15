const content = document.getElementById('content');
const domainEl = document.getElementById('domain');

// ── Left stripe: power + theme ──
(async () => {
    const { theme, scanEnabled } = await chrome.storage.local.get(['theme', 'scanEnabled']);
    if (theme === 'light') document.body.classList.add('light');

    const powerBtn = document.getElementById('powerBtn');
    updatePowerBtn(powerBtn, scanEnabled !== false);

    powerBtn?.addEventListener('click', async () => {
        const { scanEnabled: cur } = await chrome.storage.local.get('scanEnabled');
        const next = cur === false;
        await chrome.storage.local.set({ scanEnabled: next });
        updatePowerBtn(powerBtn, next);
    });

    document.getElementById('themeBtn')?.addEventListener('click', async () => {
        const isLight = document.body.classList.toggle('light');
        await chrome.storage.local.set({ theme: isLight ? 'light' : 'dark' });
    });
})();

function updatePowerBtn(btn, enabled) {
    if (!btn) return;
    btn.classList.toggle('power-on', enabled);
    btn.classList.toggle('power-off', !enabled);
    btn.title = enabled ? 'Scanning active — click to disable' : 'Scanning disabled — click to enable';
}

// Open IP/external links in new tab instead of navigating popup
document.addEventListener('click', e => {
    const url = e.target.dataset?.url;
    if (url) { e.preventDefault(); chrome.tabs.create({ url }); }
});

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

function formatTimestamp(ts) {
    if (!ts) return null;
    const d = new Date(ts);
    const date = d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
    const time = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    return { date, time };
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
    const ipStr = ip
        ? `<a class="ip-link" data-url="https://ipinfo.io/${ip}">${ip}</a>${hosting ? ` — ${hosting}` : ''}`
        : null;
    const rows = [
        ipStr          && `<div class="item">🌐 Server IP: ${ipStr}</div>`,
        serverType     && serverType !== 'Not disclosed' && `<div class="item">🖥 Server: ${serverType}</div>`,
        poweredBy      && `<div class="item">⚡ Powered by: ${poweredBy}</div>`,
    ].filter(Boolean).join('');
    if (!rows) return '';
    return `<div class="section"><div class="section-title">Detected Details</div>${rows}</div>`;
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

    const ts = formatTimestamp(data.timestamp);
    const timeHtml = ts
        ? `<div class="score-time">${ts.date}<br>${ts.time}</div>`
        : '';

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
            ${timeHtml}
        </div>
        <div class="section">
            <div class="section-title">Detected Issues</div>
            ${issueItems}
        </div>
        <div class="section">
            <div class="section-title">Detected Strengths</div>
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

function renderOnboarding() {
    content.innerHTML = `
        <div class="onboarding">
            <div class="onboarding-icon">🛡</div>
            <div class="onboarding-title">Welcome to WeetWiz</div>
            <div class="onboarding-desc">Enter your email to get your API key and start scanning sites instantly.</div>
            <div class="onboarding-form">
                <input type="email" id="emailInput" placeholder="your@email.com" autocomplete="email">
                <button class="save-btn" id="getKeyBtn">Get Started →</button>
                <div class="onboarding-msg" id="onboardingMsg"></div>
            </div>
            <div class="onboarding-divider">Already have a key?</div>
            ${renderSettings(false)}
        </div>
    `;
    bindSave();

    const emailInput = document.getElementById('emailInput');
    const getKeyBtn  = document.getElementById('getKeyBtn');
    const msg        = document.getElementById('onboardingMsg');

    getKeyBtn?.addEventListener('click', async () => {
        const email = emailInput?.value?.trim();
        if (!email || !email.includes('@')) {
            msg.style.color = '#f87171';
            msg.textContent = 'Enter a valid email address.';
            msg.style.display = 'block';
            return;
        }
        getKeyBtn.disabled = true;
        getKeyBtn.textContent = 'Opening…';
        try {
            const res = await fetch('https://weetwiz-api.weetwiz.com/api/checkout', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email }),
            });
            const data = await res.json();
            if (!res.ok || !data.url) throw new Error(data.error || `Error ${res.status}`);
            chrome.tabs.create({ url: data.url });
            msg.style.color = '#4ade80';
            msg.innerHTML = 'Checkout opened — your API key will arrive by email.<br>Paste it below once received.';
            msg.style.display = 'block';
            getKeyBtn.textContent = 'Done ✓';
        } catch (err) {
            msg.style.color = '#f87171';
            msg.textContent = err.message;
            msg.style.display = 'block';
            getKeyBtn.disabled = false;
            getKeyBtn.textContent = 'Get Started →';
        }
    });
}

(async () => {
    const { apiKey } = await chrome.storage.local.get('apiKey');
    if (!apiKey) {
        renderOnboarding();
        return;
    }

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    try {
        const hostname = new URL(tab.url).hostname;
        domainEl.innerHTML = `<a class="ip-link domain" data-url="https://${hostname}">${hostname}</a>`;
    } catch { /* non-url tab */ }

    const key = `result_${tab.id}`;
    const stored = await chrome.storage.session.get(key);
    const result = stored[key];

    if (!result) {
        renderState('🔍', 'No data yet — navigate to a page');
        return;
    }
    if (result.disabled) {
        renderState('⏸', 'Scanning disabled — click ⏻ to enable');
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
