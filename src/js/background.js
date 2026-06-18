const API_BASE = 'https://weetwiz-api.weetwiz.com';
const headerCache = new Map();

async function scoreUrl(tabId, payload) {
    chrome.storage.session.set({ [`result_${tabId}`]: { loading: true } });
    chrome.storage.local.get(['apiKey', 'scanEnabled'], async ({ apiKey, scanEnabled }) => {
        if (scanEnabled === false) {
            chrome.storage.session.set({ [`result_${tabId}`]: { disabled: true } });
            return;
        }
        if (!apiKey) {
            chrome.storage.session.set({ [`result_${tabId}`]: { error: 'No API key — open popup to set one' } });
            return;
        }
        try {
            const res = await fetch(`${API_BASE}/api/score`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': apiKey,
                },
                body: JSON.stringify(payload),
            });
            const data = await res.json();
            if (!res.ok) {
                chrome.storage.session.set({ [`result_${tabId}`]: { error: data.error || `API error ${res.status}` } });
                return;
            }
            chrome.storage.session.set({ [`result_${tabId}`]: { ...data, timestamp: Date.now() } });
        } catch (err) {
            chrome.storage.session.set({ [`result_${tabId}`]: { error: err.message } });
        }
    });
}

chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
        if (details.tabId < 0) return;
        if (details.type !== 'main_frame') return;

        const headers = {};
        const cookies = [];
        details.responseHeaders.forEach(h => {
            const name = h.name.toLowerCase();
            if (name === 'set-cookie') {
                cookies.push(h.value);
            } else {
                headers[name] = h.value;
            }
        });
        console.log('[WeetWiz] headers received:', Object.keys(headers).join(', '));

        const protocol = details.url.startsWith('https') ? 'https:' : 'http:';
        const tabId = details.tabId;
        const serverIp = details.ip || null;

        headerCache.set(tabId, { headers, cookies, protocol, serverIp });
        scoreUrl(tabId, { headers, protocol, cookies, serverIp, url: details.url });
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders', 'extraHeaders']
);

chrome.runtime.onMessage.addListener((request, sender) => {
    if (request.action !== 'reaudit') return;
    const tabId = sender.tab?.id;
    if (!tabId) return;
    const cached = headerCache.get(tabId);
    if (!cached) return;
    scoreUrl(tabId, { ...cached, url: request.url });
});

chrome.tabs.onRemoved.addListener((tabId) => {
    headerCache.delete(tabId);
});
