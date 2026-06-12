const API_BASE = 'https://web-api.weetwiz.com';

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

        const protocol = details.url.startsWith('https') ? 'https:' : 'http:';
        const tabId = details.tabId;

        chrome.storage.session.set({ [`result_${tabId}`]: { loading: true } });

        chrome.storage.local.get('apiKey', async ({ apiKey }) => {
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
                    body: JSON.stringify({ headers, protocol, cookies, serverIp: details.ip || null, url: details.url }),
                });
                const data = await res.json();
                if (!res.ok) {
                    chrome.storage.session.set({ [`result_${tabId}`]: { error: data.error || `API error ${res.status}` } });
                    return;
                }
                chrome.storage.session.set({ [`result_${tabId}`]: data });
            } catch (err) {
                chrome.storage.session.set({ [`result_${tabId}`]: { error: err.message } });
            }
        });
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders', 'extraHeaders']
);
