const API_BASE = 'http://localhost:8080';

async function scoreUrl(tabId, url) {
    chrome.storage.session.set({ [`result_${tabId}`]: { loading: true } });
    try {
        const res = await fetch(`${API_BASE}/api/score/both`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url }),
        });
        const data = await res.json();
        if (!res.ok) {
            chrome.storage.session.set({ [`result_${tabId}`]: { error: data.error || `API error ${res.status}` } });
            return;
        }
        const t1 = data.tier1 || data;
        const t2threats = (data.tier2?.threats || []).map(t => `🚨 ${t.type}: ${t.detail || t.url || ''}`);
        const flat = {
            ...t1,
            total:     t1.safety?.score,
            maxScore:  t1.safety?.maxScore,
            riskLevel: t1.safety?.riskLevel,
            strengths: t1.safety?.findings?.strengths || [],
            warnings:  [...(t1.safety?.findings?.warnings || []), ...t2threats],
            issues:    [...(t1.safety?.findings?.warnings || []), ...t2threats],
        };
        chrome.storage.session.set({ [`result_${tabId}`]: { ...flat, timestamp: Date.now() } });
    } catch (err) {
        chrome.storage.session.set({ [`result_${tabId}`]: { error: err.message } });
    }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status !== 'complete') return;
    if (!tab.url || !tab.url.startsWith('http')) return;
    scoreUrl(tabId, tab.url);
});

chrome.tabs.onRemoved.addListener((tabId) => {
    chrome.storage.session.remove(`result_${tabId}`);
});
