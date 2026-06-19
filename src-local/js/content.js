let lastUrl = location.href;

function notifyReaudit() {
    const url = location.href;
    if (url === lastUrl) return;
    lastUrl = url;
    chrome.runtime.sendMessage({ action: 'reaudit', url });
}

window.addEventListener('hashchange', notifyReaudit);
window.addEventListener('popstate', notifyReaudit);

const origPushState = history.pushState.bind(history);
history.pushState = function (...args) {
    origPushState(...args);
    notifyReaudit();
};
