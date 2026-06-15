// Server-side header fetcher — replaces chrome.webRequest / fetchPageData from the extension
// HEAD with GET fallback, same pattern as checkLink in broken_links.js

export async function fetchHeaders(url) {
    try {
        let response = await fetch(url, { method: 'HEAD', redirect: 'follow' });

        // 405 = Method Not Allowed, 520 = Cloudflare blocks HEAD — retry with GET
        if (response.status === 405 || response.status === 520) {
            response = await fetch(url, { method: 'GET', redirect: 'follow' });
        }

        const headers = {};
        for (const [key, value] of response.headers) {
            headers[key.toLowerCase()] = value;
        }

        // set-cookie merges duplicate values in the headers iterator — use getSetCookie() instead
        if (typeof response.headers.getSetCookie === 'function') {
            const setCookies = response.headers.getSetCookie();
            if (setCookies.length > 0) {
                headers['set-cookie'] = setCookies;
            }
        }

        return {
            headers,
            protocol: new URL(response.url).protocol,
            status: response.status
        };
    } catch (error) {
        return { error: error.message, headers: {}, protocol: 'https:', status: 0 };
    }
}
