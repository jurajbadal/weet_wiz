// Detect CDN/proxy provider from response headers
// Returns { detected, provider, signals }

export function detectCDN(headers) {
    // cf-ray is injected by CF Workers runtime into every outbound fetch response,
    // so require server === 'cloudflare' to confirm the TARGET is actually on Cloudflare
    if ((headers['cf-ray'] || headers['cf-cache-status']) && headers['server'] === 'cloudflare') {
        const signals = ['cf-ray', 'cf-cache-status'].filter(h => headers[h]);
        return { detected: true, provider: 'Cloudflare', signals };
    }

    if (headers['x-amz-cf-id'] || headers['x-amz-cf-pop']) {
        const signals = ['x-amz-cf-id', 'x-amz-cf-pop'].filter(h => headers[h]);
        return { detected: true, provider: 'AWS CloudFront', signals };
    }

    if (headers['x-vercel-id']) {
        return { detected: true, provider: 'Vercel', signals: ['x-vercel-id'] };
    }

    if (headers['x-nf-request-id']) {
        return { detected: true, provider: 'Netlify', signals: ['x-nf-request-id'] };
    }

    if (headers['x-github-request-id']) {
        return { detected: true, provider: 'GitHub Pages', signals: ['x-github-request-id'] };
    }

    const akamaiSignals = Object.keys(headers).filter(h => h === 'x-check-cacheable' || h.startsWith('x-akamai-'));
    if (akamaiSignals.length > 0) {
        return { detected: true, provider: 'Akamai', signals: akamaiSignals };
    }

    // Fastly: x-timer is their proprietary per-request timing header (format: S<epoch>.<us>,VS<ns>,VE<ns>)
    // x-served-by uses opaque cache-node IDs like "cache-sjc1000098-SJC" — never contains "fastly"
    if (headers['x-timer'] || (headers['x-served-by'] && headers['x-cache'])) {
        const signals = ['x-timer', 'x-served-by', 'x-cache'].filter(h => headers[h]);
        return { detected: true, provider: 'Fastly', signals };
    }

    if (headers['via']) {
        return { detected: true, provider: `CDN (${headers['via']})`, signals: ['via'] };
    }

    return { detected: false, provider: null, signals: [] };
}
