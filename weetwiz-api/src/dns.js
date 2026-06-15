// DNS-over-HTTPS — replaces node:dns/promises (not available in Workers)
const DOH = 'https://cloudflare-dns.com/dns-query';

export async function resolveTxt(domain) {
    try {
        const res = await fetch(`${DOH}?name=${encodeURIComponent(domain)}&type=TXT`, {
            headers: { accept: 'application/dns-json' }
        });
        const data = await res.json();
        return (data.Answer || []).map(r => [r.data.replace(/^"|"$/g, '')]);
    } catch {
        return [];
    }
}

export async function lookup(domain) {
    try {
        const res = await fetch(`${DOH}?name=${encodeURIComponent(domain)}&type=A`, {
            headers: { accept: 'application/dns-json' }
        });
        const data = await res.json();
        return (data.Answer || []).map(r => ({ address: r.data }));
    } catch {
        return [];
    }
}
