import { fetchHeaders } from '../utils/fetch_headers.js';
import { analyzeSafety } from '../logic/analyze_safety.js';
import { detectCDN } from '../logic/detect_cdn.js';
import { analyzeCookies } from '../logic/analyze_cookies.js';

export async function scanTier1(url) {
    const { headers, protocol, status, error } = await fetchHeaders(url);
    if (error) throw new Error(error);

    const domain = new URL(url).hostname;
    const safety = await analyzeSafety(headers, protocol, domain);
    const cdn    = detectCDN(headers);
    const cookies = analyzeCookies(headers['set-cookie'] || []);

    return { tier: 1, url, status, safety, cdn, cookies };
}
