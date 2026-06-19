import { fetchHeaders } from '../utils/fetch_headers.js';
import { analyzeSafety, computeRiskLevel } from '../logic/analyze_safety.js';
import { detectCDN } from '../logic/detect_cdn.js';
import { analyzeCookies } from '../logic/analyze_cookies.js';
import { auditLabels as L } from '../config/labels.js';

export async function scanTier1(url) {
    const { headers, protocol, status, error } = await fetchHeaders(url);
    if (error) throw new Error(error);

    const domain  = new URL(url).hostname;
    const safety  = await analyzeSafety(headers, protocol, domain);
    const cdn     = detectCDN(headers);
    const cookies = analyzeCookies(headers['set-cookie'] || []);

    // CDN (+1pt)
    const CDN_W = 1.0;
    safety.maxScore = Math.round((safety.maxScore + CDN_W) * 10) / 10;
    if (cdn.detected) {
        safety.score = Math.round((safety.score + CDN_W) * 10) / 10;
        safety.findings.strengths.push(L.strengths.cdn(cdn.provider));
    }

    // Cookies (+1pt if no issues)
    const COOKIE_W = 1.0;
    safety.maxScore = Math.round((safety.maxScore + COOKIE_W) * 10) / 10;
    if (cookies.issues.length === 0) {
        safety.score = Math.round((safety.score + COOKIE_W) * 10) / 10;
    }

    // Normalize to 0–27
    if (safety.maxScore > 0) {
        safety.score    = Math.round(safety.score / safety.maxScore * 27);
        safety.maxScore = 27;
        safety.riskLevel = computeRiskLevel(safety.score, safety.maxScore);
    }

    return { tier: 1, url, status, safety, cdn, cookies };
}
