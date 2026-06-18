import { riskLabels, auditLabels as L } from '../config/labels.js';

// Check weights — 1.5pt critical, 1pt standard
const W = {
    https:             1.5,
    hsts:              1.0,
    csp:               1.5,
    cspNoUnsafeInline: 1.0,
    cspNoUnsafeEval:   1.0,
    cspNoWildcard:     1.0,
    xFrame:            1.5,
    corsNoWildcard:    1.5,
    corsCredentials:   1.5,
    corsMethods:       1.0,
    xssNotDisabled:    1.0,
    permissions:       1.0,
    coop:              1.0,
    coep:              1.0,
    serverHidden:      1.0,
    noPoweredBy:       1.0,
    xContentType:      1.0,
    referrer:          1.0,
    noEtag:            1.0,
    noLastModified:    1.0,
};

// ≥70% Impressive, ≥50% Could Be Better, <50% Must Be Better
export function computeRiskLevel(score, maxScore) {
    const pct = maxScore > 0 ? score / maxScore : 0;
    if (pct >= 0.78) return riskLabels.IMPRESSIVE;
    if (pct >= 0.52) return riskLabels.ALMOST_IMPRESSIVE;
    if (pct >= 0.33) return riskLabels.COULD_BE_BETTER;
    return riskLabels.MUST_BE_BETTER;
}

export async function analyzeSafety(headers, protocol, domain, certInfo = {}) {
    const findings = { strong: [], warnings: [], info: [] };
    const securityIssues = new Set();
    let maxScore = 0;
    let score = 0;

    // Registers an applicable check. Returns whether it passed.
    const check = (weight, passed, onPass, onFail) => {
        maxScore += weight;
        if (passed) { score += weight; onPass?.(); }
        else        { onFail?.(); }
        return passed;
    };

    // ── HTTPS ──────────────────────────────────────────────────────────────────
    const hasHttps = check(W.https,
        protocol === 'https:',
        () => findings.strong.push(L.strengths.https),
        () => securityIssues.add(L.warnings.noHttps)
    );

    if (hasHttps) {
        const hsts = headers['strict-transport-security'];
        const maxAgeMatch = hsts?.match(/max-age=(\d+)/i);
        const hstsGood = !!hsts && parseInt(maxAgeMatch?.[1] ?? 0) >= 31536000;
        check(W.hsts,
            hstsGood,
            () => findings.strong.push(L.strengths.hsts(hsts.split(';').length)),
            () => securityIssues.add(hsts ? L.warnings.hstsShort : L.warnings.noHsts)
        );
    }

    // ── CSP ───────────────────────────────────────────────────────────────────
    const hasCsp = check(W.csp,
        !!headers['content-security-policy'],
        () => findings.strong.push(L.strengths.csp),
        () => securityIssues.add(L.warnings.noCsp)
    );

    if (hasCsp) {
        const csp = headers['content-security-policy'];
        check(W.cspNoUnsafeInline, !csp.includes("'unsafe-inline'"), null, () => securityIssues.add(L.warnings.cspUnsafeInline));
        check(W.cspNoUnsafeEval,   !csp.includes("'unsafe-eval'"),   null, () => securityIssues.add(L.warnings.cspUnsafeEval));
        check(W.cspNoWildcard,     !/(?:^|\s)\*(?:\s|;|$)/.test(csp), null, () => securityIssues.add(L.warnings.cspWildcard));
    }

    // ── X-Frame-Options ───────────────────────────────────────────────────────
    check(W.xFrame,
        !!headers['x-frame-options'],
        () => findings.strong.push(L.strengths.xFrame),
        () => securityIssues.add(L.warnings.noXFrame)
    );

    // ── CORS ──────────────────────────────────────────────────────────────────
    const corsOrigin       = headers['access-control-allow-origin'];
    const allowCredentials = headers['access-control-allow-credentials'];
    const allowMethods     = headers['access-control-allow-methods'];

    if (corsOrigin !== undefined) {
        check(W.corsNoWildcard,
            corsOrigin !== '*',
            null,
            () => securityIssues.add(L.warnings.corsWildcard)
        );
    }
    if (allowCredentials !== undefined) {
        check(W.corsCredentials,
            !(allowCredentials === 'true' && corsOrigin === '*'),
            null,
            () => securityIssues.add(L.warnings.corsCredentials)
        );
    }
    if (allowMethods !== undefined && corsOrigin === '*') {
        check(W.corsMethods,
            !/DELETE|PUT/i.test(allowMethods),
            null,
            () => securityIssues.add(L.warnings.corsMethods)
        );
    }

    // ── X-XSS-Protection (only relevant if present — deprecated header) ────────
    if (headers['x-xss-protection'] !== undefined) {
        check(W.xssNotDisabled,
            headers['x-xss-protection'].trim() !== '0',
            null,
            () => securityIssues.add(L.warnings.xssDisabled)
        );
    }

    // ── Permissions-Policy ────────────────────────────────────────────────────
    check(W.permissions,
        !!headers['permissions-policy'],
        () => findings.strong.push(L.strengths.permissions),
        () => securityIssues.add(L.warnings.noPermissions)
    );

    // ── COOP ──────────────────────────────────────────────────────────────────
    check(W.coop,
        !!headers['cross-origin-opener-policy'],
        () => findings.strong.push(L.strengths.coop),
        () => securityIssues.add(L.warnings.noCoop)
    );

    // ── COEP ──────────────────────────────────────────────────────────────────
    check(W.coep,
        !!headers['cross-origin-embedder-policy'],
        () => findings.strong.push(L.strengths.coep),
        () => securityIssues.add(L.warnings.noCoep)
    );

    // ── Server / tech exposure ─────────────────────────────────────────────────
    const CDN_SERVER_NAMES = ['cloudflare', 'awselb', 'amazons3', 'cloudfront', 'vercel', 'netlify', 'fastly', 'artisanal bits'];
    const serverVal = (headers['server'] || '').toLowerCase();
    const serverIsCdn = CDN_SERVER_NAMES.some(cdn => serverVal === cdn);

    const serverClean = check(W.serverHidden,
        !headers['server'] || serverIsCdn,
        null,
        () => securityIssues.add(L.warnings.serverExposed)
    );
    const poweredByClean = check(W.noPoweredBy,
        !headers['x-powered-by'],
        null,
        () => securityIssues.add(L.warnings.poweredByExposed)
    );
    if (serverClean && poweredByClean) findings.strong.push(L.strengths.techHidden);

    // ── X-Content-Type-Options ────────────────────────────────────────────────
    const xcto = headers['x-content-type-options'];
    check(W.xContentType,
        !!xcto && xcto.toLowerCase().includes('nosniff'),
        () => findings.strong.push(L.strengths.nosniff),
        () => securityIssues.add(xcto ? L.warnings.xContentTypeInvalid : L.warnings.noXContentType)
    );

    // ── Referrer-Policy ───────────────────────────────────────────────────────
    check(W.referrer,
        !!headers['referrer-policy'],
        () => findings.strong.push(L.strengths.referrerPolicy),
        () => securityIssues.add(L.warnings.noReferrer)
    );

    // ── Tracking vectors ──────────────────────────────────────────────────────
    check(W.noEtag,         !headers['etag'],          null, () => securityIssues.add(L.warnings.etagExposed));
    check(W.noLastModified, !headers['last-modified'],  null, () => securityIssues.add(L.warnings.lastModifiedExposed));

    // ── Score ─────────────────────────────────────────────────────────────────
    const finalScore    = Math.round(score * 10) / 10;
    const finalMaxScore = Math.round(maxScore * 10) / 10;

    findings.warnings = Array.from(securityIssues);

    return {
        score:    finalScore,
        maxScore: finalMaxScore,
        riskLevel: computeRiskLevel(finalScore, finalMaxScore),
        categories: {
            headers: { score: 0, findings: [] },
            config:  { score: 0, findings: [] },
        },
        findings: {
            strengths: findings.strong,
            warnings:  findings.warnings,
            info:      findings.info,
        },
    };
}
