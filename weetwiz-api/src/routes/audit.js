import { resolveTxt, lookup }    from '../dns.js';
import { fetchHeaders }           from '../utils/fetch_headers.js';
import { analyzeSafety, computeRiskLevel } from '../logic/analyze_safety.js';
import { detectCDN }              from '../logic/detect_cdn.js';
import { analyzeCookies }         from '../logic/analyze_cookies.js';
import { auditLabels as L }       from '../config/labels.js';

// POST /api/score — weet_wiz: browser sends real headers, no server re-fetch
export async function handleScore(request, env) {
    const { headers, protocol, cookies = [], serverIp = null, url = '' } = await request.json();
    if (!headers) return Response.json({ error: 'headers required' }, { status: 400 });

    try {
        // Parse domain for DNS-based checks
        let domain = '';
        let apexDomain = '';
        let urlObj = null;
        if (url) {
            try {
                urlObj = new URL(url);
                domain = urlObj.hostname;
                const parts = domain.split('.');
                apexDomain = parts.length > 2 ? parts.slice(-2).join('.') : domain;
            } catch { /* invalid url */ }
        }

        // Run all probes in parallel — all non-fatal
        const [etagResult, spfResult, dmarcResult, httpsRedirectResult] = await Promise.allSettled([
            // ETag — Chrome strips it from extension headers
            (!headers['etag'] && url)
                ? fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(3000) })
                    .then(r => r.headers.get('etag'))
                    .catch(() => null)
                : Promise.resolve(null),
            // SPF
            apexDomain ? resolveTxt(apexDomain) : Promise.resolve([]),
            // DMARC
            apexDomain ? resolveTxt(`_dmarc.${apexDomain}`) : Promise.resolve([]),
            // HTTPS redirect probe — only if visiting via https
            (url && urlObj?.protocol === 'https:')
                ? fetch(url.replace(/^https?:\/\//, 'http://'), { method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(5000) })
                    .then(r => ({ status: r.status, location: r.headers.get('location') || '' }))
                    .catch(() => null)
                : Promise.resolve(null),
        ]);

        // Apply ETag if server-side probe found one
        if (!headers['etag'] && etagResult.value) headers['etag'] = etagResult.value;

        const safetyAnalysis = await analyzeSafety(headers, protocol || 'https:', '', {});
        const cdnResult = detectCDN(headers);
        const CDN_W = 1.0;
        safetyAnalysis.maxScore = Math.round((safetyAnalysis.maxScore + CDN_W) * 10) / 10;
        if (cdnResult.detected) {
            safetyAnalysis.score = Math.round((safetyAnalysis.score + CDN_W) * 10) / 10;
            safetyAnalysis.findings.strengths.push(L.strengths.cdn(cdnResult.provider));
        }

        const cookieAnalysis = analyzeCookies(cookies);
        const COOKIE_W = 1.0;
        safetyAnalysis.maxScore = Math.round((safetyAnalysis.maxScore + COOKIE_W) * 10) / 10;
        if (cookieAnalysis.issues.length === 0) {
            safetyAnalysis.score = Math.round((safetyAnalysis.score + COOKIE_W) * 10) / 10;
        }

        // SPF / DMARC — counted in score so all displayed issues are reflected
        if (apexDomain) {
            const spfRecords = spfResult.value || [];
            const dmarcRecords = dmarcResult.value || [];
            const hasSPF = spfRecords.flat().some(r => r.startsWith('v=spf1'));
            const hasDMARC = dmarcRecords.flat().some(r => r.startsWith('v=DMARC1'));
            const SPF_W = 1.0, DMARC_W = 1.0;
            safetyAnalysis.maxScore = Math.round((safetyAnalysis.maxScore + SPF_W + DMARC_W) * 10) / 10;
            if (hasSPF)   { safetyAnalysis.score = Math.round((safetyAnalysis.score + SPF_W) * 10) / 10; }
            else          { safetyAnalysis.findings.warnings.push(L.warnings.noSpf); }
            if (hasDMARC) { safetyAnalysis.score = Math.round((safetyAnalysis.score + DMARC_W) * 10) / 10; }
            else          { safetyAnalysis.findings.warnings.push(L.warnings.noDmarc); }
            if (hasSPF && hasDMARC) safetyAnalysis.findings.strengths.push(L.strengths.spfDmarc);
            safetyAnalysis.riskLevel = computeRiskLevel(safetyAnalysis.score, safetyAnalysis.maxScore);
        }

        // HTTPS redirect score (only when probe ran successfully)
        if (urlObj?.protocol === 'https:' && httpsRedirectResult.value !== null) {
            const REDIRECT_W = 1.0;
            safetyAnalysis.maxScore = Math.round((safetyAnalysis.maxScore + REDIRECT_W) * 10) / 10;
            const { status, location } = httpsRedirectResult.value;
            if (status >= 300 && status < 400 && location.startsWith('https://')) {
                safetyAnalysis.score = Math.round((safetyAnalysis.score + REDIRECT_W) * 10) / 10;
            }
        }

        // Normalize raw score to 0-27 display scale (after all score-affecting additions)
        if (safetyAnalysis.maxScore > 0) {
            safetyAnalysis.score    = Math.round(safetyAnalysis.score / safetyAnalysis.maxScore * 27);
            safetyAnalysis.maxScore = 27;
            safetyAnalysis.riskLevel = computeRiskLevel(safetyAnalysis.score, safetyAnalysis.maxScore);
        }

        // HTTPS redirect findings — skip if probe failed (null)
        if (urlObj?.protocol === 'https:' && httpsRedirectResult.value) {
            const { status, location } = httpsRedirectResult.value;
            if (status >= 300 && status < 400 && location.startsWith('https://')) {
                try {
                    const destHostname = new URL(location).hostname;
                    if (destHostname === domain) {
                        safetyAnalysis.findings.strengths.push(L.strengths.httpsRedirect);
                    } else {
                        safetyAnalysis.findings.strengths.push(L.strengths.httpsRedirectExt(destHostname));
                        safetyAnalysis.findings.info.push(L.info.httpsRedirectExtDomain(destHostname));
                    }
                } catch { /* invalid location URL */ }
            } else {
                safetyAnalysis.findings.warnings.push(L.warnings.noHttpsRedirect);
            }
        }

        // Server type — CDN-proxied servers hide real type
        const serverHeader = (headers['server'] || '').toLowerCase();
        const cdnMarkers = ['cloudflare', 'awselb', 'amazons3', 'cloudfront', 'vercel', 'netlify', 'fastly', 'artisanal bits'];
        const serverType = cdnResult.detected && cdnMarkers.some(m => serverHeader === m)
            ? `Not detectable (${cdnResult.provider} proxied)`
            : (headers['server'] || 'Not disclosed');

        // IP geo lookup — prefer serverIp from chrome.webRequest, fall back to DNS
        let resolvedIp = serverIp;
        if (!resolvedIp && domain) {
            try {
                const addresses = await lookup(domain);
                resolvedIp = addresses[0]?.address || null;
            } catch { /* non-fatal */ }
        }
        let hostingInfo = null;
        if (resolvedIp) {
            try {
                const geo = await fetch(`http://ip-api.com/json/${resolvedIp}?fields=country,org`)
                    .then(r => r.json())
                    .catch(() => null);
                if (geo && geo.status !== 'fail') {
                    hostingInfo = [geo.org, geo.country].filter(Boolean).join(', ') || null;
                }
            } catch { /* non-fatal */ }
        }

        return Response.json({
            total:      safetyAnalysis.score,
            maxScore:   safetyAnalysis.maxScore,
            riskLevel:  safetyAnalysis.riskLevel,
            issues:     safetyAnalysis.findings.warnings,
            strengths:  safetyAnalysis.findings.strengths,
            cdn:        cdnResult,
            cookies:    cookieAnalysis,
            server:     { type: serverType, poweredBy: headers['x-powered-by'] || null },
            connection: { serverIp: resolvedIp, hostingInfo },
        });
    } catch (error) {
        console.error('Score error:', error);
        return Response.json({ error: error.message }, { status: 500 });
    }
}

export async function handleAudit(request, env) {
    const { url, localData, browserHeaders } = await request.json();
    if (!url) return Response.json({ error: 'url is required' }, { status: 400 });

    try {
        const startTime = Date.now();
        const response = await fetchHeaders(url);

        if (response.error) {
            return Response.json({ error: `Could not reach target URL: ${response.error}` }, { status: 502 });
        }

        const responseTime = Date.now() - startTime;
        const headers = response.headers || {};
        const urlObj = new URL(url);
        const domain = urlObj.hostname;
        const protocol = response.protocol || urlObj.protocol;

        // Prefer browser-captured headers for CDN detection — real edge headers, more accurate
        const cdnResult = detectCDN(browserHeaders || headers);

        // Prefer localData.serverIp — skips DNS + ip-api.com round trips
        let serverIp = localData?.serverIp ?? null;
        let hostingInfo = localData?.hostingInfo ?? null;
        if (serverIp === null) {
            try {
                const addresses = await lookup(domain);
                serverIp = addresses[0]?.address || null;
                if (serverIp) {
                    const geo = await fetch(`http://ip-api.com/json/${serverIp}?fields=country,org`)
                        .then(r => r.json())
                        .catch(() => null);
                    if (geo && geo.status !== 'fail') {
                        hostingInfo = [geo.org, geo.country].filter(Boolean).join(', ') || null;
                    }
                }
            } catch { /* non-fatal */ }
        }

        const rawCookies = headers['set-cookie'];
        const cookieHeaders = Array.isArray(rawCookies) ? rawCookies : rawCookies ? [rawCookies] : [];
        const cookieAnalysis = analyzeCookies(cookieHeaders);

        // Item 4 — HTTP → HTTPS redirect
        // Prefer localData — browser context sees real Cloudflare redirect, CF Worker may not
        let httpsRedirect = false;
        let redirectDestination = null;
        let redirectSameDomain = null;
        if (localData?.httpsRedirect !== undefined) {
            httpsRedirect = localData.httpsRedirect;
            redirectDestination = localData.redirectDestination ?? null;
            redirectSameDomain = localData.redirectSameDomain ?? null;
        } else {
            try {
                const httpUrl = url.replace(/^https?:\/\//, 'http://');
                const httpRes = await fetch(httpUrl, { method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(5000) });
                const location = httpRes.headers.get('location') || '';
                if (httpRes.status >= 300 && httpRes.status < 400 && location) {
                    httpsRedirect = location.startsWith('https://');
                    try {
                        const destHostname = new URL(location).hostname;
                        redirectDestination = destHostname;
                        redirectSameDomain = destHostname === domain;
                    } catch { /* invalid Location URL */ }
                }
            } catch { /* non-fatal */ }
        }

        // Item 5 — SPF / DMARC (apex domain only)
        const parts = domain.split('.');
        const apexDomain = parts.length > 2 ? parts.slice(-2).join('.') : domain;
        const spfRecords = await resolveTxt(apexDomain);
        const hasSPF = spfRecords.flat().some(r => r.startsWith('v=spf1'));
        const dmarcRecords = await resolveTxt(`_dmarc.${apexDomain}`);
        const hasDMARC = dmarcRecords.flat().some(r => r.startsWith('v=DMARC1'));

        const safetyAnalysis = await analyzeSafety(headers, protocol, domain, {});

        const CDN_W = 1.0;
        safetyAnalysis.maxScore = Math.round((safetyAnalysis.maxScore + CDN_W) * 10) / 10;
        if (cdnResult.detected) {
            safetyAnalysis.score = Math.round((safetyAnalysis.score + CDN_W) * 10) / 10;
            safetyAnalysis.findings.strengths.push(L.strengths.cdn(cdnResult.provider));
        }

        const COOKIE_W = 1.0;
        safetyAnalysis.maxScore = Math.round((safetyAnalysis.maxScore + COOKIE_W) * 10) / 10;
        if (cookieAnalysis.issues.length === 0) {
            safetyAnalysis.score = Math.round((safetyAnalysis.score + COOKIE_W) * 10) / 10;
        }

        // Item 4 score + findings
        if (urlObj.protocol === 'https:') {
            const REDIRECT_W = 1.0;
            safetyAnalysis.maxScore = Math.round((safetyAnalysis.maxScore + REDIRECT_W) * 10) / 10;
            if (httpsRedirect) {
                safetyAnalysis.score = Math.round((safetyAnalysis.score + REDIRECT_W) * 10) / 10;
                if (redirectSameDomain) {
                    safetyAnalysis.findings.strengths.push(L.strengths.httpsRedirect);
                } else {
                    safetyAnalysis.findings.strengths.push(L.strengths.httpsRedirectExt(redirectDestination));
                    safetyAnalysis.findings.info.push(L.info.httpsRedirectExtDomain(redirectDestination));
                }
            } else {
                safetyAnalysis.findings.warnings.push(L.warnings.noHttpsRedirect);
            }
        }

        // Item 5 findings — counted in score so all displayed issues are reflected
        {
            const SPF_W = 1.0, DMARC_W = 1.0;
            safetyAnalysis.maxScore = Math.round((safetyAnalysis.maxScore + SPF_W + DMARC_W) * 10) / 10;
            if (hasSPF)   { safetyAnalysis.score = Math.round((safetyAnalysis.score + SPF_W) * 10) / 10; }
            else          { safetyAnalysis.findings.warnings.push(L.warnings.noSpf); }
            if (hasDMARC) { safetyAnalysis.score = Math.round((safetyAnalysis.score + DMARC_W) * 10) / 10; }
            else          { safetyAnalysis.findings.warnings.push(L.warnings.noDmarc); }
            if (hasSPF && hasDMARC) safetyAnalysis.findings.strengths.push(L.strengths.spfDmarc);
            safetyAnalysis.riskLevel = computeRiskLevel(safetyAnalysis.score, safetyAnalysis.maxScore);
        }


        // Normalize raw score to 0-27 display scale (after all score-affecting additions)
        if (safetyAnalysis.maxScore > 0) {
            safetyAnalysis.score    = Math.round(safetyAnalysis.score / safetyAnalysis.maxScore * 27);
            safetyAnalysis.maxScore = 27;
            safetyAnalysis.riskLevel = computeRiskLevel(safetyAnalysis.score, safetyAnalysis.maxScore);
        }
        const metrics = {
            performance: {
                responseTime: `${responseTime}ms`,
                protocol,
                status: response.status || 200,
                domain,
                path: urlObj.pathname,
                port: urlObj.port || (protocol === 'https:' ? '443' : '80')
            },
            security: {
                'Content-Security-Policy':          headers['content-security-policy']          || 'Not set',
                'X-Frame-Options':                  headers['x-frame-options']                  || 'Not set',
                'X-Content-Type-Options':           headers['x-content-type-options']           || 'Not set',
                'Strict-Transport-Security':        headers['strict-transport-security']        || 'Not set',
                'X-XSS-Protection':                 headers['x-xss-protection']                 || 'Not set',
                'Access-Control-Allow-Origin':      headers['access-control-allow-origin']      || 'Not set',
                'Access-Control-Allow-Credentials': headers['access-control-allow-credentials'] || 'Not set',
                'Access-Control-Allow-Methods':     headers['access-control-allow-methods']     || 'Not set',
                'Cross-Origin-Opener-Policy':       headers['cross-origin-opener-policy']       || 'Not set',
                'Cross-Origin-Resource-Policy':     headers['cross-origin-resource-policy']     || 'Not set',
                'Cross-Origin-Embedder-Policy':     headers['cross-origin-embedder-policy']     || 'Not set',
                'Referrer-Policy':                  headers['referrer-policy']                  || 'Not set',
                'Permissions-Policy':               headers['permissions-policy']               || 'Not set',
                'Content-Type':                     headers['content-type']                     || 'Not set',
            },
            certificate: protocol === 'https:' ? {
                issuer:     'Not available',
                validFrom:  'Not available',
                validTo:    'Not available',
                version:    'Not available',
                tlsVersion: 'Not available'
            } : null,
            server: {
                type:      headers['server']      || 'Not disclosed',
                poweredBy: headers['x-powered-by'] || 'Not disclosed'
            },
            connection: {
                protocol:            protocol.replace(':', ''),
                encryption:          protocol === 'https:' ? 'TLS' : 'None',
                compression:         headers['content-encoding'] || 'None',
                cdn:                 cdnResult,
                serverIp,
                hostingInfo,
                httpsRedirect,
                redirectDestination,
                redirectSameDomain
            },
            emailSecurity: { spf: hasSPF, dmarc: hasDMARC },
            cache: {
                control:      headers['cache-control'] || 'Not set',
                expires:      headers['expires']       || 'Not set',
                lastModified: headers['last-modified'] || 'Not set'
            },
            cookies: cookieAnalysis,
            safety:  safetyAnalysis
        };

        return Response.json(metrics);
    } catch (error) {
        console.error('Audit error:', error);
        return Response.json({ error: error.message }, { status: 500 });
    }
}
