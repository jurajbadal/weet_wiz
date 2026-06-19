import { chromium } from 'playwright';

// Singleton browser — shared across requests, one context per scan
let browser = null;

async function getBrowser() {
    if (!browser) browser = await chromium.launch();
    return browser;
}

export async function scanTier2(url) {
    const b       = await getBrowser();
    const context = await b.newContext();
    const page    = await context.newPage();

    try {
        const threats = [];
        const navHeaders = {};

        page.on('response', response => {
            if (response.request().isNavigationRequest()) {
                for (const [k, v] of Object.entries(response.headers())) {
                    navHeaders[k.toLowerCase()] = v;
                }
            }
        });

        await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 });

        // Credential harvesting — forms with password/email inputs
        const forms = await page.$$eval('form', forms =>
            forms.map(f => ({
                action: f.action,
                sensitiveInputs: f.querySelectorAll('input[type=password], input[type=email]').length,
            }))
        );
        const suspiciousForms = forms.filter(f => f.sensitiveInputs > 0);
        if (suspiciousForms.length) {
            threats.push({ type: 'credential_form', count: suspiciousForms.length });
        }

        // JS redirect to different root domain (subdomain redirects are not threats)
        const finalUrl = page.url();
        const rootDomain = u => new URL(u).hostname.split('.').slice(-2).join('.');
        if (rootDomain(finalUrl) !== rootDomain(url)) {
            threats.push({ type: 'js_redirect', from: new URL(url).hostname, to: new URL(finalUrl).hostname });
        }

        return { tier: 2, url, finalUrl, threats, headers: navHeaders };
    } finally {
        await context.close();
    }
}
