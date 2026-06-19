// Parse Set-Cookie headers and check each cookie for missing security flags
// Returns { count, issues: [{ name, flag, severity, detail }], strengths: [] }

export function analyzeCookies(cookieHeaders) {
    if (!cookieHeaders || cookieHeaders.length === 0) {
        return { count: 0, issues: [], strengths: [] };
    }

    const issues = [];
    const strengths = [];

    for (const cookie of cookieHeaders) {
        if (typeof cookie !== 'string' || !cookie.includes('=') || cookie.startsWith('=')) continue;
        const nameMatch = cookie.trim().match(/^([^=;]+)/);
        const name = nameMatch ? nameMatch[1].trim() : 'unknown';
        const lower = cookie.toLowerCase();

        let hasAllFlags = true;

        if (!lower.includes('secure')) {
            issues.push({ name, flag: 'Secure', severity: 'High', detail: 'Cookie sent over HTTP — session hijack risk' });
            hasAllFlags = false;
        }

        if (!lower.includes('httponly')) {
            issues.push({ name, flag: 'HttpOnly', severity: 'High', detail: 'Readable by JS — XSS can steal it' });
            hasAllFlags = false;
        }

        if (!lower.includes('samesite')) {
            issues.push({ name, flag: 'SameSite', severity: 'Medium', detail: 'Missing SameSite — CSRF risk' });
            hasAllFlags = false;
        } else if (lower.includes('samesite=none') && !lower.includes('secure')) {
            issues.push({ name, flag: 'SameSite=None without Secure', severity: 'High', detail: 'SameSite=None requires the Secure flag' });
            hasAllFlags = false;
        }

        if (hasAllFlags) {
            strengths.push(`Cookie '${name}' has all security flags set`);
        }
    }

    return { count: cookieHeaders.length, issues, strengths };
}
