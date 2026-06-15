import { handleWebhook }  from './routes/webhook.js';
import { handleCheckout } from './routes/checkout.js';
import { handleAudit, handleScore } from './routes/audit.js';
import { requireApiKey }  from './auth.js';

const CORS = {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-API-Key',
};

function addCors(response) {
    const r = new Response(response.body, response);
    for (const [k, v] of Object.entries(CORS)) r.headers.set(k, v);
    return r;
}

export default {
    async fetch(request, env) {
        const { pathname } = new URL(request.url);
        const method = request.method;

        if (method === 'OPTIONS') return new Response(null, { headers: CORS });

        console.log(`${new Date().toISOString()}  ${method}  ${pathname}`);

        // Public
        if (pathname === '/health' && method === 'GET')
            return addCors(Response.json({ ok: true }));
        if (pathname === '/success' && method === 'GET')
            return addCors(new Response('<h2>Payment successful! Check your email for your API key.</h2>', { headers: { 'Content-Type': 'text/html' } }));
        if (pathname === '/cancel' && method === 'GET')
            return addCors(new Response('<h2>Payment cancelled. You can close this tab.</h2>', { headers: { 'Content-Type': 'text/html' } }));

        // Webhook — raw body, no auth
        if (pathname === '/api/webhook' && method === 'POST')
            return addCors(await handleWebhook(request, env));

        // Checkout — no auth
        if (pathname === '/api/checkout' && method === 'POST')
            return addCors(await handleCheckout(request, env));

        // Protected
        const authError = await requireApiKey(request, env);
        if (authError) return addCors(authError);

        if (pathname === '/api/audit' && method === 'POST')
            return addCors(await handleAudit(request, env));
        if (pathname === '/api/score' && method === 'POST')
            return addCors(await handleScore(request, env));

        return addCors(new Response('Not found', { status: 404 }));
    }
};
