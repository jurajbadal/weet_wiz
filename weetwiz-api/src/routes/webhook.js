import Stripe from 'stripe';
import { Resend } from 'resend';

export async function handleWebhook(request, env) {
    const rawBody = await request.text();
    const sig = request.headers.get('stripe-signature') || '';
    const stripe = new Stripe(env.STRIPE_SECRET_KEY);

    let event;
    try {
        event = await stripe.webhooks.constructEventAsync(rawBody, sig, env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        return new Response(`Webhook Error: ${err.message}`, { status: 400 });
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;

        // Price guard — only process payments for this service's product
        if (env.STRIPE_PRICE_ID) {
            const lineItems = await stripe.checkout.sessions.listLineItems(session.id, { limit: 1 });
            const priceId = lineItems.data[0]?.price?.id;
            if (priceId && priceId !== env.STRIPE_PRICE_ID) return Response.json({ received: true });
        }

        const email = session.customer_details?.email || session.customer_email;
        if (!email) return Response.json({ received: true });

        await env.DB.prepare('INSERT OR IGNORE INTO users (email) VALUES (?)').bind(email).run();
        const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
        const userId = user.id;

        // Idempotency: skip if purchase already completed
        const purchase = await env.DB.prepare(
            'SELECT status FROM purchases WHERE stripe_checkout_session_id = ?'
        ).bind(session.id).first();
        if (purchase?.status === 'completed') return Response.json({ received: true });

        const bytes = new Uint8Array(32);
        crypto.getRandomValues(bytes);
        const apiKey = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        await env.DB.prepare('INSERT INTO api_keys (user_id, key) VALUES (?, ?)').bind(userId, apiKey).run();

        await env.DB.prepare(
            'INSERT OR IGNORE INTO purchases (user_id, stripe_checkout_session_id) VALUES (?, ?)'
        ).bind(userId, session.id).run();

        await env.DB.prepare(
            "UPDATE purchases SET status = 'completed', stripe_payment_intent_id = ? WHERE stripe_checkout_session_id = ?"
        ).bind(session.payment_intent, session.id).run();

        if (session.customer) {
            await env.DB.prepare('UPDATE users SET stripe_customer_id = ? WHERE id = ?').bind(session.customer, userId).run();
        }

        try {
            const resend = new Resend(env.RESEND_API_KEY);
            await resend.emails.send({
                from:    'WeetWiz <noreply@weetwiz.com>',
                to:      email,
                subject: 'Your WeetWiz API Key',
                html: `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f5f5f5;padding:40px 0;">
    <tr><td align="center">
      <table width="520" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.08);">
        <tr><td style="background:#1a1a2e;padding:28px 36px;">
          <span style="color:#ffffff;font-size:22px;font-weight:700;letter-spacing:-0.3px;">WeetWiz</span>
        </td></tr>
        <tr><td style="padding:36px 36px 12px;">
          <h1 style="margin:0 0 8px;font-size:20px;font-weight:600;color:#111;">Your API key is ready</h1>
          <p style="margin:0 0 24px;font-size:15px;color:#555;line-height:1.5;">Thanks for your purchase. Copy the key below and paste it into the WeetWiz extension settings.</p>
          <div style="background:#f0f0f5;border-radius:6px;padding:16px 20px;margin-bottom:24px;">
            <p style="margin:0 0 6px;font-size:11px;font-weight:600;color:#888;letter-spacing:0.8px;text-transform:uppercase;">API Key</p>
            <code style="font-size:15px;color:#1a1a2e;word-break:break-all;font-family:'Courier New',monospace;">${apiKey}</code>
          </div>
          <p style="margin:0 0 8px;font-size:14px;color:#555;line-height:1.6;">
            Open the <strong>WeetWiz extension</strong> → click the settings icon → paste your key → save.
          </p>
        </td></tr>
        <tr><td style="padding:12px 36px 36px;">
          <p style="margin:0;font-size:12px;color:#aaa;line-height:1.5;">Keep this key private — it cannot be recovered if lost. If you need help, reply to this email.</p>
        </td></tr>
        <tr><td style="background:#f9f9f9;padding:16px 36px;border-top:1px solid #eee;">
          <p style="margin:0;font-size:12px;color:#bbb;">© WeetWiz · <a href="https://weetwiz.com" style="color:#bbb;text-decoration:none;">weetwiz.com</a></p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`,
            });
        } catch (emailErr) {
            console.error('Email send failed:', emailErr.message);
        }

        console.log(`Key issued for user ${userId} (${email})`);
    }

    return Response.json({ received: true });
}
