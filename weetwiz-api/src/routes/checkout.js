import Stripe from 'stripe';

export async function handleCheckout(request, env) {
    const { email } = await request.json();
    if (!email) return Response.json({ error: 'email required' }, { status: 400 });

    const stripe = new Stripe(env.STRIPE_SECRET_KEY);
    try {
        await env.DB.prepare('INSERT OR IGNORE INTO users (email) VALUES (?)').bind(email).run();
        const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [{ price: env.STRIPE_PRICE_ID, quantity: 1 }],
            mode: 'payment',
            customer_email: email,
            metadata: { user_id: String(user.id) },
            success_url: `${env.APP_URL}/success`,
            cancel_url:  `${env.APP_URL}/cancel`,
        });

        await env.DB.prepare('INSERT INTO purchases (user_id, stripe_checkout_session_id) VALUES (?, ?)').bind(user.id, session.id).run();
        return Response.json({ url: session.url });
    } catch (err) {
        console.error('Checkout error:', err.message);
        return Response.json({ error: 'Failed to create checkout session' }, { status: 500 });
    }
}
