export async function requireApiKey(request, env) {
    const key = request.headers.get('x-api-key');
    if (!key) return Response.json({ error: 'X-API-Key header required' }, { status: 401 });

    const row = await env.DB.prepare(
        'SELECT k.*, u.email FROM api_keys k JOIN users u ON k.user_id = u.id WHERE k.key = ? AND k.active = 1'
    ).bind(key).first();

    if (!row) return Response.json({ error: 'Invalid or inactive API key' }, { status: 401 });
    return null;
}
