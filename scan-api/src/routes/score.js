import { scanTier1 } from '../scanner/tier1.js';

export async function handleScore(req, res) {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'url required' });
    try {
        res.json(await scanTier1(url));
    } catch (err) {
        res.status(502).json({ error: err.message });
    }
}
