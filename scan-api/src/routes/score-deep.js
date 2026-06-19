import { scanTier2 } from '../scanner/tier2.js';

export async function handleScoreDeep(req, res) {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'url required' });
    try {
        res.json(await scanTier2(url));
    } catch (err) {
        res.status(502).json({ error: err.message });
    }
}
