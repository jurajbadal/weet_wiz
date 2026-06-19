import { scanTier1 } from '../scanner/tier1.js';
import { scanTier2 } from '../scanner/tier2.js';

export async function handleScoreBoth(req, res) {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'url required' });
    try {
        const [tier1, tier2] = await Promise.all([scanTier1(url), scanTier2(url)]);
        res.json({ url, tier1, tier2 });
    } catch (err) {
        res.status(502).json({ error: err.message });
    }
}
