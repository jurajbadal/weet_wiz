import express from 'express';
import { handleScore } from './routes/score.js';
import { handleScoreDeep } from './routes/score-deep.js';
import { handleScoreBoth } from './routes/score-both.js';

const app = express();
app.use(express.json());
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.get('/health', (req, res) => res.json({ ok: true }));
app.post('/api/score',      handleScore);
app.post('/api/score/deep', handleScoreDeep);
app.post('/api/score/both', handleScoreBoth);

app.listen(8080, () => console.log('scan-api listening on :8080'));
