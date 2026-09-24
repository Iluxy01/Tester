// npm i express   |   BOT_TOKEN=123:ABC node server.js
import express from 'express';
import crypto from 'node:crypto';

const BOT_TOKEN = "8248460525:AAFQbBc_AmvV40zL39iAlvfRpv7IgudMGlc";
if (!BOT_TOKEN) throw new Error('Задай переменную окружения BOT_TOKEN');
const MAX_AGE_SEC = 3600; // initData старше часа не принимаем

// Проверка подписи по документации Telegram:
// secret = HMAC_SHA256(key="WebAppData", msg=BOT_TOKEN); hash = HMAC_SHA256(secret, data_check_string)
function verifyInitData(initData) {
  if (!initData) return null;
  const p = new URLSearchParams(initData);
  const hash = p.get('hash');
  if (!hash) return null;
  p.delete('hash');
  const dataCheckString = [...p.entries()].map(([k, v]) => `${k}=${v}`).sort().join('\n');
  const secret = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
  const calc = crypto.createHmac('sha256', secret).update(dataCheckString).digest('hex');
  const a = Buffer.from(calc), b = Buffer.from(hash);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  if (Date.now() / 1000 - Number(p.get('auth_date')) > MAX_AGE_SEC) return null;
  try { return JSON.parse(p.get('user')); } catch { return null; }
}

function auth(req, res, next) {
  const user = verifyInitData(req.get('X-Init-Data'));
  if (!user) return res.status(401).json({ error: 'invalid initData' });
  req.tgUser = user; // теперь user.id — доверенный
  next();
}

// Допустимые диапазоны: базовая защита от очевидно подделанных значений
const LIMITS = { reaction: [80, 2000, 'min'], iq: [70, 140, 'max'], taps: [0, 15, 'max'] };

// Демо-хранилище в памяти. В проде замени на БД (Postgres, SQLite и т.п.)
const db = new Map(); // userId -> { name, best: {test: value} }

const app = express();
app.use(express.json());
app.use(express.static('public'));

app.get('/api/me', auth, (req, res) => {
  res.json({ best: db.get(req.tgUser.id)?.best || {} });
});

app.post('/api/results', auth, (req, res) => {
  const { test, value } = req.body || {};
  const lim = LIMITS[test];
  if (!lim || typeof value !== 'number' || value < lim[0] || value > lim[1])
    return res.status(400).json({ error: 'bad result' });
  const rec = db.get(req.tgUser.id) || { name: req.tgUser.first_name, best: {} };
  const cur = rec.best[test];
  if (cur == null || (lim[2] === 'max' ? value > cur : value < cur)) rec.best[test] = value;
  db.set(req.tgUser.id, rec);
  res.json({ best: rec.best });
});

app.listen(process.env.PORT || 3000, () => console.log('Mini App server is up'));
