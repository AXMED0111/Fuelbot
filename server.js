// ═══════════════════════════════════════════════════════════════
//  FUELBOT PRO v4 — Exchange Proxy Server
//  Runs on Railway (free) — handles CORS + HMAC signing
//  Supports: Binance, OKX, MEXC spot orders
// ═══════════════════════════════════════════════════════════════

const express  = require('express');
const cors     = require('cors');
const crypto   = require('crypto');
const axios    = require('axios');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3000;

// ── CORS — only allow your GitHub Pages URL ───────────────────
const ALLOWED_ORIGINS = [
  process.env.FRONTEND_URL || '*',   // set this in Railway env vars
  'http://localhost:3000',
  /\.github\.io$/,                   // any github pages domain
];

app.use(cors({
  origin: (origin, cb) => {
    if(!origin) return cb(null, true); // allow non-browser requests
    const allowed = ALLOWED_ORIGINS.some(o =>
      typeof o === 'string' ? o === '*' || o === origin : o.test(origin)
    );
    cb(allowed ? null : new Error('CORS blocked'), allowed);
  },
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','X-Bot-Secret'],
}));

app.use(express.json());

// ── BOT SECRET — stops anyone else using your proxy ──────────
const BOT_SECRET = process.env.BOT_SECRET || 'fuelbot-secret-change-me';

function authCheck(req, res, next) {
  const secret = req.headers['x-bot-secret'];
  if(secret !== BOT_SECRET) {
    return res.status(401).json({ ok: false, error: 'Unauthorized' });
  }
  next();
}

// ── HELPERS ───────────────────────────────────────────────────
function hmac256(secret, payload) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

function log(msg) {
  console.log(`[${new Date().toISOString()}] ${msg}`);
}

// ═══════════════════════════════════════════════════════════════
//  HEALTH CHECK
// ═══════════════════════════════════════════════════════════════
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'FuelBot PRO v4 Proxy',
    version: '1.0.0',
    uptime: Math.floor(process.uptime()) + 's',
    exchanges: ['binance','okx','mexc'],
    timestamp: new Date().toISOString(),
  });
});

app.get('/health', (req, res) => res.json({ ok: true }));

// ═══════════════════════════════════════════════════════════════
//  BINANCE SPOT
//  POST /binance/order
//  Body: { apiKey, apiSecret, symbol, side, quantity }
// ═══════════════════════════════════════════════════════════════
app.post('/binance/order', authCheck, async (req, res) => {
  const { apiKey, apiSecret, symbol, side, quantity } = req.body;

  if(!apiKey || !apiSecret || !symbol || !side || !quantity) {
    return res.status(400).json({ ok: false, error: 'Missing required fields' });
  }

  try {
    const ts     = Date.now();
    const params = `symbol=${symbol}&side=${side.toUpperCase()}&type=MARKET&quantity=${quantity}&timestamp=${ts}`;
    const sig    = hmac256(apiSecret, params);
    const url    = `https://api.binance.com/api/v3/order?${params}&signature=${sig}`;

    log(`BINANCE ORDER: ${side.toUpperCase()} ${quantity} ${symbol}`);

    const response = await axios.post(url, null, {
      headers: {
        'X-MBX-APIKEY': apiKey,
        'Content-Type': 'application/json',
      },
      timeout: 10000,
    });

    log(`BINANCE OK: orderId=${response.data.orderId}`);
    res.json({ ok: true, exchange: 'binance', order: response.data });

  } catch(err) {
    const errData = err.response?.data || err.message;
    log(`BINANCE ERROR: ${JSON.stringify(errData)}`);
    res.status(err.response?.status || 500).json({
      ok: false, exchange: 'binance', error: errData
    });
  }
});

// Binance — get account balance
app.post('/binance/balance', authCheck, async (req, res) => {
  const { apiKey, apiSecret } = req.body;
  try {
    const ts     = Date.now();
    const params = `timestamp=${ts}`;
    const sig    = hmac256(apiSecret, params);
    const url    = `https://api.binance.com/api/v3/account?${params}&signature=${sig}`;
    const r = await axios.get(url, {
      headers: { 'X-MBX-APIKEY': apiKey },
      timeout: 8000,
    });
    const usdt = r.data.balances.find(b => b.asset === 'USDT');
    res.json({ ok: true, exchange: 'binance', usdt: usdt?.free || '0', balances: r.data.balances });
  } catch(err) {
    res.status(500).json({ ok: false, error: err.response?.data || err.message });
  }
});

// Binance — cancel order
app.post('/binance/cancel', authCheck, async (req, res) => {
  const { apiKey, apiSecret, symbol, orderId } = req.body;
  try {
    const ts     = Date.now();
    const params = `symbol=${symbol}&orderId=${orderId}&timestamp=${ts}`;
    const sig    = hmac256(apiSecret, params);
    const url    = `https://api.binance.com/api/v3/order?${params}&signature=${sig}`;
    const r = await axios.delete(url, { headers: { 'X-MBX-APIKEY': apiKey }, timeout: 8000 });
    res.json({ ok: true, exchange: 'binance', order: r.data });
  } catch(err) {
    res.status(500).json({ ok: false, error: err.response?.data || err.message });
  }
});

// ═══════════════════════════════════════════════════════════════
//  OKX SPOT
//  POST /okx/order
//  Body: { apiKey, apiSecret, passphrase, instId, side, sz }
// ═══════════════════════════════════════════════════════════════
app.post('/okx/order', authCheck, async (req, res) => {
  const { apiKey, apiSecret, passphrase, instId, side, sz } = req.body;

  if(!apiKey || !apiSecret || !passphrase || !instId || !side || !sz) {
    return res.status(400).json({ ok: false, error: 'Missing required fields' });
  }

  try {
    const ts        = Date.now().toString();
    const method    = 'POST';
    const path      = '/api/v5/trade/order';
    const body      = JSON.stringify({
      instId,
      tdMode:  'cash',     // spot mode
      side:    side.toLowerCase(),
      ordType: 'market',
      sz,
    });

    // OKX signature: timestamp + method + path + body
    const preSign = ts + method + path + body;
    const sig     = crypto.createHmac('sha256', apiSecret)
                          .update(preSign).digest('base64');

    log(`OKX ORDER: ${side.toUpperCase()} ${sz} ${instId}`);

    const response = await axios.post(`https://www.okx.com${path}`, body, {
      headers: {
        'OK-ACCESS-KEY':        apiKey,
        'OK-ACCESS-SIGN':       sig,
        'OK-ACCESS-TIMESTAMP':  ts,
        'OK-ACCESS-PASSPHRASE': passphrase,
        'Content-Type':         'application/json',
      },
      timeout: 10000,
    });

    const data = response.data;
    if(data.code !== '0') {
      log(`OKX ERROR: ${JSON.stringify(data)}`);
      return res.status(400).json({ ok: false, exchange: 'okx', error: data });
    }

    log(`OKX OK: ordId=${data.data?.[0]?.ordId}`);
    res.json({ ok: true, exchange: 'okx', order: data.data?.[0] });

  } catch(err) {
    const errData = err.response?.data || err.message;
    log(`OKX ERROR: ${JSON.stringify(errData)}`);
    res.status(err.response?.status || 500).json({
      ok: false, exchange: 'okx', error: errData
    });
  }
});

// OKX — get balance
app.post('/okx/balance', authCheck, async (req, res) => {
  const { apiKey, apiSecret, passphrase } = req.body;
  try {
    const ts      = Date.now().toString();
    const path    = '/api/v5/account/balance';
    const preSign = ts + 'GET' + path;
    const sig     = crypto.createHmac('sha256', apiSecret).update(preSign).digest('base64');
    const r = await axios.get(`https://www.okx.com${path}`, {
      headers: {
        'OK-ACCESS-KEY': apiKey, 'OK-ACCESS-SIGN': sig,
        'OK-ACCESS-TIMESTAMP': ts, 'OK-ACCESS-PASSPHRASE': passphrase,
      }, timeout: 8000,
    });
    res.json({ ok: true, exchange: 'okx', data: r.data });
  } catch(err) {
    res.status(500).json({ ok: false, error: err.response?.data || err.message });
  }
});

// ═══════════════════════════════════════════════════════════════
//  MEXC SPOT
//  POST /mexc/order
//  Body: { apiKey, apiSecret, symbol, side, quantity }
// ═══════════════════════════════════════════════════════════════
app.post('/mexc/order', authCheck, async (req, res) => {
  const { apiKey, apiSecret, symbol, side, quantity } = req.body;

  if(!apiKey || !apiSecret || !symbol || !side || !quantity) {
    return res.status(400).json({ ok: false, error: 'Missing required fields' });
  }

  try {
    const ts     = Date.now();
    const params = `symbol=${symbol}&side=${side.toUpperCase()}&type=MARKET&quantity=${quantity}&timestamp=${ts}`;
    const sig    = hmac256(apiSecret, params);
    const url    = `https://api.mexc.com/api/v3/order?${params}&signature=${sig}`;

    log(`MEXC ORDER: ${side.toUpperCase()} ${quantity} ${symbol}`);

    const response = await axios.post(url, null, {
      headers: {
        'X-MEXC-APIKEY': apiKey,
        'Content-Type': 'application/json',
      },
      timeout: 10000,
    });

    log(`MEXC OK: orderId=${response.data.orderId}`);
    res.json({ ok: true, exchange: 'mexc', order: response.data });

  } catch(err) {
    const errData = err.response?.data || err.message;
    log(`MEXC ERROR: ${JSON.stringify(errData)}`);
    res.status(err.response?.status || 500).json({
      ok: false, exchange: 'mexc', error: errData
    });
  }
});

// MEXC — get balance
app.post('/mexc/balance', authCheck, async (req, res) => {
  const { apiKey, apiSecret } = req.body;
  try {
    const ts     = Date.now();
    const params = `timestamp=${ts}`;
    const sig    = hmac256(apiSecret, params);
    const r = await axios.get(`https://api.mexc.com/api/v3/account?${params}&signature=${sig}`, {
      headers: { 'X-MEXC-APIKEY': apiKey }, timeout: 8000,
    });
    const usdt = r.data.balances?.find(b => b.asset === 'USDT');
    res.json({ ok: true, exchange: 'mexc', usdt: usdt?.free || '0' });
  } catch(err) {
    res.status(500).json({ ok: false, error: err.response?.data || err.message });
  }
});


// ═══════════════════════════════════════════════════════════════
//  AI ANALYSIS — POST /ai/analyse
//  Routes to Anthropic API (avoids browser CORS restriction)
//  Requires ANTHROPIC_KEY env var on Railway
// ═══════════════════════════════════════════════════════════════
app.post('/ai/analyse', authCheck, async (req, res) => {
  const ANTHROPIC_KEY = process.env.ANTHROPIC_KEY;
  if(!ANTHROPIC_KEY) {
    return res.status(500).json({ ok: false, error: 'ANTHROPIC_KEY not set in Railway environment variables' });
  }

  const { model, max_tokens, messages } = req.body;
  if(!messages || !messages.length) {
    return res.status(400).json({ ok: false, error: 'Missing messages' });
  }

  try {
    log(`AI analysis request — model: ${model || 'claude-sonnet-4-20250514'}`);
    const response = await axios.post('https://api.anthropic.com/v1/messages', {
      model:      model      || 'claude-sonnet-4-20250514',
      max_tokens: max_tokens || 1500,
      messages,
    }, {
      headers: {
        'x-api-key':         ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01',
        'content-type':      'application/json',
      },
      timeout: 60000,
    });

    log(`AI analysis OK — ${response.data?.usage?.output_tokens || '?'} tokens`);
    res.json(response.data);

  } catch(err) {
    const status = err.response?.status || 500;
    const msg    = err.response?.data?.error?.message || err.message;
    log(`AI analysis error: ${status} ${msg}`);
    res.status(status).json({ ok: false, error: msg });
  }
});

// ── START ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  log(`FuelBot Proxy running on port ${PORT}`);
  log(`BOT_SECRET: ${BOT_SECRET === 'fuelbot-secret-change-me' ? '⚠ USING DEFAULT — set BOT_SECRET env var!' : '✔ Custom secret set'}`);
});
