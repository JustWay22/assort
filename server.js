app.post('/api/referral/withdraw', requireAuth, async (req, res) => {
  const earnings = await dbGet(
    'SELECT SUM(earning_rub) as total FROM referral_earnings WHERE referrer_id = ?',
    [req.dbUser.id]
  );
  const amount = earnings.total || 0;
  if (amount <= 0) return res.status(400).json({ error: 'No earnings to withdraw' });

  await dbRun(
    'UPDATE users SET balance_rub = balance_rub + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
    [amount, req.dbUser.id]
  );
  await dbRun(
    'DELETE FROM referral_earnings WHERE referrer_id = ?',
    [req.dbUser.id]
  );

  const user = await dbGet('SELECT balance_rub FROM users WHERE id = ?', [req.dbUser.id]);
  res.json({ ok: true, amount, new_balance: user.balance_rub });
});
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fetch = require('node-fetch');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// ==================== DATABASE ====================
const db = new sqlite3.Database(path.join(__dirname, 'game.db'), (err) => {
  if (err) console.error('DB error:', err);
  else console.log('✅ Database connected');
});

// Helper: run query as promise
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

// Create tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_id TEXT UNIQUE NOT NULL,
    tg_username TEXT,
    tg_first_name TEXT,
    balance_rub REAL DEFAULT 50,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    amount_ton REAL,
    amount_rub REAL,
    ton_rate REAL,
    tx_hash TEXT UNIQUE,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS game_rounds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    bet_rub REAL NOT NULL,
    crash_point REAL NOT NULL,
    cashout_multiplier REAL,
    win_rub REAL DEFAULT 0,
    result TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS pending_deposits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount_ton REAL NOT NULL,
    wallet_address TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    checked_at DATETIME,
    status TEXT DEFAULT 'waiting'
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS cryptobot_invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    invoice_id TEXT UNIQUE NOT NULL,
    asset TEXT NOT NULL,
    amount REAL NOT NULL,
    amount_rub REAL NOT NULL,
    status TEXT DEFAULT 'active',
    pay_url TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    paid_at DATETIME
  )`);

  console.log('✅ Tables ready');
});

// ==================== MIDDLEWARE ====================
app.use(cors({
  origin: [
    'https://assort-five.vercel.app',
    'http://localhost:3000',
    /\.vercel\.app$/
  ],
  credentials: true
}));

// CryptoBot webhook needs raw body for signature verification — register BEFORE express.json()
app.use('/api/cryptobot/webhook', express.raw({ type: 'application/json' }));

app.use(express.json());

// ==================== TELEGRAM AUTH ====================
function validateTelegramWebAppData(initData) {
  const BOT_TOKEN = process.env.BOT_TOKEN;
  if (!BOT_TOKEN) { console.error('BOT_TOKEN not set!'); return null; }

  try {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    if (!hash) return null;
    params.delete('hash');

    const checkArr = [];
    for (const [key, value] of [...params.entries()].sort()) {
      checkArr.push(`${key}=${value}`);
    }
    const checkString = checkArr.join('\n');

    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
    const hmac = crypto.createHmac('sha256', secretKey).update(checkString).digest('hex');

    if (hmac !== hash) return null;

    const authDate = parseInt(params.get('auth_date') || '0');
    if (Math.floor(Date.now() / 1000) - authDate > 86400) return null;

    const userStr = params.get('user');
    if (!userStr) return null;
    return JSON.parse(userStr);
  } catch (e) {
    console.error('TG auth error:', e.message);
    return null;
  }
}

async function requireAuth(req, res, next) {
  const initData = req.headers['x-telegram-init-data'];
  if (!initData) return res.status(401).json({ error: 'No auth data' });

  const user = validateTelegramWebAppData(initData);
  if (!user) return res.status(401).json({ error: 'Invalid auth' });

  req.tgUser = user;

  try {
    await dbRun(`
      INSERT INTO users (tg_id, tg_username, tg_first_name)
      VALUES (?, ?, ?)
      ON CONFLICT(tg_id) DO UPDATE SET
        tg_username = excluded.tg_username,
        tg_first_name = excluded.tg_first_name,
        updated_at = CURRENT_TIMESTAMP
    `, [String(user.id), user.username || '', user.first_name || '']);

    const dbUser = await dbGet('SELECT * FROM users WHERE tg_id = ?', [String(user.id)]);
    req.dbUser = dbUser;
    next();
  } catch(e) {
    console.error('Auth DB error:', e);
    res.status(500).json({ error: 'Server error' });
  }
}

// ==================== TON RATE ====================
let cachedRate = { rate: 115, timestamp: 0 };

async function getTonRate() {
  const now = Date.now();
  if (now - cachedRate.timestamp < 5 * 60 * 1000) return cachedRate.rate;
  try {
    const res = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=the-open-network&vs_currencies=rub');
    const data = await res.json();
    const rate = data?.['the-open-network']?.rub;
    if (rate && rate > 0) { cachedRate = { rate, timestamp: now }; return rate; }
  } catch (e) { console.error('Rate fetch error:', e.message); }
  return cachedRate.rate;
}

// ==================== TON VERIFICATION ====================
const WALLET_ADDRESS = process.env.WALLET_ADDRESS || 'UQAVxMR3ycUvfkmAC8x5elwY9X-jX77sOp2wEVobK1uhvdR4';

// TONCenter returns addresses in raw form (0:hex...), while TON Connect gives user-friendly
// form (UQ.../EQ...). We normalize both to the raw hex tail for comparison.
function normalizeAddress(addr) {
  if (!addr) return null;
  try {
    // Raw form: "0:abcdef..." -> take hex part
    if (addr.includes(':')) {
      return addr.split(':')[1].toLowerCase();
    }
    // User-friendly base64/base64url form: decode and extract the 32-byte hash
    let b64 = addr.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    const buf = Buffer.from(b64, 'base64');
    // Format: [flags(1)][workchain(1)][hash(32)][crc(2)]
    if (buf.length >= 34) {
      return buf.slice(2, 34).toString('hex').toLowerCase();
    }
  } catch (e) {
    console.error('Address normalize error for', addr, ':', e.message);
  }
  return addr.toLowerCase();
}

async function checkWalletTransactions(sinceTimestamp) {
  try {
    const url = `https://toncenter.com/api/v2/getTransactions?address=${WALLET_ADDRESS}&limit=20`;
    const res = await fetch(url);
    const data = await res.json();
    if (!data.ok || !data.result) {
      console.log('TONCenter response not ok:', JSON.stringify(data).slice(0, 300));
      return [];
    }

    const txs = data.result
      .filter(tx => tx.utime >= sinceTimestamp)
      .map(tx => ({
        hash: tx.transaction_id?.hash,
        amount_ton: (tx.in_msg?.value || 0) / 1e9,
        from_address: tx.in_msg?.source,
        from_address_normalized: normalizeAddress(tx.in_msg?.source),
        timestamp: tx.utime
      }))
      .filter(tx => tx.amount_ton > 0 && tx.from_address);

    console.log(`TONCenter: found ${txs.length} candidate txs since ${sinceTimestamp}:`,
      txs.map(t => `${t.amount_ton} TON from ${t.from_address} (norm: ${t.from_address_normalized})`).join(' | '));

    return txs;
  } catch (e) {
    console.error('TON API error:', e.message);
    return [];
  }
}

// ==================== CRYPTOBOT ====================
const CRYPTOBOT_TOKEN = process.env.CRYPTOBOT_TOKEN;
// Use 'https://testnet-pay.crypt.bot/api' for testnet token (@CryptoTestnetBot)
const CRYPTOBOT_API = process.env.CRYPTOBOT_API_URL || 'https://pay.crypt.bot/api';

async function cryptoBotRequest(method, params = {}) {
  if (!CRYPTOBOT_TOKEN) throw new Error('CRYPTOBOT_TOKEN not set');
  const res = await fetch(`${CRYPTOBOT_API}/${method}`, {
    method: 'POST',
    headers: {
      'Crypto-Pay-API-Token': CRYPTOBOT_TOKEN,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(params)
  });
  const data = await res.json();
  if (!data.ok) throw new Error(data.error?.name || 'CryptoBot API error');
  return data.result;
}

function verifyCryptoBotSignature(rawBody, signature) {
  if (!CRYPTOBOT_TOKEN) return false;
  const secret = crypto.createHash('sha256').update(CRYPTOBOT_TOKEN).digest();
  const hmac = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  return hmac === signature;
}

// ==================== ROUTES ====================

app.get('/health', (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

app.get('/api/ton-rate', async (req, res) => {
  const rate = await getTonRate();
  res.json({ rate, currency: 'RUB' });
});

app.get('/api/me', requireAuth, (req, res) => {
  const u = req.dbUser;
  res.json({ id: u.id, tg_id: u.tg_id, username: u.tg_username, first_name: u.tg_first_name, balance_rub: u.balance_rub });
});

app.post('/api/deposit/init', requireAuth, async (req, res) => {
  const { amount_ton, wallet_address } = req.body;
  if (!amount_ton || amount_ton < 0.1) return res.status(400).json({ error: 'Minimum deposit: 0.1 TON' });
  if (!wallet_address) return res.status(400).json({ error: 'Wallet address required' });

  const rate = await getTonRate();
  const result = await dbRun(
    'INSERT INTO pending_deposits (user_id, amount_ton, wallet_address) VALUES (?, ?, ?)',
    [req.dbUser.id, amount_ton, wallet_address]
  );

  res.json({ deposit_id: result.lastID, amount_ton, amount_rub: Math.round(amount_ton * rate), rate, to_address: WALLET_ADDRESS });
});

app.get('/api/deposit/check/:deposit_id', requireAuth, async (req, res) => {
  const deposit = await dbGet('SELECT * FROM pending_deposits WHERE id = ? AND user_id = ?', [req.params.deposit_id, req.dbUser.id]);
  if (!deposit) return res.status(404).json({ error: 'Deposit not found' });
  if (deposit.status === 'completed') return res.json({ status: 'completed', credited: true });

  const depositTime = Math.floor(new Date(deposit.created_at).getTime() / 1000);
  const txs = await checkWalletTransactions(depositTime - 60);

  const expectedAddrNorm = normalizeAddress(deposit.wallet_address);
  console.log(`Checking deposit #${deposit.id}: expecting ${deposit.amount_ton} TON from ${deposit.wallet_address} (norm: ${expectedAddrNorm})`);

  for (const tx of txs) {
    const addressMatches = tx.from_address_normalized === expectedAddrNorm;
    // Allow up to 0.05 TON tolerance: sender's wallet may deduct gas before the value reaches us,
    // or amount might be slightly adjusted by the wallet app.
    const amountMatches = Math.abs(tx.amount_ton - deposit.amount_ton) < 0.05;

    if (addressMatches && amountMatches) {
      const existing = await dbGet('SELECT id FROM transactions WHERE tx_hash = ?', [tx.hash]);
      if (existing) {
        await dbRun('UPDATE pending_deposits SET status = ? WHERE id = ?', ['completed', deposit.id]);
        return res.json({ status: 'completed', credited: true });
      }

      const rate = await getTonRate();
      const amount_rub = tx.amount_ton * rate;

      await dbRun('INSERT INTO transactions (user_id, type, amount_ton, amount_rub, ton_rate, tx_hash, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [req.dbUser.id, 'deposit', tx.amount_ton, amount_rub, rate, tx.hash, 'completed']);
      await dbRun('UPDATE users SET balance_rub = balance_rub + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [amount_rub, req.dbUser.id]);
      await dbRun('UPDATE pending_deposits SET status = ? WHERE id = ?', ['completed', deposit.id]);

      const updatedUser = await dbGet('SELECT balance_rub FROM users WHERE id = ?', [req.dbUser.id]);
      return res.json({ status: 'completed', credited: true, amount_ton: tx.amount_ton, amount_rub, new_balance: updatedUser.balance_rub });
    }
  }

  await dbRun('UPDATE pending_deposits SET checked_at = CURRENT_TIMESTAMP WHERE id = ?', [deposit.id]);
  res.json({ status: 'waiting', credited: false });
});

app.post('/api/game/round', requireAuth, async (req, res) => {
  const { bet_rub, crash_point, cashout_multiplier, win_rub, result } = req.body;
  if (!bet_rub || bet_rub <= 0) return res.status(400).json({ error: 'Invalid bet' });

  const user = await dbGet('SELECT balance_rub FROM users WHERE id = ?', [req.dbUser.id]);
  if (user.balance_rub < bet_rub) return res.status(400).json({ error: 'Insufficient balance' });

  await dbRun('UPDATE users SET balance_rub = balance_rub - ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [bet_rub, req.dbUser.id]);
  if (result === 'win' && win_rub > 0) {
    await dbRun('UPDATE users SET balance_rub = balance_rub + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [win_rub, req.dbUser.id]);
  }
  await dbRun('INSERT INTO game_rounds (user_id, bet_rub, crash_point, cashout_multiplier, win_rub, result) VALUES (?, ?, ?, ?, ?, ?)',
    [req.dbUser.id, bet_rub, crash_point, cashout_multiplier || null, win_rub || 0, result]);

  const updatedUser = await dbGet('SELECT balance_rub FROM users WHERE id = ?', [req.dbUser.id]);
  res.json({ ok: true, new_balance: updatedUser.balance_rub });
});

app.get('/api/stats', requireAuth, async (req, res) => {
  const stats = await dbGet(`
    SELECT COUNT(*) as games, SUM(CASE WHEN result='win' THEN 1 ELSE 0 END) as wins,
    SUM(bet_rub) as total_bet, SUM(win_rub) as total_win, MAX(cashout_multiplier) as best_multiplier
    FROM game_rounds WHERE user_id = ?
  `, [req.dbUser.id]);
  res.json({ stats });
});

app.get('/api/game/history', requireAuth, async (req, res) => {
  const rounds = await dbAll('SELECT * FROM game_rounds WHERE user_id = ? ORDER BY created_at DESC LIMIT 20', [req.dbUser.id]);
  res.json({ rounds });
});

// ==================== CRYPTOBOT ROUTES ====================

// Create an invoice for deposit
app.post('/api/cryptobot/create-invoice', requireAuth, async (req, res) => {
  try {
    const { amount, asset } = req.body;
    const validAssets = ['USDT', 'TON', 'BTC', 'ETH', 'LTC', 'BNB', 'TRX', 'USDC'];
    const selectedAsset = validAssets.includes(asset) ? asset : 'USDT';

    if (!amount || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });

    const rate = await getTonRate(); // RUB per TON, used for TON; for others we estimate via TON rate proxy is wrong, so:
    // For RUB conversion we use a simple rule: if asset is TON, use TON rate; otherwise treat 1 unit ≈ rough USD-RUB via TON rate proxy is inaccurate.
    // Simplest reliable approach: ask user for amount in the chosen asset, and compute RUB only for TON precisely.
    // For non-TON assets we still credit based on real fiat amount CryptoBot reports on payment (paid_usd_rate from webhook), not an estimate here.

    const invoice = await cryptoBotRequest('createInvoice', {
      amount: String(amount),
      asset: selectedAsset,
      description: 'Пополнение баланса КРАШ',
      hidden_message: 'Спасибо за пополнение!',
      payload: JSON.stringify({ user_id: req.dbUser.id }),
      expires_in: 3600
    });

    // Estimate RUB only as a preview; final credited amount is computed from CryptoBot's reported paid amount at webhook time
    let amount_rub_preview = 0;
    if (selectedAsset === 'TON') {
      amount_rub_preview = amount * rate;
    }

    await dbRun(
      `INSERT INTO cryptobot_invoices (user_id, invoice_id, asset, amount, amount_rub, status, pay_url)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [req.dbUser.id, String(invoice.invoice_id), selectedAsset, amount, amount_rub_preview, 'active', invoice.pay_url || invoice.bot_invoice_url]
    );

    res.json({
      invoice_id: invoice.invoice_id,
      pay_url: invoice.pay_url || invoice.bot_invoice_url,
      mini_app_url: invoice.mini_app_invoice_url,
      asset: selectedAsset,
      amount
    });
  } catch (e) {
    console.error('CryptoBot invoice error:', e.message);
    res.status(500).json({ error: 'Failed to create invoice: ' + e.message });
  }
});

// Check invoice status (polling from frontend, as backup to webhook)
app.get('/api/cryptobot/check-invoice/:invoice_id', requireAuth, async (req, res) => {
  const inv = await dbGet(
    'SELECT * FROM cryptobot_invoices WHERE invoice_id = ? AND user_id = ?',
    [req.params.invoice_id, req.dbUser.id]
  );
  if (!inv) return res.status(404).json({ error: 'Invoice not found' });

  if (inv.status === 'paid') {
    const user = await dbGet('SELECT balance_rub FROM users WHERE id = ?', [req.dbUser.id]);
    return res.json({ status: 'paid', credited: true, new_balance: user.balance_rub });
  }

  // Fallback: actively check with CryptoBot in case webhook hasn't arrived yet
  try {
    const result = await cryptoBotRequest('getInvoices', { invoice_ids: inv.invoice_id });
    const remoteInvoice = result.items?.[0];
    if (remoteInvoice && remoteInvoice.status === 'paid') {
      await creditCryptoBotInvoice(remoteInvoice);
      const user = await dbGet('SELECT balance_rub FROM users WHERE id = ?', [req.dbUser.id]);
      return res.json({ status: 'paid', credited: true, new_balance: user.balance_rub });
    }
  } catch (e) {
    console.error('Invoice check error:', e.message);
  }

  res.json({ status: inv.status, credited: false });
});

// Shared crediting logic used by both webhook and polling fallback
async function creditCryptoBotInvoice(invoiceData) {
  const inv = await dbGet('SELECT * FROM cryptobot_invoices WHERE invoice_id = ?', [String(invoiceData.invoice_id)]);
  if (!inv) {
    console.error('Unknown invoice paid:', invoiceData.invoice_id);
    return;
  }
  if (inv.status === 'paid') return; // already credited, avoid double-credit

  const rate = await getTonRate();

  // Compute RUB amount from what was actually paid.
  // CryptoBot reports paid_asset/paid_amount, and for fiat conversion we use paid_usd_rate when available.
  let amount_rub;
  if (invoiceData.paid_asset === 'TON') {
    amount_rub = parseFloat(invoiceData.paid_amount) * rate;
  } else if (invoiceData.paid_usd_rate) {
    // Convert paid amount to USD, then USD to RUB using TON's RUB/USD cross rate as approximation
    const usdValue = parseFloat(invoiceData.paid_amount) * parseFloat(invoiceData.paid_usd_rate);
    // Approximate USD->RUB using a fallback fixed cross rate derived from TON rate if no direct USD rate is cached
    const usdRubRate = cachedUsdRubRate.rate;
    amount_rub = usdValue * usdRubRate;
  } else {
    amount_rub = parseFloat(invoiceData.amount) * rate; // last resort fallback
  }
  amount_rub = Math.round(amount_rub);

  await dbRun(
    `UPDATE cryptobot_invoices SET status = 'paid', paid_at = CURRENT_TIMESTAMP, amount_rub = ? WHERE invoice_id = ?`,
    [amount_rub, String(invoiceData.invoice_id)]
  );
  await dbRun(
    'UPDATE users SET balance_rub = balance_rub + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
    [amount_rub, inv.user_id]
  );
  await dbRun(
    `INSERT INTO transactions (user_id, type, amount_ton, amount_rub, ton_rate, tx_hash, status)
     VALUES (?, 'cryptobot_deposit', ?, ?, ?, ?, 'completed')`,
    [inv.user_id, invoiceData.paid_asset === 'TON' ? parseFloat(invoiceData.paid_amount) : null, amount_rub, rate, 'cryptobot_' + invoiceData.invoice_id]
  );

  console.log(`✅ Credited ${amount_rub} RUB to user ${inv.user_id} via CryptoBot invoice ${invoiceData.invoice_id}`);
}

// USD/RUB rate cache (rough, for non-TON asset conversion fallback)
let cachedUsdRubRate = { rate: 90, timestamp: 0 };
async function getUsdRubRate() {
  const now = Date.now();
  if (now - cachedUsdRubRate.timestamp < 5 * 60 * 1000) return cachedUsdRubRate.rate;
  try {
    const res = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies=rub');
    const data = await res.json();
    const rate = data?.tether?.rub;
    if (rate && rate > 0) { cachedUsdRubRate = { rate, timestamp: now }; return rate; }
  } catch (e) { console.error('USD/RUB rate fetch error:', e.message); }
  return cachedUsdRubRate.rate;
}

// CryptoBot webhook — receives payment notifications
app.post('/api/cryptobot/webhook', async (req, res) => {
  try {
    const signature = req.headers['crypto-pay-api-signature'];
    const rawBody = req.body; // Buffer, because of express.raw() middleware on this route

    if (!signature || !verifyCryptoBotSignature(rawBody, signature)) {
      console.error('CryptoBot webhook: invalid signature');
      return res.status(403).json({ error: 'Invalid signature' });
    }

    const update = JSON.parse(rawBody.toString('utf8'));

    if (update.update_type === 'invoice_paid') {
      await getUsdRubRate(); // ensure cache is warm
      await creditCryptoBotInvoice(update.payload);
    }

    res.status(200).json({ ok: true });
  } catch (e) {
    console.error('CryptoBot webhook error:', e.message);
    res.status(500).json({ error: 'Webhook processing error' });
  }
});

// ==================== START ====================
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`💰 Wallet: ${WALLET_ADDRESS}`);
  console.log(`🤖 Bot token: ${process.env.BOT_TOKEN ? 'SET ✅' : 'NOT SET ❌'}`);
  console.log(`💳 CryptoBot token: ${CRYPTOBOT_TOKEN ? 'SET ✅' : 'NOT SET ❌'}`);
});
