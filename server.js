// ClipHeist sales site: landing page -> Stripe Checkout (£4.99) -> signed download link.
// Zero dependencies. Needs Node 20+.  Run:  node server.js
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

try { process.loadEnvFile(path.join(__dirname, '.env')); } catch {}

const PORT = +process.env.PORT || 3000;
// On Render the public address is provided automatically as RENDER_EXTERNAL_URL.
const BASE_URL = (process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
// Public landing page (e.g. the GitHub Pages site). Buyers who cancel checkout are sent back here.
const SITE_URL = (process.env.SITE_URL || BASE_URL).replace(/\/$/, '');
const STRIPE_KEY = process.env.STRIPE_SECRET_KEY || '';
const SECRET = process.env.DOWNLOAD_SECRET || '';
const INSTALLER_URL = process.env.INSTALLER_URL || ''; // optional: installer hosted elsewhere (e.g. a GitHub release)
const INSTALLER = path.resolve(__dirname, process.env.INSTALLER_PATH || 'downloads/ClipHeist-Setup.exe');
const PRICE_PENCE = 499;
const LINK_DAYS = 7;
const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const EMAIL_KEY = process.env.RESEND_API_KEY || '';
const EMAIL_FROM = process.env.EMAIL_FROM || '';
const EMAIL_API = process.env.EMAIL_API_URL || 'https://api.resend.com/emails';
const LICENSE_PRIVATE_KEY = process.env.LICENSE_PRIVATE_KEY || '';
const MAX_DEVICES = +process.env.MAX_DEVICES || 2;
const DATA_DIR = path.join(__dirname, 'data');
const emailReady = () => !!(EMAIL_KEY && EMAIL_FROM);
const PUBLIC = path.join(__dirname, 'public');
const TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };

const configured = () => STRIPE_KEY.startsWith('sk_') && SECRET.length >= 16;

async function stripe(method, route, params) {
  const res = await fetch('https://api.stripe.com/v1' + route, {
    method,
    headers: { Authorization: `Bearer ${STRIPE_KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params ? new URLSearchParams(params).toString() : undefined,
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error?.message || 'Stripe error');
  return json;
}

const sign = (data) => crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
function makeToken(sessionId) {
  const body = Buffer.from(`${sessionId}.${Date.now() + LINK_DAYS * 864e5}`).toString('base64url');
  return `${body}.${sign(body)}`;
}
function checkToken(token) {
  const [body, sig] = String(token || '').split('.');
  if (!body || !sig) return false;
  const expect = sign(body);
  if (sig.length !== expect.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return false;
  const exp = +Buffer.from(body, 'base64url').toString().split('.').pop();
  return Date.now() < exp;
}

/* ---------- licence keys ----------
   Every order gets its own key (CH-XXXXX-XXXXX-XXXXX-XXXXX), derived from the order id with the server secret,
   so keys can't be guessed or forged. The app activates a key here once per PC (limit MAX_DEVICES per key). */
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function code(input, len) {
  const h = crypto.createHmac('sha256', SECRET).update(input).digest();
  let out = '';
  for (let i = 0; i < len; i++) out += ALPHABET[h[i] % 32];
  return out;
}
const formatKey = (id) => 'CH-' + (id + code('key:' + id, 10)).match(/.{5}/g).join('-');
const licenceFor = (orderId) => formatKey(code('order:' + orderId, 10));
function parseLicence(key) {
  const raw = String(key || '').toUpperCase().replace(/[^A-Z0-9]/g, '').replace(/^CH/, '');
  if (raw.length !== 20) return null;
  const id = raw.slice(0, 10), mac = raw.slice(10), expect = code('key:' + id, 10);
  return crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expect)) ? id : null;
}
const actFile = path.join(DATA_DIR, 'activations.json');
let activations = {};
try { activations = JSON.parse(fs.readFileSync(actFile, 'utf8')); } catch {}
function saveActivations() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(actFile + '.tmp', JSON.stringify(activations));
  fs.renameSync(actFile + '.tmp', actFile);
}
function activate(key, device) {
  const id = SECRET && parseLicence(key);
  if (!id) return { ok: false, error: 'That licence key is not valid. Check it against your email.' };
  if (!/^[a-f0-9]{32,64}$/.test(device || '')) return { ok: false, error: 'Bad request.' };
  const rec = activations[id] || (activations[id] = { devices: [] });
  if (rec.revoked) return { ok: false, error: 'This licence key has been disabled.' };
  if (!rec.devices.includes(device)) {
    if (rec.devices.length >= MAX_DEVICES) return { ok: false, error: `This key is already active on ${MAX_DEVICES} PCs.` };
    rec.devices.push(device);
    saveActivations();
  }
  const canon = formatKey(id);
  const priv = crypto.createPrivateKey({ key: Buffer.from(LICENSE_PRIVATE_KEY, 'base64'), format: 'der', type: 'pkcs8' });
  const proof = crypto.sign(null, Buffer.from(`${canon}|${device}`), priv).toString('base64');
  return { ok: true, key: canon, proof };
}
const hits = new Map();
function limited(ip) {
  const now = Date.now(), list = (hits.get(ip) || []).filter((t) => now - t < 60000);
  list.push(now); hits.set(ip, list);
  if (hits.size > 5000) hits.clear();
  return list.length > 10;
}

const esc = (v) => String(v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Emails the buyer their personal download link. Safe to call more than once per order.
const emailed = new Set();
async function emailLink(session) {
  const to = session.customer_details?.email;
  if (!emailReady() || !to || session.payment_status !== 'paid') return false;
  if (emailed.has(session.id) || session.metadata?.emailed === '1') return true;
  emailed.add(session.id);
  const link = `${BASE_URL}/download?t=${encodeURIComponent(makeToken(session.id))}`;
  const key = licenceFor(session.id);
  try {
    const res = await fetch(EMAIL_API, {
      method: 'POST',
      headers: { Authorization: `Bearer ${EMAIL_KEY}`, 'Content-Type': 'application/json', 'Idempotency-Key': `clipheist-${session.id}` },
      body: JSON.stringify({
        from: EMAIL_FROM,
        to: [to],
        subject: 'Your ClipHeist licence key and download',
        text: `Thanks for buying ClipHeist.

Your licence key: ${key}
Enter it when you first open the app. It works on up to ${MAX_DEVICES} PCs.

Your personal download link (valid for ${LINK_DAYS} days):
${link}

Run ClipHeist-Setup.exe. If Windows shows a "Windows protected your PC" notice, choose More info, then Run anyway.

Your key and link are unique to your order, so please don't share them.

At checkout you asked for immediate access to this digital product and acknowledged that the 14-day right to cancel ends once it is supplied. If the app is faulty, reply to this email and we will put it right.`,
        html: `<div style="font-family:Segoe UI,Arial,sans-serif;font-size:16px;color:#111;max-width:520px">
<h2 style="margin:0 0 12px">Thanks for buying ClipHeist</h2>
<p>Your licence key:</p>
<p style="font:700 20px Consolas,monospace;background:#f3f3f6;border:1px solid #ddd;border-radius:8px;padding:12px 14px;letter-spacing:1px">${key}</p>
<p style="font-size:14px;color:#555">Enter it when you first open the app. It works on up to ${MAX_DEVICES} PCs.</p>
<p>Your personal download link (works for ${LINK_DAYS} days):</p>
<p><a href="${esc(link)}" style="display:inline-block;background:#ff3d8b;color:#fff;font-weight:700;text-decoration:none;padding:14px 22px;border-radius:10px">Download for Windows</a></p>
<p style="font-size:14px;color:#555">Run ClipHeist-Setup.exe. If Windows shows a "Windows protected your PC" notice, choose More info, then Run anyway.</p>
<p style="font-size:13px;color:#777">Your key and link are unique to your order, so please don't share them.</p>
<p style="font-size:13px;color:#777">At checkout you asked for immediate access to this digital product and acknowledged that the 14-day right to cancel ends once it is supplied. If the app is faulty, reply to this email and we will put it right.</p></div>`,
      }),
    });
    if (!res.ok) throw new Error(`email API ${res.status}: ${(await res.text()).slice(0, 200)}`);
  } catch (e) {
    emailed.delete(session.id);
    throw e;
  }
  if (STRIPE_KEY) stripe('POST', `/checkout/sessions/${session.id}`, { 'metadata[emailed]': '1' }).catch(() => {});
  return true;
}

function verifyStripeSignature(raw, header) {
  const parts = Object.fromEntries(String(header || '').split(',').map((kv) => kv.split('=')));
  if (!parts.t || !parts.v1 || Math.abs(Date.now() / 1000 - +parts.t) > 300) return false;
  const expect = crypto.createHmac('sha256', WEBHOOK_SECRET).update(`${parts.t}.${raw}`).digest('hex');
  return parts.v1.length === expect.length && crypto.timingSafeEqual(Buffer.from(parts.v1), Buffer.from(expect));
}
function readBody(req, limit = 1e6) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0;
    req.on('data', (c) => { n += c.length; if (n > limit) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function page(title, inner) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} · ClipHeist</title><link rel="stylesheet" href="/style.css"></head><body><main class="narrow">
<a class="brand" href="/"><span class="mark"></span>Clip<b>Heist</b></a>${inner}</main></body></html>`;
}
function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', ...headers });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, BASE_URL);
  try {
    if (req.method === 'POST' && url.pathname === '/buy') {
      const form = new URLSearchParams(await readBody(req, 2000));
      if (form.get('consent') !== 'yes') {
        return send(res, 400, page('One more thing', `<h1>Please tick the box first</h1><p>We need your OK to deliver the download straight away.</p><a class="btn" href="/#buy">Back</a>`));
      }
      if (!configured()) {
        return send(res, 503, page('Not open yet', `<h1>Checkout isn't switched on yet</h1><p>The shop owner still needs to add their Stripe keys. Nothing has been charged.</p><a class="btn" href="/">Back</a>`));
      }
      const session = await stripe('POST', '/checkout/sessions', {
        mode: 'payment',
        'line_items[0][quantity]': '1',
        'line_items[0][price_data][currency]': 'gbp',
        'line_items[0][price_data][unit_amount]': String(PRICE_PENCE),
        'line_items[0][price_data][product_data][name]': 'ClipHeist for Windows (one-time purchase)',
        success_url: `${BASE_URL}/thanks?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${SITE_URL}/#buy`,
        'metadata[immediate_supply_consent]': new Date().toISOString(),
        // Standard Stripe checkout: you are the seller and your own refund terms apply.
        // (Stripe 'Managed Payments' is on by default for this account; it needs a product tax code and uses Stripe's own refund rules.)
        'managed_payments[enabled]': 'false',
      });
      res.writeHead(303, { Location: session.url });
      return res.end();
    }

    if (req.method === 'POST' && url.pathname === '/api/activate') {
      const json = (status, obj) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
      if (limited(req.socket.remoteAddress)) return json(429, { ok: false, error: 'Too many attempts. Wait a minute and try again.' });
      if (!SECRET || !LICENSE_PRIVATE_KEY) return json(503, { ok: false, error: 'Activation is not available right now.' });
      let body = {};
      try { body = JSON.parse(await readBody(req, 2000)); } catch {}
      const r = activate(body.key, body.device);
      return json(r.ok ? 200 : 403, r);
    }

    // Stripe calls this when a payment completes, so the email goes out even if the buyer closes the tab.
    if (req.method === 'POST' && url.pathname === '/stripe/webhook') {
      const raw = await readBody(req);
      if (!WEBHOOK_SECRET || !SECRET || !verifyStripeSignature(raw, req.headers['stripe-signature'])) return send(res, 400, 'bad signature');
      const event = JSON.parse(raw);
      if (event.type === 'checkout.session.completed' || event.type === 'checkout.session.async_payment_succeeded') {
        await emailLink(event.data.object); // a throw here returns 500 so Stripe retries later
      }
      return send(res, 200, 'ok');
    }

    if (req.method === 'GET' && url.pathname === '/thanks') {
      const id = url.searchParams.get('session_id') || '';
      if (!configured() || !/^cs_[A-Za-z0-9_]+$/.test(id)) return send(res, 400, page('Hmm', `<h1>We couldn't find that order</h1><a class="btn" href="/">Back</a>`));
      const session = await stripe('GET', `/checkout/sessions/${id}`);
      if (session.payment_status !== 'paid') {
        return send(res, 402, page('Payment pending', `<h1>Payment not completed</h1><p>You haven't been charged. You can try again.</p><a class="btn" href="/#buy">Try again</a>`));
      }
      const link = `/download?t=${encodeURIComponent(makeToken(id))}`;
      let sent = false;
      try { sent = await emailLink(session); } catch (e) { console.error('email failed:', e.message); }
      const email = session.customer_details?.email;
      const note = sent
        ? `<p>We've emailed your licence key and download link to <b>${esc(email)}</b>. Check spam if it isn't there in a couple of minutes.</p>`
        : `<p>Save your licence key now. You'll need it when you first open the app.</p>`;
      return send(res, 200, page('Thank you', `<h1>You're in. Download ClipHeist.</h1>
${note}
<p class="key">${licenceFor(id)}</p>
<a class="btn" href="${link}">Download for Windows</a>
<ol class="steps"><li>Run <b>ClipHeist-Setup.exe</b>. Windows may show a "Windows protected your PC" notice for new apps: choose <b>More info → Run anyway</b>.</li><li>Open ClipHeist and enter your licence key. It works on up to ${MAX_DEVICES} PCs.</li><li>Paste a clip link and hit <b>Grab clip</b>.</li><li>Generate captions, style them, check the score, export.</li></ol>`), { 'Cache-Control': 'no-store' });
    }

    if (req.method === 'GET' && url.pathname === '/download') {
      if (!SECRET || !checkToken(url.searchParams.get('t'))) {
        return send(res, 403, page('Link expired', `<h1>This download link isn't valid</h1><p>Links last ${LINK_DAYS} days. Reply to your Stripe receipt email and we'll send a fresh one.</p>`));
      }
      if (!LICENSE_PRIVATE_KEY) console.log('Activation is OFF: LICENSE_PRIVATE_KEY missing from .env');
  if (!emailReady()) console.log('Email is OFF: set RESEND_API_KEY and EMAIL_FROM in .env');
  if (!WEBHOOK_SECRET) console.log('Webhook is OFF: set STRIPE_WEBHOOK_SECRET (emails then only send when the buyer reaches the thank-you page)');
  if (/^https:\/\//.test(INSTALLER_URL)) { res.writeHead(302, { Location: INSTALLER_URL, 'Cache-Control': 'no-store' }); return res.end(); }
      if (!fs.existsSync(INSTALLER)) return send(res, 500, page('Oops', `<h1>The installer is missing on the server</h1><p>Please contact support. Your purchase is safe.</p>`));
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': fs.statSync(INSTALLER).size,
        'Content-Disposition': 'attachment; filename="ClipHeist-Setup.exe"',
        'Cache-Control': 'no-store',
      });
      return fs.createReadStream(INSTALLER).pipe(res);
    }

    if (req.method === 'GET') {
      const rel = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
      const file = path.join(PUBLIC, path.normalize(rel));
      if (file.startsWith(PUBLIC + path.sep) && fs.existsSync(file) && fs.statSync(file).isFile()) {
        res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff' });
        return fs.createReadStream(file).pipe(res);
      }
    }
    send(res, 404, page('Not found', `<h1>Page not found</h1><a class="btn" href="/">Home</a>`));
  } catch (e) {
    console.error(e);
    send(res, 500, page('Error', `<h1>Something went wrong</h1><p>You have not been charged twice. Please try again in a moment.</p><a class="btn" href="/">Home</a>`));
  }
});

// `node server.js issue [note]` prints a fresh licence key (for support or giveaways).
if (process.argv[2] === 'issue') {
  if (SECRET.length < 16) { console.error('Set DOWNLOAD_SECRET in .env first.'); process.exit(1); }
  console.log(licenceFor('manual:' + (process.argv[3] || crypto.randomUUID())));
  process.exit(0);
}

server.listen(PORT, () => {
  console.log(`ClipHeist site on ${BASE_URL}`);
  if (!configured()) console.log('Checkout is OFF: set STRIPE_SECRET_KEY and DOWNLOAD_SECRET in .env');
  if (!emailReady()) console.log('Email is OFF: set RESEND_API_KEY and EMAIL_FROM in .env');
  if (!WEBHOOK_SECRET) console.log('Webhook is OFF: set STRIPE_WEBHOOK_SECRET (emails then only send when the buyer reaches the thank-you page)');
  if (!INSTALLER_URL && !fs.existsSync(INSTALLER)) console.log('Installer not found at', INSTALLER);
});
