// Grain Desk access gate (Cloudflare Worker)
//
// Routes
//   POST /api/request        {name}          -> {id}           visitor asks for access
//   GET  /api/status?id=...                  -> {status, url?} visitor's page polls this
//   POST /tg                 Telegram webhook (Approve / Reject / Revoke buttons)
//   GET  /setup?key=...      one-time: registers the Telegram webhook
//   GET  /enter?t=...        approved link: sets a cookie and opens Grain Desk
//   everything else          Grain Desk files, only with a valid cookie
//
// Bindings (wrangler.toml / dashboard)
//   ASSETS   static assets (public/)          ACCESS  KV namespace
//   secrets: TG_TOKEN, TG_CHAT_ID, SIGNING_KEY, WEBHOOK_SECRET
//   vars:    ALLOWED_ORIGINS (comma separated), ACCESS_DAYS, PORTFOLIO_URL

const enc = new TextEncoder();

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const p = url.pathname;
    try {
      if (p.startsWith('/api/')) {
        if (req.method === 'OPTIONS') return cors(req, env, new Response(null, { status: 204 }));
        if (p === '/api/request' && req.method === 'POST') return cors(req, env, await requestAccess(req, env));
        if (p === '/api/status' && req.method === 'GET') return cors(req, env, await status(url, env));
        return cors(req, env, json({ error: 'not_found' }, 404));
      }
      if (p === '/tg' && req.method === 'POST') return await telegram(req, env);
      if (p === '/setup') return await setup(url, env);
      if (p === '/enter') return await enter(url, env);
      return await serveApp(req, env);
    } catch (e) {
      return json({ error: 'server_error' }, 500);
    }
  },
};

/* ---------- visitor side ---------- */

async function requestAccess(req, env) {
  let body;
  try { body = await req.json(); } catch { return json({ error: 'bad_request' }, 400); }
  const name = String(body.name || '').replace(/\s+/g, ' ').trim().slice(0, 80);
  if (name.length < 3 || !/\s/.test(name)) return json({ error: 'name_required' }, 400);
  if (body.website) return json({ id: rid() }); // honeypot field: bots fill it, people do not

  // at most 3 requests per hour from one IP
  const ip = req.headers.get('CF-Connecting-IP') || 'x';
  const rk = 'rl:' + ip + ':' + Math.floor(Date.now() / 3600e3);
  const n = parseInt((await env.ACCESS.get(rk)) || '0', 10);
  if (n >= 3) return json({ error: 'too_many' }, 429);
  await env.ACCESS.put(rk, String(n + 1), { expirationTtl: 3700 });

  const id = rid();
  const rec = {
    name, status: 'pending', created: Date.now(),
    country: req.cf?.country || '', city: req.cf?.city || '',
  };
  const where = [rec.city, rec.country].filter(Boolean).join(', ');
  const msg = await tg(env, 'sendMessage', {
    chat_id: env.TG_CHAT_ID,
    parse_mode: 'HTML',
    text: `🔑 <b>Grain Desk erişim isteği</b>\n\n👤 ${esc(name)}${where ? `\n📍 ${esc(where)}` : ''}`,
    reply_markup: { inline_keyboard: [[
      { text: '✅ Onayla', callback_data: 'a:' + id },
      { text: '❌ Reddet', callback_data: 'r:' + id },
    ]] },
  });
  if (!msg.ok) return json({ error: 'notify_failed' }, 502);
  await env.ACCESS.put('req:' + id, JSON.stringify(rec), { expirationTtl: 60 * 86400 });
  return json({ id });
}

async function status(url, env) {
  const id = url.searchParams.get('id') || '';
  if (!/^[A-Za-z0-9_-]{20,40}$/.test(id)) return json({ error: 'bad_id' }, 400);
  const rec = await getRec(env, id);
  if (!rec) return json({ status: 'unknown' });
  if (rec.status === 'approved') {
    if (Date.now() > rec.exp) return json({ status: 'expired' });
    const t = await sign(env, id, rec.exp);
    return json({ status: 'approved', url: new URL('/enter?t=' + t, url).href, exp: rec.exp });
  }
  return json({ status: rec.status }); // pending | rejected | revoked
}

async function enter(url, env) {
  const t = url.searchParams.get('t') || '';
  const ok = await checkToken(env, t);
  if (!ok) return gatePage(env, 'Bu bağlantının süresi dolmuş ya da erişim kapatılmış.', 'This link has expired or access was withdrawn.', 403);
  const maxAge = Math.max(60, Math.floor((ok.exp - Date.now()) / 1000));
  return new Response(null, {
    status: 302,
    headers: {
      Location: '/',
      'Set-Cookie': `gd=${t}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`,
      'Cache-Control': 'no-store',
    },
  });
}

async function serveApp(req, env) {
  const t = (req.headers.get('Cookie') || '').match(/(?:^|;\s*)gd=([^;]+)/)?.[1] || '';
  if (!(await checkToken(env, t))) {
    return gatePage(env, 'Grain Desk şu an davetle açık. Erişim için portfolyodan istek gönderebilirsiniz.', 'Grain Desk is open by invitation. You can request access from the portfolio.', 401);
  }
  const res = await env.ASSETS.fetch(req);
  const h = new Headers(res.headers);
  h.set('Cache-Control', 'private, no-store');
  h.set('X-Robots-Tag', 'noindex');
  return new Response(res.body, { status: res.status, headers: h });
}

/* ---------- Telegram side ---------- */

async function telegram(req, env) {
  if (req.headers.get('X-Telegram-Bot-Api-Secret-Token') !== env.WEBHOOK_SECRET) return new Response('no', { status: 403 });
  const u = await req.json();

  // "/start" tells the sender their chat id, which goes into TG_CHAT_ID once
  if (u.message?.text?.startsWith('/start')) {
    await tg(env, 'sendMessage', { chat_id: u.message.chat.id, text: `Chat ID: ${u.message.chat.id}` });
    return new Response('ok');
  }

  const cq = u.callback_query;
  if (!cq) return new Response('ok');
  if (String(cq.from.id) !== String(env.TG_CHAT_ID)) {
    await tg(env, 'answerCallbackQuery', { callback_query_id: cq.id, text: 'Yetkin yok.' });
    return new Response('ok');
  }
  const [act, id] = String(cq.data || '').split(':');
  const rec = await getRec(env, id);
  if (!rec) {
    await tg(env, 'answerCallbackQuery', { callback_query_id: cq.id, text: 'İstek bulunamadı.' });
    return new Response('ok');
  }

  const days = parseInt(env.ACCESS_DAYS || '7', 10);
  let label, keyboard = [];
  if (act === 'a') {
    rec.status = 'approved';
    rec.exp = Date.now() + days * 86400e3;
    label = `✅ Onaylandı · ${days} gün, ${fmtDate(rec.exp)} tarihine kadar`;
    keyboard = [[{ text: '🚫 Erişimi kapat', callback_data: 'x:' + id }]];
  } else if (act === 'r') {
    rec.status = 'rejected';
    label = '❌ Reddedildi';
  } else if (act === 'x') {
    rec.status = 'revoked';
    label = '🚫 Erişim kapatıldı';
  } else {
    return new Response('ok');
  }
  rec.decided = Date.now();
  await env.ACCESS.put('req:' + id, JSON.stringify(rec), { expirationTtl: 60 * 86400 });

  const where = [rec.city, rec.country].filter(Boolean).join(', ');
  await tg(env, 'editMessageText', {
    chat_id: cq.message.chat.id,
    message_id: cq.message.message_id,
    parse_mode: 'HTML',
    text: `🔑 <b>Grain Desk erişim isteği</b>\n\n👤 ${esc(rec.name)}${where ? `\n📍 ${esc(where)}` : ''}\n\n${label}`,
    reply_markup: { inline_keyboard: keyboard },
  });
  await tg(env, 'answerCallbackQuery', { callback_query_id: cq.id, text: label });
  return new Response('ok');
}

async function setup(url, env) {
  if (url.searchParams.get('key') !== env.WEBHOOK_SECRET) return new Response('no', { status: 403 });
  const r = await tg(env, 'setWebhook', {
    url: new URL('/tg', url).href,
    secret_token: env.WEBHOOK_SECRET,
    allowed_updates: ['message', 'callback_query'],
  });
  return json(r);
}

/* ---------- helpers ---------- */

async function getRec(env, id) {
  if (!id) return null;
  const s = await env.ACCESS.get('req:' + id);
  return s ? JSON.parse(s) : null;
}

// token = id.exp.signature ; also re-checked against KV so "Erişimi kapat" works at once
async function checkToken(env, t) {
  const [id, exp, sig] = String(t).split('.');
  if (!id || !exp || !sig) return null;
  if (Date.now() > +exp) return null;
  if ((await hmac(env, id + '.' + exp)) !== sig) return null;
  const rec = await getRec(env, id);
  if (!rec || rec.status !== 'approved' || rec.exp !== +exp) return null;
  return rec;
}
async function sign(env, id, exp) { return `${id}.${exp}.${await hmac(env, id + '.' + exp)}`; }
async function hmac(env, data) {
  const key = await crypto.subtle.importKey('raw', enc.encode(env.SIGNING_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64u(new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(data))));
}
function rid() { return b64u(crypto.getRandomValues(new Uint8Array(18))); }
function b64u(a) { return btoa(String.fromCharCode(...a)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function esc(s) { return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
function fmtDate(ms) { return new Date(ms).toLocaleDateString('tr-TR', { day: 'numeric', month: 'long', timeZone: 'Europe/Istanbul' }); }

async function tg(env, method, payload) {
  const r = await fetch(`${env.TG_API || 'https://api.telegram.org'}/bot${env.TG_TOKEN}/${method}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  return r.json().catch(() => ({ ok: false }));
}

function json(o, status = 200) {
  return new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
}

function cors(req, env, res) {
  const origin = req.headers.get('Origin') || '';
  const allowed = String(env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const h = new Headers(res.headers);
  if (allowed.includes(origin)) {
    h.set('Access-Control-Allow-Origin', origin);
    h.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    h.set('Access-Control-Allow-Headers', 'Content-Type');
    h.set('Vary', 'Origin');
  }
  return new Response(res.body, { status: res.status, headers: h });
}

function gatePage(env, tr, en, status) {
  const back = env.PORTFOLIO_URL || 'https://zenginemrah.github.io/resume/';
  const html = `<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Grain Desk</title>
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0E1B2C;color:#F4EFE6;font:300 16px/1.6 system-ui,-apple-system,'Segoe UI',sans-serif;padding:24px;box-sizing:border-box}
main{max-width:460px;border:1px solid #283D59;border-left:2px solid #C9A45C;padding:32px}h1{font:500 28px Georgia,serif;color:#C9A45C;margin:0 0 14px}p{margin:0 0 10px;color:#D9DFE7}p.en{color:#9AA9BC;font-size:14px}
a{display:inline-block;margin-top:16px;padding:12px 22px;border:1px solid #C9A45C;color:#C9A45C;text-decoration:none;font-weight:500;letter-spacing:.04em}a:hover{background:#C9A45C;color:#0E1B2C}</style></head>
<body><main><h1>Grain Desk</h1><p>${tr}</p><p class="en">${en}</p><a href="${back}#ai">Portfolyo · Portfolio</a></main></body></html>`;
  return new Response(html, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
}
