require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const crypto     = require('crypto');
const fs         = require('fs');
const path       = require('path');
const nodemailer = require('nodemailer');
const jwt        = require('jsonwebtoken');
const Groq       = require('groq-sdk');
const Stripe     = require('stripe');
const { google } = require('googleapis');

const app = express();
app.use(cors({ origin: '*' }));

// Stripe webhook needs raw body — must come before express.json()
app.use('/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

// ── Services ──────────────────────────────────────────────────────────────────
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const groq   = new Groq({ apiKey: process.env.GROQ_API_KEY });

// ── Users DB (JSON file) ──────────────────────────────────────────────────────
const DB = path.join(__dirname, 'users.json');
const load  = () => { try { return JSON.parse(fs.readFileSync(DB,'utf8')); } catch { return {}; } };
const save  = u  => fs.writeFileSync(DB, JSON.stringify(u, null, 2));

// ── Crypto ────────────────────────────────────────────────────────────────────
const key256 = () => crypto.createHash('sha256').update(process.env.ENCRYPTION_KEY).digest();

function encrypt(text) {
  const iv  = crypto.randomBytes(16);
  const c   = crypto.createCipheriv('aes-256-cbc', key256(), iv);
  return iv.toString('hex') + ':' + c.update(text,'utf8','hex') + c.final('hex');
}
function decrypt(enc) {
  const [iv, data] = enc.split(':');
  const d = crypto.createDecipheriv('aes-256-cbc', key256(), Buffer.from(iv,'hex'));
  return d.update(data,'hex','utf8') + d.final('utf8');
}

// ── Limits ────────────────────────────────────────────────────────────────────
const LIMITS = {
  free: { questions: 10, writerbacks: 5  },
  pro:  { questions: 40, writerbacks: 20 }
};
function today() { return new Date().toISOString().slice(0,10); }
function usage(user) {
  if (!user.usage || user.usage.date !== today())
    user.usage = { date: today(), questions: 0, writerbacks: 0 };
  return user.usage;
}

// ── Mailer ────────────────────────────────────────────────────────────────────
const mailer = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.APP_EMAIL, pass: process.env.APP_PASSWORD }
});

async function sendWelcome(to) {
  await mailer.sendMail({
    from: `"MailZap ⚡" <${process.env.APP_EMAIL}>`,
    to,
    subject: '⚡ Welcome to MailZap!',
    html: `<div style="font-family:'Segoe UI',sans-serif;max-width:540px;margin:auto">
      <div style="background:linear-gradient(135deg,#1557d4,#2d88f5);padding:36px;text-align:center;border-radius:12px 12px 0 0">
        <h1 style="color:#fff;margin:0;font-size:28px">⚡ MailZap</h1>
        <p style="color:rgba(255,255,255,0.8);margin:8px 0 0">AI-powered inbox cleaner</p>
      </div>
      <div style="background:#fff;padding:32px;border:1px solid #e5e7eb;border-top:none">
        <h2 style="color:#111827;margin-top:0">Welcome!</h2>
        <p style="color:#4b5563;line-height:1.7">Your MailZap account is ready. Here's what you get <b>free every day</b>:</p>
        <table style="width:100%;border-collapse:collapse;margin:16px 0">
          <tr><td style="padding:10px 0;border-bottom:1px solid #f3f4f6;font-size:15px">🤖 AI questions</td><td style="text-align:right;font-weight:700;color:#1557d4">10 / day</td></tr>
          <tr><td style="padding:10px 0;font-size:15px">✍️ Writer-Backer replies</td><td style="text-align:right;font-weight:700;color:#059669">5 / day</td></tr>
        </table>
        <p style="color:#6b7280">Upgrade to <b>Pro</b> for $4.99/mo → 40 questions &amp; 20 replies daily.</p>
      </div>
      <div style="background:#f9fafb;padding:14px;text-align:center;color:#9ca3af;font-size:12px;border-radius:0 0 12px 12px;border:1px solid #e5e7eb;border-top:none">
        MailZap · AI Inbox Cleaner
      </div>
    </div>`
  });
}

// ── Auth middleware ───────────────────────────────────────────────────────────
function auth(req, res, next) {
  const tok = req.headers.authorization?.split(' ')[1];
  if (!tok) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(tok, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ── OAuth2 factory ────────────────────────────────────────────────────────────
function oauth2() {
  return new google.auth.OAuth2(
    process.env.GMAIL_CLIENT_ID,
    process.env.GMAIL_CLIENT_SECRET,
    process.env.GMAIL_REDIRECT_URI
  );
}

// ─────────────────────────────────────────────────────────────────────────────
//  ROUTES
// ─────────────────────────────────────────────────────────────────────────────

app.get('/', (_, res) => res.send('MailZap Server ⚡ Running'));

// ── Register ──────────────────────────────────────────────────────────────────
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const users = load();
  if (users[email]) return res.status(400).json({ error: 'Account already exists' });

  users[email] = {
    email, password: encrypt(password), plan: 'free',
    usage: { date: today(), questions: 0, writerbacks: 0 },
    gmailTokens: null, layout: {}, createdAt: new Date().toISOString()
  };
  save(users);

  try { await sendWelcome(email); } catch(e) { console.error('welcome mail failed:', e.message); }

  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, plan: 'free', gmailConnected: false });
});

// ── Login ─────────────────────────────────────────────────────────────────────
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const users = load();
  const user  = users[email];
  if (!user) return res.status(400).json({ error: 'Account not found' });

  let pw;
  try { pw = decrypt(user.password); } catch { return res.status(400).json({ error: 'Decryption error' }); }
  if (pw !== password) return res.status(400).json({ error: 'Wrong password' });

  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, plan: user.plan, layout: user.layout, gmailConnected: !!user.gmailTokens });
});

// ── Usage ─────────────────────────────────────────────────────────────────────
app.get('/usage', auth, (req, res) => {
  const users = load();
  const user  = users[req.user.email];
  if (!user) return res.status(404).json({ error: 'User not found' });
  const u = usage(user);
  save(users);
  res.json({
    plan: user.plan,
    questions:   { used: u.questions,   limit: LIMITS[user.plan].questions   },
    writerbacks: { used: u.writerbacks, limit: LIMITS[user.plan].writerbacks },
    gmailConnected: !!user.gmailTokens
  });
});

// ── AI Ask ────────────────────────────────────────────────────────────────────
app.post('/ask', auth, async (req, res) => {
  const users = load();
  const user  = users[req.user.email];
  if (!user) return res.status(404).json({ error: 'User not found' });
  const u = usage(user);
  if (u.questions >= LIMITS[user.plan].questions)
    return res.status(403).json({ error: 'limit_reached', plan: user.plan });

  try {
    const r = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { role: 'system', content: `You are MailZap, a concise AI email assistant.
Help users clean inboxes, spot spam, organise emails, and write replies.
Rules:
- Be brief and direct.
- Use bullet points for lists.
- Never use markdown headers or excessive asterisks.
- Strip any unnecessary preamble — get straight to the answer.` },
        { role: 'user', content: req.body.question }
      ],
      max_tokens: 600, temperature: 0.55
    });
    u.questions++;
    save(users);
    res.json({ answer: r.choices[0].message.content.replace(/\*\*/g,'').trim(), remaining: LIMITS[user.plan].questions - u.questions });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Writer-Backer ─────────────────────────────────────────────────────────────
app.post('/writeback', auth, async (req, res) => {
  const users = load();
  const user  = users[req.user.email];
  if (!user) return res.status(404).json({ error: 'User not found' });
  const u = usage(user);
  if (u.writerbacks >= LIMITS[user.plan].writerbacks)
    return res.status(403).json({ error: 'limit_reached', plan: user.plan });

  try {
    const r = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { role: 'system', content: `Write a professional, friendly email reply.
Output ONLY the reply body text.
No subject line. No "Here is a reply:". No markdown. Just the message.
Match the tone of the original — casual if casual, formal if formal.` },
        { role: 'user', content: `Write a reply to:\n\n${req.body.emailContent}` }
      ],
      max_tokens: 400, temperature: 0.7
    });
    u.writerbacks++;
    save(users);
    res.json({ reply: r.choices[0].message.content.replace(/\*\*/g,'').trim(), remaining: LIMITS[user.plan].writerbacks - u.writerbacks });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Categorize ────────────────────────────────────────────────────────────────
app.post('/categorize', auth, async (req, res) => {
  const { emails } = req.body;
  if (!emails?.length) return res.status(400).json({ error: 'No emails provided' });

  try {
    const r = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { role: 'system', content: `Categorize each email. Categories: Important, Work, Promotions, Social, Updates, Spam.
Return ONLY valid JSON array — no markdown, no extra text:
[{"id":"...","category":"Important","isSpam":false}]` },
        { role: 'user', content: JSON.stringify(emails.slice(0, 30)) }
      ],
      max_tokens: 1000, temperature: 0.2
    });
    let raw = r.choices[0].message.content.trim()
      .replace(/^```json\s*/i,'').replace(/^```\s*/i,'').replace(/```\s*$/i,'');
    let categories;
    try { categories = JSON.parse(raw); } catch { categories = []; }
    res.json({ categories });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Gmail OAuth ───────────────────────────────────────────────────────────────
app.get('/auth-url', auth, (req, res) => {
  const oa = oauth2();
  const url = oa.generateAuthUrl({
    access_type: 'offline', prompt: 'consent',
    scope: ['https://www.googleapis.com/auth/gmail.readonly','https://www.googleapis.com/auth/gmail.modify'],
    state: req.user.email
  });
  res.json({ url });
});

app.get('/oauth2callback', async (req, res) => {
  const { code, state: email } = req.query;
  if (!code || !email) return res.status(400).send('Missing parameters');
  try {
    const oa = oauth2();
    const { tokens } = await oa.getToken(code);
    const users = load();
    if (users[email]) { users[email].gmailTokens = tokens; save(users); }
    res.send(`<!DOCTYPE html><html><head><title>MailZap — Connected</title>
    <style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;background:#f0f9ff}
    .card{background:#fff;border-radius:16px;padding:40px;text-align:center;box-shadow:0 8px 30px rgba(0,0,0,0.1);max-width:340px}
    .icon{width:56px;height:56px;background:#dcfce7;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 16px;font-size:24px}
    h2{color:#111827;font-size:20px;margin-bottom:8px}p{color:#6b7280;font-size:14px}</style></head>
    <body><div class="card"><div class="icon">✓</div><h2>Gmail Connected!</h2><p>You can close this tab and return to MailZap.</p></div>
    <script>setTimeout(()=>window.close(),2500)</script></body></html>`);
  } catch(e) { res.status(500).send('OAuth error: ' + e.message); }
});

// ── Read inbox ────────────────────────────────────────────────────────────────
app.get('/inbox', auth, async (req, res) => {
  const users = load();
  const user  = users[req.user.email];
  if (!user?.gmailTokens) return res.status(400).json({ error: 'Gmail not connected' });

  try {
    const oa = oauth2();
    oa.setCredentials(user.gmailTokens);
    oa.on('tokens', t => { user.gmailTokens = {...user.gmailTokens,...t}; save(load()); });

    const gmail = google.gmail({ version: 'v1', auth: oa });
    const list  = await gmail.users.messages.list({ userId: 'me', maxResults: 25, labelIds: ['INBOX'] });
    const msgs  = (list.data.messages || []).slice(0, 20);

    const emails = await Promise.all(msgs.map(async m => {
      const msg = await gmail.users.messages.get({
        userId: 'me', id: m.id, format: 'metadata',
        metadataHeaders: ['Subject','From','Date']
      });
      const H = k => msg.data.payload.headers.find(h => h.name === k)?.value || '';
      return { id: m.id, subject: H('Subject')||'(no subject)', sender: H('From'), date: H('Date'), snippet: msg.data.snippet||'', labelIds: msg.data.labelIds||[] };
    }));

    res.json({ emails });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Trash email ───────────────────────────────────────────────────────────────
app.post('/trash', auth, async (req, res) => {
  const users = load();
  const user  = users[req.user.email];
  if (!user?.gmailTokens) return res.status(400).json({ error: 'Gmail not connected' });
  try {
    const oa = oauth2();
    oa.setCredentials(user.gmailTokens);
    await google.gmail({ version:'v1', auth: oa }).users.messages.trash({ userId:'me', id: req.body.messageId });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Mark as read ──────────────────────────────────────────────────────────────
app.post('/mark-read', auth, async (req, res) => {
  const users = load();
  const user  = users[req.user.email];
  if (!user?.gmailTokens) return res.status(400).json({ error: 'Gmail not connected' });
  try {
    const oa = oauth2();
    oa.setCredentials(user.gmailTokens);
    await google.gmail({ version:'v1', auth: oa }).users.messages.modify({
      userId:'me', id: req.body.messageId,
      requestBody: { removeLabelIds: ['UNREAD'] }
    });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Stripe checkout ───────────────────────────────────────────────────────────
app.post('/create-checkout', auth, async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription', payment_method_types: ['card'],
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      customer_email: req.user.email,
      success_url: process.env.STRIPE_SUCCESS_URL + '?email=' + encodeURIComponent(req.user.email),
      cancel_url:  process.env.STRIPE_CANCEL_URL
    });
    res.json({ url: session.url });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Stripe webhook ────────────────────────────────────────────────────────────
app.post('/webhook', (req, res) => {
  const sig = req.headers['stripe-signature'];
  if (!sig || !process.env.STRIPE_WEBHOOK_SECRET) return res.sendStatus(400);
  let event;
  try { event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET); }
  catch(e) { return res.status(400).send('Webhook error: ' + e.message); }

  if (event.type === 'checkout.session.completed') {
    const email = event.data.object.customer_email;
    const users = load();
    if (users[email]) { users[email].plan = 'pro'; save(users); }
  }
  res.json({ received: true });
});

// ── Stripe success / cancel pages ─────────────────────────────────────────────
const PAGE = (icon, title, body, color) => `<!DOCTYPE html><html><head><title>MailZap</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;background:#f0f9ff}
.card{background:#fff;border-radius:20px;padding:48px 40px;text-align:center;box-shadow:0 12px 40px rgba(0,0,0,0.1);max-width:400px;width:90%}
.ic{font-size:48px;margin-bottom:20px}h1{font-size:22px;color:${color};margin-bottom:10px}p{color:#6b7280;font-size:14px;line-height:1.6}</style></head>
<body><div class="card"><div class="ic">${icon}</div><h1>${title}</h1><p>${body}</p></div></body></html>`;

app.get('/success', (req, res) => {
  const email = decodeURIComponent(req.query.email || '');
  if (email) { const u = load(); if (u[email]) { u[email].plan='pro'; save(u); } }
  res.send(PAGE('🎉', 'Welcome to Pro!', 'Your MailZap Pro subscription is active.<br><br>You now get <b>40 AI questions</b> and <b>20 Writer-Backer replies</b> daily.<br><br>Close this tab and reopen MailZap.', '#1557d4'));
});

app.get('/cancel', (_, res) =>
  res.send(PAGE('❌', 'Payment Cancelled', 'No charge was made. You can upgrade anytime from the MailZap extension.', '#6b7280'))
);

// ── Confirm pro fallback ──────────────────────────────────────────────────────
app.post('/confirm-pro', auth, (req, res) => {
  const users = load();
  if (users[req.user.email]) { users[req.user.email].plan = 'pro'; save(users); }
  res.json({ plan: 'pro' });
});

// ── Save layout ───────────────────────────────────────────────────────────────
app.post('/save-layout', auth, (req, res) => {
  const users = load();
  if (users[req.user.email]) { users[req.user.email].layout = req.body.layout; save(users); }
  res.json({ ok: true });
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MailZap server on port ${PORT} ⚡`));
