// MailZap Cloud Server — server.js
// Deploy on Render.com (Free tier works fine)
require('dotenv').config();

const express    = require('express');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const fs         = require('fs');
const path       = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ────────────────────────────────────────────────
app.use(cors({
  origin: ['chrome-extension://*', '*'],
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.use(express.json());

// ── JSON Database ─────────────────────────────────────────────
// Render persists the filesystem between deploys on paid plans.
// On the free plan, use /tmp or rely on environment variables for persistence.
const DB_PATH = process.env.DB_PATH || path.join('/tmp', 'mailzap_users.json');

function readDB() {
  try {
    if (!fs.existsSync(DB_PATH)) return { users: {} };
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch {
    return { users: {} };
  }
}

function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf8');
}

function getUser(email) {
  const db = readDB();
  return db.users[email.toLowerCase()] || null;
}

function saveUser(email, data) {
  const db = readDB();
  db.users[email.toLowerCase()] = data;
  writeDB(db);
}

// ── Email (App Password) ──────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.MAIL_FROM,
    pass: process.env.MAIL_APP_PASSWORD   // Gmail App Password, NOT your login password
  }
});

async function sendVerificationEmail(toEmail, token) {
  const verifyUrl = `${process.env.BASE_URL}/auth/verify?token=${token}`;
  const html = `
<!DOCTYPE html>
<html>
<body style="font-family:'Google Sans',Arial,sans-serif;background:#12121e;color:#e8eaed;padding:32px;margin:0;">
  <div style="max-width:480px;margin:0 auto;background:#1a1a2e;border-radius:16px;padding:32px;border:1px solid rgba(255,255,255,.1);">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:24px;">
      <div style="width:40px;height:40px;border-radius:10px;background:linear-gradient(135deg,#00b4d8,#1a73e8,#9334e6);display:flex;align-items:center;justify-content:center;font-size:20px;">⚡</div>
      <span style="font-size:22px;font-weight:700;letter-spacing:-.02em;">Mail<span style="color:#1a73e8;">Zap</span></span>
    </div>
    <h2 style="font-size:20px;font-weight:700;margin-bottom:12px;">Verify your email address</h2>
    <p style="color:#9aa0a6;line-height:1.6;margin-bottom:24px;">Thanks for signing up! Click the button below to verify your email and activate your MailZap account.</p>
    <a href="${verifyUrl}" style="display:inline-block;background:#1a73e8;color:#fff;padding:12px 28px;border-radius:22px;text-decoration:none;font-weight:600;font-size:14px;margin-bottom:24px;">Verify Email Address</a>
    <p style="color:#5f6368;font-size:12px;">Or paste this link in your browser:<br><span style="color:#1a73e8;">${verifyUrl}</span></p>
    <hr style="border:none;border-top:1px solid rgba(255,255,255,.08);margin:24px 0;">
    <p style="color:#5f6368;font-size:12px;">This link expires in 24 hours. If you didn't sign up for MailZap, ignore this email.</p>
  </div>
</body>
</html>`;
  await transporter.sendMail({
    from: `"MailZap" <${process.env.MAIL_FROM}>`,
    to: toEmail,
    subject: '⚡ Verify your MailZap account',
    html
  });
}

// ── JWT helpers ───────────────────────────────────────────────
function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '90d' });
}
function verifyToken(token) {
  return jwt.verify(token, process.env.JWT_SECRET);
}

// Auth middleware
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = verifyToken(auth.slice(7));
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── Routes ────────────────────────────────────────────────────

// Health check
app.get('/', (req, res) => res.json({ status: 'ok', app: 'MailZap Server v1.0' }));

// REGISTER
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const emailLower = email.toLowerCase().trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailLower)) return res.status(400).json({ error: 'Invalid email address' });
  if (getUser(emailLower)) return res.status(409).json({ error: 'An account with this email already exists' });
  try {
    // Hash password with bcrypt (saltRounds=12 → ~256-char bcrypt hash)
    const passwordHash = await bcrypt.hash(password, 12);
    const verifyToken = uuidv4() + uuidv4(); // long random token
    const user = {
      id: uuidv4(),
      email: emailLower,
      passwordHash,
      verified: false,
      verifyToken,
      verifyTokenExpiry: Date.now() + 24 * 60 * 60 * 1000,
      isPro: false,
      stripeCustomerId: null,
      createdAt: new Date().toISOString()
    };
    saveUser(emailLower, user);
    // Send verification email
    await sendVerificationEmail(emailLower, verifyToken);
    res.json({ success: true, message: 'Verification email sent. Check your inbox!' });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// VERIFY EMAIL
app.get('/auth/verify', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send(htmlPage('Error', 'Invalid verification link.'));
  const db = readDB();
  const user = Object.values(db.users).find(u => u.verifyToken === token);
  if (!user) return res.status(404).send(htmlPage('Error', 'Verification link not found or already used.'));
  if (Date.now() > user.verifyTokenExpiry) return res.status(410).send(htmlPage('Expired', 'This link has expired. Please register again.'));
  user.verified = true;
  user.verifyToken = null;
  user.verifyTokenExpiry = null;
  saveUser(user.email, user);
  res.send(htmlPage('Email Verified! ✓', 'Your MailZap account is now active. You can close this tab and sign in from the extension.'));
});

// LOGIN
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const emailLower = email.toLowerCase().trim();
  const user = getUser(emailLower);
  if (!user) return res.status(401).json({ error: 'No account found with this email' });
  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.status(401).json({ error: 'Incorrect password' });
  if (!user.verified) return res.status(403).json({ error: 'Please verify your email first. Check your inbox.' });
  const token = signToken({ sub: user.id, email: user.email });
  res.json({ success: true, token, isPro: user.isPro, email: user.email });
});

// GET ME (check token + pro status)
app.get('/auth/me', requireAuth, (req, res) => {
  const user = getUser(req.user.email);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ email: user.email, isPro: user.isPro, createdAt: user.createdAt });
});

// STRIPE CHECKOUT — creates a Stripe Checkout session
app.post('/stripe/checkout', requireAuth, async (req, res) => {
  const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      customer_email: req.user.email,
      success_url: process.env.STRIPE_SUCCESS_URL + '?session_id={CHECKOUT_SESSION_ID}',
      cancel_url: process.env.STRIPE_CANCEL_URL,
      metadata: { email: req.user.email }
    });
    res.json({ url: session.url });
  } catch (e) {
    console.error('Stripe checkout error:', e);
    res.status(500).json({ error: 'Could not create checkout session' });
  }
});

// Success / Cancel landing pages
app.get('/success', (req, res) => res.send(htmlPage('Payment Successful! ⭐', 'You are now a MailZap Pro member! Close this tab and reopen the extension — your Pro status will sync automatically.')));
app.get('/cancel',  (req, res) => res.send(htmlPage('Payment Cancelled', 'No charge was made. You can upgrade to Pro any time from the MailZap extension.')));

// STRIPE WEBHOOK — sets user.isPro = true on successful subscription
app.post('/stripe/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    console.error('Stripe webhook error:', e.message);
    return res.status(400).json({ error: 'Webhook signature failed' });
  }
  switch (event.type) {
    case 'checkout.session.completed':
    case 'customer.subscription.created':
    case 'invoice.paid': {
      const email = event.data.object.customer_email || event.data.object.customer_details?.email;
      if (email) {
        const user = getUser(email.toLowerCase());
        if (user) { user.isPro = true; saveUser(user.email, user); }
      }
      break;
    }
    case 'customer.subscription.deleted':
    case 'invoice.payment_failed': {
      const email = event.data.object.customer_email;
      if (email) {
        const user = getUser(email.toLowerCase());
        if (user) { user.isPro = false; saveUser(user.email, user); }
      }
      break;
    }
  }
  res.json({ received: true });
});

// ── Simple HTML page helper ───────────────────────────────────
function htmlPage(title, message) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>MailZap — ${title}</title>
  <style>body{font-family:'Google Sans',Arial,sans-serif;background:#12121e;color:#e8eaed;
  display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}
  .box{background:#1a1a2e;border:1px solid rgba(255,255,255,.1);border-radius:20px;
  padding:48px;text-align:center;max-width:400px;}
  h1{font-size:22px;margin-bottom:16px;} p{color:#9aa0a6;line-height:1.6;}
  .icon{font-size:48px;margin-bottom:16px;}</style></head>
  <body><div class="box"><div class="icon">${title.includes('✓')?'✅':'⚡'}</div>
  <h1>${title}</h1><p>${message}</p>
  <p style="margin-top:24px;font-size:13px;color:#5f6368;">MailZap v5.0</p></div></body></html>`;
}

// ── Start ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ MailZap server running on port ${PORT}`);
  console.log(`📦 DB path: ${DB_PATH}`);
});
