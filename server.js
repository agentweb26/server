require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const Groq = require('groq-sdk');
const Stripe = require('stripe');

const app = express();
app.use(cors());
app.use(express.json());

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

const USERS_FILE = path.join(__dirname, 'users.json');

// ---------- Helpers ----------
function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch {
    return {};
  }
}
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// 256-bit (32-byte -> 64 hex char) encryption
function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const key = crypto.createHash('sha256').update(process.env.ENCRYPTION_KEY).digest();
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function todayKey() {
  return new Date().toISOString().slice(0, 10);
}

function getUserUsage(user) {
  if (!user.usage || user.usage.date !== todayKey()) {
    user.usage = { date: todayKey(), questions: 0, writerbacks: 0 };
  }
  return user.usage;
}

// Limits
const LIMITS = {
  free: { questions: 10, writerbacks: 5 },
  pro: { questions: 40, writerbacks: 20 }
};

// Email sender
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.APP_EMAIL,
    pass: process.env.APP_PASSWORD
  }
});

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ---------- Register ----------
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

  const users = loadUsers();
  if (users[email]) return res.status(400).json({ error: 'User already exists' });

  users[email] = {
    email,
    password: encrypt(password),
    plan: 'free',
    usage: { date: todayKey(), questions: 0, writerbacks: 0 },
    gmailConnected: false,
    layout: {},
    createdAt: new Date().toISOString()
  };
  saveUsers(users);

  // Welcome email
  try {
    await transporter.sendMail({
      from: `"MailZap" <${process.env.APP_EMAIL}>`,
      to: email,
      subject: 'Welcome to MailZap! ⚡',
      html: `<h2>Welcome to MailZap!</h2>
             <p>Your account is ready. Clean your inbox with AI power.</p>
             <p>You get <b>10 free AI questions</b> and <b>5 free writer-backs</b> daily.</p>
             <p>Upgrade to Pro for \$4.99/mo for more!</p>`
    });
  } catch (e) {
    console.error('Email error:', e.message);
  }

  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, plan: 'free' });
});

// ---------- Login ----------
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const users = loadUsers();
  const user = users[email];
  if (!user) return res.status(400).json({ error: 'User not found' });

  // Decrypt-compare
  const [ivHex, enc] = user.password.split(':');
  const key = crypto.createHash('sha256').update(process.env.ENCRYPTION_KEY).digest();
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(ivHex, 'hex'));
  let decrypted = decipher.update(enc, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  if (decrypted !== password) return res.status(400).json({ error: 'Wrong password' });

  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, plan: user.plan, layout: user.layout, gmailConnected: user.gmailConnected });
});

// ---------- AI Question ----------
app.post('/ask', authMiddleware, async (req, res) => {
  const users = loadUsers();
  const user = users[req.user.email];
  const usage = getUserUsage(user);
  const limit = LIMITS[user.plan].questions;

  if (usage.questions >= limit) {
    return res.status(403).json({ error: 'limit_reached', upgrade: user.plan === 'free' });
  }

  try {
    const completion = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { role: 'system', content: 'You are MailZap, an assistant that helps clean inboxes, organize emails, and identify spam.' },
        { role: 'user', content: req.body.question }
      ]
    });
    usage.questions++;
    saveUsers(users);
    res.json({
      answer: completion.choices[0].message.content,
      remaining: limit - usage.questions
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Writer-Backer ----------
app.post('/writeback', authMiddleware, async (req, res) => {
  const users = loadUsers();
  const user = users[req.user.email];
  const usage = getUserUsage(user);
  const limit = LIMITS[user.plan].writerbacks;

  if (usage.writerbacks >= limit) {
    return res.status(403).json({ error: 'limit_reached', upgrade: user.plan === 'free' });
  }

  try {
    const completion = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { role: 'system', content: 'You write professional, friendly email replies. Output only the reply body.' },
        { role: 'user', content: `Write a reply to this email:\n\n${req.body.emailContent}` }
      ]
    });
    usage.writerbacks++;
    saveUsers(users);
    res.json({
      reply: completion.choices[0].message.content,
      remaining: limit - usage.writerbacks
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Categorize Inbox ----------
app.post('/categorize', authMiddleware, async (req, res) => {
  try {
    const completion = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { role: 'system', content: 'Categorize emails into: Important, Promotions, Social, Spam, Updates. Return JSON array [{subject, category, isSpam}].' },
        { role: 'user', content: JSON.stringify(req.body.emails) }
      ]
    });
    res.json({ result: completion.choices[0].message.content });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Stripe Checkout ----------
app.post('/create-checkout', authMiddleware, async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      customer_email: req.user.email,
      success_url: process.env.STRIPE_SUCCESS_URL + '?email=' + req.user.email,
      cancel_url: process.env.STRIPE_CANCEL_URL
    });
    res.json({ url: session.url });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Confirm Pro (call from success page) ----------
app.post('/confirm-pro', authMiddleware, (req, res) => {
  const users = loadUsers();
  users[req.user.email].plan = 'pro';
  saveUsers(users);
  res.json({ plan: 'pro' });
});

// ---------- Save Layout / Gmail Connect ----------
app.post('/save-layout', authMiddleware, (req, res) => {
  const users = loadUsers();
  users[req.user.email].layout = req.body.layout;
  saveUsers(users);
  res.json({ ok: true });
});

app.post('/connect-gmail', authMiddleware, (req, res) => {
  const users = loadUsers();
  users[req.user.email].gmailConnected = true;
  saveUsers(users);
  res.json({ ok: true });
});

// ---------- Usage ----------
app.get('/usage', authMiddleware, (req, res) => {
  const users = loadUsers();
  const user = users[req.user.email];
  const usage = getUserUsage(user);
  saveUsers(users);
  res.json({
    plan: user.plan,
    questions: { used: usage.questions, limit: LIMITS[user.plan].questions },
    writerbacks: { used: usage.writerbacks, limit: LIMITS[user.plan].writerbacks }
  });
});

app.get('/', (req, res) => res.send('MailZap Server Running ⚡'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MailZap on port ${PORT}`));
