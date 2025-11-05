// Full Backend: Node.js / Express / MongoDB
// Features: Auth (with email verification), Profile, Uploads, VIP/Payments, Admin, WebSocket Chat
// Dependencies: npm i express mongoose bcryptjs jsonwebtoken multer ws nodemailer resend crypto

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const WebSocket = require('ws');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const { Resend } = require('resend');
const cors = require('cors'); // npm i cors

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const resend = new Resend('re_123456789'); // Replace with your Resend API key
const JWT_SECRET = 'your_jwt_secret'; // Replace with secure secret
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads')); // Serve uploads

// MongoDB
mongoose.connect('mongodb://localhost:27017/mealone', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

// Schemas
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  id: { type: String, unique: true },
  isAdmin: { type: Boolean, default: false },
  verified: { type: Boolean, default: false },
  verificationToken: String,
  uploads: [{ src: String, name: String }],
});

const chatSchema = new mongoose.Schema({
  user: String,
  text: String,
  createdAt: { type: Date, default: Date.now },
});

const vipSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  item: String,
  unlockedAt: { type: Date, default: Date.now },
});

const paymentSchema = new mongoose.Schema({
  user: String,
  item: String,
  code: String,
  message: String,
  createdAt: { type: Date, default: Date.now },
});

const giftCardSchema = new mongoose.Schema({
  userEmail: String,
  items: [{ item: String, price: Number, galleryIndex: Number }],
  code: String,
  imageUrl: String,
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Chat = mongoose.model('Chat', chatSchema);
const Vip = mongoose.model('Vip', vipSchema);
const Payment = mongoose.model('Payment', paymentSchema);
const GiftCard = mongoose.model('GiftCard', giftCardSchema);

// Auth Middleware
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(decoded.id);
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    if (!req.user.verified && !req.path.includes('/verify') && !req.path.includes('/resend')) {
      return res.status(403).json({ error: 'Verify your email first' });
    }
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const adminMiddleware = (req, res, next) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
  next();
};

// Send Verification Email
async function sendVerificationEmail(email, token) {
  await resend.emails.send({
    from: 'MeAlone <verify@mealone.com>',
    to: email,
    subject: 'Verify Your MeAlone Account',
    html: `
      <h2>Welcome to MeAlone</h2>
      <p>Click to verify:</p>
      <a href="http://localhost:${PORT}/verify?token=${token}" style="background:#ff00ff;color:#000;padding:12px 24px;text-decoration:none;border-radius:8px;">
        Verify Email
      </a>
    `,
  });
}

// Routes

// Auth
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const id = crypto.randomBytes(8).toString('hex');
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const user = new User({ email, password: hashed, id, verificationToken });
    await user.save();
    await sendVerificationEmail(email, verificationToken);
    res.json({ email, id, token: jwt.sign({ id: user._id }, JWT_SECRET) });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/auth/signin', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    res.json({ email: user.email, id: user.id, token: jwt.sign({ id: user._id }, JWT_SECRET), isAdmin: user.isAdmin });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/auth/admin/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !user.isAdmin || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: 'Invalid admin credentials' });
    }
    res.json({ email: user.email, id: user.id, token: jwt.sign({ id: user._id }, JWT_SECRET), isAdmin: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Verification
app.post('/api/auth/verify', async (req, res) => {
  const { token } = req.body;
  try {
    const user = await User.findOne({ verificationToken: token });
    if (!user) return res.status(400).json({ error: 'Invalid token' });
    user.verified = true;
    user.verificationToken = null;
    await user.save();
    res.json({ message: 'Email verified' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/resend', authMiddleware, async (req, res) => {
  if (req.user.verified) return res.json({ message: 'Already verified' });
  const token = crypto.randomBytes(32).toString('hex');
  req.user.verificationToken = token;
  await req.user.save();
  await sendVerificationEmail(req.user.email, token);
  res.json({ message: 'Verification email sent' });
});

// Profile
app.put('/api/profile', authMiddleware, async (req, res) => {
  const { email } = req.body;
  try {
    req.user.email = email;
    await req.user.save();
    res.json({ email });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

app.post('/api/upload', authMiddleware, upload.array('photos', 3), async (req, res) => {
  const { name } = req.body;
  if (req.user.uploads.length >= 3) return res.status(400).json({ error: 'Max 3 uploads' });
  const uploads = req.files.map(file => ({ src: `/uploads/${file.filename}`, name }));
  req.user.uploads.push(...uploads);
  await req.user.save();
  res.json({ uploads });
});

app.get('/api/upload', authMiddleware, async (req, res) => {
  res.json(req.user.uploads);
});

app.post('/api/admin/upload', authMiddleware, adminMiddleware, upload.array('photos'), async (req, res) => {
  const { name } = req.body;
  const uploads = req.files.map(file => ({ src: `/uploads/${file.filename}`, name }));
  // Assuming global admin uploads; store in separate collection if needed
  res.json({ uploads });
});

app.get('/api/admin/uploads', async (req, res) => {
  // Mock: Return some admin uploads; implement proper storage
  res.json([]); // Replace with actual query
});

// VIP
app.post('/api/vip/unlock', authMiddleware, async (req, res) => {
  const { item } = req.body;
  const vip = new Vip({ user: req.user._id, item });
  await vip.save();
  res.json({ message: 'Unlocked' });
});

app.get('/api/vip', authMiddleware, async (req, res) => {
  const vips = await Vip.find({ user: req.user._id });
  res.json(vips.map(v => ({ item: v.item })));
});

app.post('/api/vip/crypto', authMiddleware, async (req, res) => {
  const { paymentId, items, userEmail } = req.body;
  // Verify payment with NOWPayments API (implement callback)
  // For now, mock success
  items.forEach(item => new Vip({ user: req.user._id, item: item.item }).save());
  res.json({ message: 'Crypto payment processed' });
});

app.post('/api/vip/giftcard', authMiddleware, upload.single('giftCardImage'), async (req, res) => {
  const { code, items, userEmail } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
  const giftCard = new GiftCard({ userEmail, items: JSON.parse(items), code, imageUrl });
  await giftCard.save();
  res.json({ message: 'Gift card submitted' });
});

// Admin
app.get('/api/admin/payments', authMiddleware, adminMiddleware, async (req, res) => {
  const payments = await Payment.find();
  res.json(payments);
});

app.get('/api/admin/giftcards', authMiddleware, adminMiddleware, async (req, res) => {
  const giftCards = await GiftCard.find();
  res.json(giftCards);
});

app.post('/api/admin/response', authMiddleware, adminMiddleware, async (req, res) => {
  const { userEmail, message } = req.body;
  const payment = new Payment({ user: userEmail, message });
  await payment.save();
  res.json({ message: 'Response sent' });
});

// Chat WebSocket
const clients = new Map();

wss.on('connection', (ws) => {
  ws.on('message', async (data) => {
    const msg = JSON.parse(data);
    if (msg.type === 'message') {
      const chat = new Chat({ user: 'User', text: msg.text }); // Replace with actual user
      await chat.save();
      wss.clients.forEach(client => client.send(JSON.stringify({ type: 'message', ...chat.toObject() })));
    }
  });
});

app.get('/api/chat', authMiddleware, async (req, res) => {
  const messages = await Chat.find().sort({ createdAt: -1 }).limit(50);
  res.json(messages.reverse());
});

// Payment Callback (for NOWPayments)
app.post('/api/payment/callback', (req, res) => {
  // Verify and unlock VIP
  console.log('Payment callback:', req.body);
  res.sendStatus(200);
});

// Verify Page (for email link)
app.get('/verify', async (req, res) => {
  const { token } = req.query;
  try {
    const user = await User.findOne({ verificationToken: token });
    if (!user) return res.send('Invalid token');
    user.verified = true;
    user.verificationToken = null;
    await user.save();
    res.send('Email verified! Return to app.');
  } catch (err) {
    res.send('Error');
  }
});

// Start Server
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
