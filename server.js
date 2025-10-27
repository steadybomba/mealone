// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); // ← Replaced bcrypt with bcryptjs
const multer = require('multer');    // ← Now safe (v2+)
const WebSocket = require('ws');
const path = require('path');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const http = require('http');

// Custom logging function with timestamp and context
const log = (level, message, metadata = {}) => {
    const timestamp = new Date().toISOString();
    console[level](`[${timestamp}] ${level.toUpperCase()}: ${message}`, metadata);
};

const app = express();
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET || 'your_jwt_secret_key';
const uploadDir = path.join(__dirname, 'Uploads');

// Ensure upload directory exists
if (!fs.existsSync(uploadDir)) {
    log('info', 'Creating upload directory', { path: uploadDir });
    fs.mkdirSync(uploadDir, { recursive: true });
}

// MongoDB Connection
log('info', 'Connecting to MongoDB Atlas...');
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    log('info', 'Successfully connected to MongoDB Atlas');
}).catch(err => {
    log('error', 'MongoDB connection failed', { error: err.message, stack: err.stack });
    process.exit(1);
});

// MongoDB Schemas
const userSchema = new mongoose.Schema({
    id: { type: String, default: uuidv4, unique: true },
    email: { type: String, required: true, unique: true, match: /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/ },
    password: { type: String, required: true, select: false }, // ← FIXED
    isAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
});

const uploadSchema = new mongoose.Schema({
    src: { type: String, required: true },
    name: { type: String, required: true },
    userId: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
});

const adminUploadSchema = new mongoose.Schema({
    src: { type: String, required: true },
    name: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
});

const paymentResponseSchema = new mongoose.Schema({
    user: { type: String, required: true },
    item: { type: String, required: true },
    message: { type: String, required: true },
    paymentId: { type: String },
    code: { type: String },
    createdAt: { type: Date, default: Date.now },
});

const giftCardSchema = new mongoose.Schema({
    userEmail: { type: String, required: true },
    items: [{ item: String, price: Number, galleryIndex: Number }],
    code: { type: String },
    imageUrl: { type: String },
    createdAt: { type: Date, default: Date.now },
});

const vipUnlockSchema = new mongoose.Schema({
    item: { type: String, required: true },
    userId: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
});

const chatMessageSchema = new mongoose.Schema({
    user: { type: String, required: true },
    text: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Upload = mongoose.model('Upload', uploadSchema);
const AdminUpload = mongoose.model('AdminUpload', adminUploadSchema);
const PaymentResponse = mongoose.model('PaymentResponse', paymentResponseSchema);
const GiftCard = mongoose.model('GiftCard', giftCardSchema);
const VipUnlock = mongoose.model('VipUnlock', vipUnlockSchema);
const ChatMessage = mongoose.model('ChatMessage', chatMessageSchema);

// Middleware
app.use(cors({ origin: 'https://mealonee.netlify.app' }));
app.use(express.json({ limit: '10mb' }));
app.use('/Uploads', express.static(uploadDir));

// Multer setup (v2+ with security fixes)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        const name = `${Date.now()}-${Math.round(Math.random() * 1E9)}${ext}`;
        cb(null, name);
    },
});

const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only images are allowed'), false);
        }
    },
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
});

// JWT Authentication Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        log('warn', 'Unauthorized request: No token provided', { method: req.method, url: req.url });
        return res.status(401).json({ error: 'Unauthorized' });
    }

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            log('warn', 'Invalid token', { method: req.method, url: req.url, error: err.message });
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        log('info', 'Authenticated request', { method: req.method, url: req.url, userId: user.id });
        next();
    });
}

// === AUTH ENDPOINTS ===
app.post('/api/auth/signup', async (req, res) => {
    const { email, password } = req.body;

    log('info', 'Signup attempt', { email });

    if (!email.match(/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/)) {
        return res.status(400).json({ errors: ['Invalid email format'] });
    }
    if (!password || password.length < 6) {
        return res.status(400).json({ errors: ['Password must be at least 6 characters'] });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ errors: ['Email already exists'] });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            email,
            password: hashedPassword,
            isAdmin: false,
        });
        await user.save();

        const token = jwt.sign(
            { id: user.id, email: user.email, isAdmin: user.isAdmin },
            jwtSecret,
            { expiresIn: '1h' }
        );

        res.json({ email: user.email, id: user.id, token, isAdmin: user.isAdmin });
    } catch (error) {
        log('error', 'Signup error', { error: error.message });
        res.status(500).json({ error: 'Server error during signup' });
    }
});

app.post('/api/auth/signin', async (req, res) => {
    const { email, password } = req.body;

    if (!email.match(/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/) || !password) {
        return res.status(400).json({ error: 'Invalid credentials' });
    }

    try {
        const user = await User.findOne({ email }).select('+password');
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, isAdmin: user.isAdmin },
            jwtSecret,
            { expiresIn: '1h' }
        );

        res.json({ email: user.email, id: user.id, token, isAdmin: user.isAdmin });
    } catch (error) {
        log('error', 'Signin error', { error: error.message });
        res.status(500).json({ error: 'Server error during signin' });
    }
});

app.post('/api/auth/admin/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email.match(/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/) || !password) {
        return res.status(400).json({ error: 'Invalid credentials' });
    }

    try {
        const user = await User.findOne({ email, isAdmin: true }).select('+password');
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid admin credentials' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, isAdmin: true },
            jwtSecret,
            { expiresIn: '1h' }
        );

        res.json({ email: user.email, id: user.id, token, isAdmin: true });
    } catch (error) {
        log('error', 'Admin login error', { error: error.message });
        res.status(500).json({ error: 'Server error' });
    }
});

// === PROFILE ===
app.put('/api/profile', authenticateToken, async (req, res) => {
    const { email } = req.body;

    if (!email.match(/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/)) {
        return res.status(400).json({ errors: ['Invalid email format'] });
    }

    try {
        const user = await User.findOne({ id: req.user.id });
        if (!user) return res.status(404).json({ error: 'User not found' });

        const existing = await User.findOne({ email });
        if (existing && existing.id !== user.id) {
            return res.status(400).json({ errors: ['Email already in use'] });
        }

        user.email = email;
        await user.save();
        res.json({ email: user.email });
    } catch (error) {
        log('error', 'Profile update error', { error: error.message });
        res.status(500).json({ error: 'Server error' });
    }
});

// === UPLOADS ===
app.post('/api/upload', authenticateToken, upload.array('photos', 3), async (req, res) => {
    try {
        const userUploads = await Upload.countDocuments({ userId: req.user.id });
        if (userUploads + req.files.length > 3) {
            return res.status(400).json({ errors: ['Max 3 uploads allowed'] });
        }

        const { name } = req.body;
        const newUploads = req.files.map(file => ({
            src: `/Uploads/${file.filename}`,
            name: name || file.originalname,
            userId: req.user.id,
        }));

        const saved = await Upload.insertMany(newUploads);
        res.json({ uploads: saved });
    } catch (error) {
        log('error', 'Upload error', { error: error.message });
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/upload', authenticateToken, async (req, res) => {
    const uploads = await Upload.find({ userId: req.user.id });
    res.json(uploads);
});

// Admin uploads...
app.post('/api/admin/upload', authenticateToken, upload.array('photos'), async (req, res) => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });

    const { name } = req.body;
    const newUploads = req.files.map(file => ({
        src: `/Uploads/${file.filename}`,
        name: name || file.originalname,
    }));

    const saved = await AdminUpload.insertMany(newUploads);
    res.json({ uploads: saved });
});

app.get('/api/admin/uploads', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    const uploads = await AdminUpload.find();
    res.json(uploads);
});

// === VIP & PAYMENTS ===
app.get('/api/vip', authenticateToken, async (req, res) => {
    const unlocks = await VipUnlock.find({ userId: req.user.id });
    res.json(unlocks);
});

app.post('/api/vip/unlock', authenticateToken, async (req, res) => {
    const { item } = req.body;
    if (!item) return res.status(400).json({ error: 'Item required' });

    const unlock = new VipUnlock({ item, userId: req.user.id });
    await unlock.save();
    res.json({ message: 'Item unlocked' });
});

app.post('/api/vip/crypto', authenticateToken, async (req, res) => {
    const { paymentId, items, userEmail } = req.body;
    const response = new PaymentResponse({
        user: userEmail,
        item: items.map(i => i.item).join(', '),
        message: 'Crypto payment initiated',
        paymentId,
    });
    await response.save();
    res.json({ message: 'Crypto payment recorded' });
});

app.post('/api/vip/giftcard', authenticateToken, upload.single('giftCardImage'), async (req, res) => {
    const { code, items, userEmail } = req.body;
    let parsedItems = [];
    try { parsedItems = JSON.parse(items); } catch { }

    const giftCard = new GiftCard({
        userEmail,
        items: parsedItems,
        code: code || 'N/A',
        imageUrl: req.file ? `/Uploads/${req.file.filename}` : null,
    });
    await giftCard.save();
    res.json({ message: 'Gift card submitted' });
});

// === ADMIN PANEL ===
app.get('/api/admin/payments', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    const payments = await PaymentResponse.find();
    res.json(payments);
});

app.get('/api/admin/giftcards', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    const giftCards = await GiftCard.find();
    res.json(giftCards);
});

app.post('/api/admin/response', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });

    const { userEmail, message } = req.body;
    if (!userEmail.match(/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/) || !message) {
        return res.status(400).json({ errors: ['Invalid email or message'] });
    }

    const response = new PaymentResponse({ user: userEmail, message, item: 'Admin Response' });
    await response.save();
    res.json({ message: 'Response sent' });
});

// === PAYMENT CALLBACK ===
app.post('/api/payment/callback', async (req, res) => {
    const { payment_id, payment_status } = req.body;
    if (payment_status === 'finished') {
        await PaymentResponse.updateOne(
            { paymentId: payment_id },
            { message: 'Payment confirmed' }
        );
    }
    res.sendStatus(200);
});

// === WEBSOCKET CHAT ===
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

wss.on('connection', async (ws, req) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const token = url.searchParams.get('token');
    let user;

    try {
        user = jwt.verify(token, jwtSecret);
    } catch {
        ws.close();
        return;
    }

    // Send chat history
    const messages = await ChatMessage.find().sort({ createdAt: -1 }).limit(100);
    ws.send(JSON.stringify({ type: 'init', messages: messages.reverse() }));

    ws.on('message', async (data) => {
        let msg;
        try { msg = JSON.parse(data); } catch { return; }

        if (msg.type === 'message' && msg.text && msg.text.length <= 500) {
            const chatMsg = new ChatMessage({ user: user.email, text: msg.text });
            await chatMsg.save();

            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(JSON.stringify({ type: 'message', ...chatMsg.toObject() }));
                }
            });
        }
    });
});

// Start Server
server.listen(port, () => {
    log('info', `Server running on port ${port}`);
});
