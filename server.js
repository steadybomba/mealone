// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
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
});

// MongoDB Schemas
const userSchema = new mongoose.Schema({
    id: { type: String, default: uuidv4, unique: true },
    email: { type: String, required: true, unique: true, match: /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/ },
    password: { type: String,你就所欲 },
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
app.use(cors({ origin: 'https://mealone-frontend.netlify.app' }));
app.use(express.json());
app.use('/Uploads', express.static(uploadDir));

// Multer setup for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
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
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
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

// Authentication Endpoints
app.post('/api/auth/signup', async (req, res) => {
    const { email, password } = req.body;

    log('info', 'Signup attempt', { email });

    // Input validation
    if (!email.match(/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/)) {
        log('warn', 'Signup failed: Invalid email', { email });
        return res.status(400).json({ errors: ['Invalid email format'] });
    }
    if (!password || password.length < 6) {
        log('warn', 'Signup failed: Invalid password', { email });
        return res.status(400).json({ errors: ['Password must be at least 6 characters'] });
    }

    try {
        // Check for existing user
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            log('warn', 'Signup failed: Email already exists', { email });
            return res.status(400).json({ errors: ['Email already exists'] });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        log('info', 'Password hashed successfully', { email });

        // Create new user
        const user = new User({
            id: uuidv4(),
            email,
            password: hashedPassword,
            isAdmin: false,
        });
        await user.save();
        log('info', 'User created', { userId: user.id, email });

        // Generate JWT
        const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.isAdmin }, jwtSecret, { expiresIn: '1h' });
        log('info', 'JWT generated for user', { userId: user.id });
        res.json({ email: user.email, id: user.id, token, isAdmin: user.isAdmin });
    } catch (error) {
        log('error', 'Signup error', { error: error.message, stack: error.stack });
        res.status(500).json({ error: 'Server error during signup' });
    }
});

app.post('/api/auth/signin', async (req, res) => {
    const { email, password } = req.body;

    log('info', 'Signin attempt', { email });

    if (!email.match(/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/)) {
        log('warn', 'Signin failed: Invalid email', { email });
        return res.status(400).json({ errors: ['Invalid email format'] });
    }
    if (!password) {
        log('warn', 'Signin failed: Password required', { email });
        return res.status(400).json({ errors: ['Password required'] });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            log('warn', 'Signin failed: User not found', { email });
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            log('warn', 'Signin failed: Incorrect password', { email });
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.isAdmin }, jwtSecret, { expiresIn: '1h' });
        log('info', 'Signin successful, JWT generated', { userId: user.id });
        res.json({ email: user.email, id: user.id, token, isAdmin: user.isAdmin });
    } catch (error) {
        log('error', 'Signin error', { error: error.message, stack: error.stack });
        res.status(500).json({ error: 'Server error during signin' });
    }
});

app.post('/api/auth/admin/login', async (req, res) => {
    const { email, password } = req.body;

    log('info', 'Admin login attempt', { email });

    if (!email.match(/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/)) {
        log('warn', 'Admin login failed: Invalid email', { email });
        return res.status(400).json({ errors: ['Invalid email format'] });
    }
    if (!password) {
        log('warn', 'Admin login failed: Password required', { email });
        return res.status(400).json({ errors: ['Password required'] });
    }

    try {
        const user = await User.findOne({ email, isAdmin: true });
        if (!user) {
            log('warn', 'Admin login failed: Not an admin user', { email });
            return res.status(401).json({ error: 'Invalid admin credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            log('warn', 'Admin login failed: Incorrect password', { email });
            return res.status(401).json({ error: 'Invalid admin credentials' });
        }

        const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.isAdmin }, jwtSecret, { expiresIn: '1h' });
        log('info', 'Admin login successful, JWT generated', { userId: user.id });
        res.json({ email: user.email, id: user.id, token, isAdmin: user.isAdmin });
    } catch (error) {
        log('error', 'Admin login error', { error: error.message, stack: error.stack });
        res.status(500).json({ error: 'Server error during admin login' });
    }
});

// Profile Endpoint
app.put('/api/profile', authenticateToken, async (req, res) => {
    const { email } = req.body;

    log('info', 'Profile update attempt', { userId: req.user.id, newEmail: email });

    if (!email.match(/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/)) {
        log('warn', 'Profile update failed: Invalid email', { userId: req.user.id, email });
        return res.status(400).json({ errors: ['Invalid email format'] });
    }

    try {
        const user = await User.findOne({ id: req.user.id });
        if (!user) {
            log('warn', 'Profile update failed: User not found', { userId: req.user.id });
            return res.status(404).json({ error: 'User not found' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser && existingUser.id !== user.id) {
            log('warn', 'Profile update failed: Email already in use', { userId: req.user.id, email });
            return res.status(400).json({ errors: ['Email already in use'] });
        }

        user.email = email;
        await user.save();
        log('info', 'Profile updated successfully', { userId: user.id, newEmail: email });
        res.json({ email: user.email });
    } catch (error) {
        log('error', 'Profile update error', { userId: req.user.id, error: error.message, stack: error.stack });
        res.status(500).json({ error: 'Server error during profile update' });
    }
});

// Upload Endpoints
app.post('/api/upload', authenticateToken, upload.array('photos', 3), async (req, res) => {
    log('info', 'User upload attempt', { userId: req.user.id, fileCount: req.files.length });

    try {
        const userUploads = await Upload.countDocuments({ userId: req.user.id });
        if (req.files.length + userUploads > 3) {
            log('warn', 'Upload failed: Max 3 uploads allowed', { userId: req.user.id, current: userUploads, attempted: req.files.length });
            return res.status(400).json({ errors: ['Max 3 uploads allowed'] });
        }

        const { name } = req.body;
        const newUploads = req.files.map(file => ({
            src: `/Uploads/${file.filename}`,
            name: name || file.originalname,
            userId: req.user.id,
            createdAt: new Date(),
        }));

        const savedUploads = await Upload.insertMany(newUploads);
        log('info', 'Uploads saved successfully', { userId: req.user.id, uploadCount: savedUploads.length });
        res.json({ uploads: savedUploads });
    } catch (error) {
        log('error', 'Upload error', { userId: req.user.id, error: error.message, stack: error.stack });
        res.status(500).json({ error: 'Server error during upload' });
    }
});

app.get('/api/upload', authenticateToken, async (req, res) => {
    log('info', 'Fetching user uploads', { userId: req.user.id });

    try {
        const userUploads = await Upload.find({ userId: req.user.id });
        log('info', 'User uploads retrieved', { userId: req.user.id, count: userUploads.length });
        res.json(userUploads);
    } catch (error) {
        log('error', 'Fetch uploads error', { userId: req.user.id, error: error.message, stack: error.stack });
        res.status(500).json({ error: 'Server error fetching uploads' });
    }
});

app.post('/api/admin/upload', authenticateToken, upload.array('photos'), async (req, res) => {
    if (!req.user.isAdmin) {
        log('warn', 'Admin upload failed: Not admin', { userId: req.user.id });
        return res.status(403).json({ error: 'Admin access required' });
    }

    log('info', 'Admin upload attempt', { userId: req.user.id, fileCount: req.files.length });

    try {
        const { name } = req.body;
        const newUploads = req.files.map(file => ({
            src: `/Uploads/${file.filename}`,
            name: name || file.originalname,
            createdAt: new Date(),
        }));

        const savedUploads = await AdminUpload.insertMany(newUploads);
        log('info', 'Admin uploads saved successfully', { userId: req.user.id, uploadCount: savedUploads.length });
        res.json({ uploads: savedUploads });
    } catch (error) {
        log('error', 'Admin upload error', { userId: req.user.id, error: error.message, stack: error.stack });
        res.status(500).json({ error: 'Server error during admin upload' });
    }
});

app.get('/api/admin/uploads', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) {
        log('warn', 'Fetch admin uploads failed: Not admin', { userId: req.user.id });
        return res.status(403).json({ error: 'Admin access required' });
    }

    log('info', 'Fetching admin uploads', { userId: req.user.id });

    try {
        const uploads = await AdminUpload.find();
        log('info', 'Admin uploads retrieved', { userId: req.user.id, count: uploads.length });
        res.json(uploads);
    } catch (error) {
        log('error', 'Fetch admin uploads error', { userId: req.user.id, error: error.message, stack: error.stack });
        res.status(500).json({ error: 'Server error fetching admin uploads' });
    }
});

// VIP and Payment Endpoints
app.get('/api/vip', authenticateToken, async (req, res) => {
    log('info', 'Fetching VIP unlocks', { userId: req.user.id });

    try {
        const userVipUnlocks = await VipUnlock.find({ userId: req.user.id });
        log('info', 'VIP unlocks retrieved', { userId: req.user.id, count: userVipUnlocks.length });
        res.json(userVipUnlocks);
    } catch (error) {
        log('error', 'Fetch VIP unlocks error', { userId: req.user.id, error: error.message, stack: error.stack });
        res.status(500).json({ error: 'Server error fetching VIP unlocks' });
    }
});

app.post('/api/vip/unlock', authenticateToken, async (req, res) => {
    const { item } = req.body;

    log('info', 'VIP unlock attempt', { userId: req.user.id, item });

    if (!item) {
        log('warn', 'VIP unlock failed: Item required', { userId: req.user.id });
        return res.status(400).json({ error: 'Item required' });
    }

    try {
        const vipUnlock = new VipUnlock({
            item,
            userId: req.user.id,
            createdAt: new Date(),
        });
        await vipUnlock.save();
        log('info', 'VIP item unlocked', { userId: req.user.id, item });
        res.json({ message: 'Item unlocked' });
    } catch (error) {
        log('error', 'VIP unlock error', { userId: req.user.id, error: error.message, stack: error.stack });
        res.status(500).json({ error: 'Server error during VIP unlock' });
    }
});

app.post('/api/vip/crypto', authenticateToken, async (req, res) => {
    const { paymentId, items, userEmail } = req.body;

    log('info', 'Crypto payment attempt', { userId: req.user.id, userEmail, paymentId });

    try {
        const paymentResponse = new PaymentResponse({
            user: userEmail,
            item: items.map(i => i.item).join(', '),
            message: 'Crypto payment initiated',
            paymentId,
            createdAt: new Date(),
        });
        await paymentResponse.save();
        log('info', 'Crypto payment recorded', { userId: req.user.id, paymentId });
        res.json({ message: 'Crypto payment recorded' });
    } catch (error) {
        log('error', 'Crypto payment error', { userId: req.user.id, error: error.message, stack: error.stack });
        res.status(500).json({ error: 'Server error during crypto payment' });
    }
});

app.post('/api/vip/giftcard', authenticateToken, upload.single('giftCardImage'), async (req, res) => {
    const { code, items, userEmail } = req.body;
    const parsedItems = JSON.parse(items);

    log('info', 'Gift card submission attempt', { userId: req.user.id, userEmail, code: code || 'N/A' });

    try {
        const giftCard = new GiftCard({
            userEmail,
            items: parsedItems,
            code: code || 'N/A',
            imageUrl: req.file ? `/Uploads/${req.file.filename}` : null,
            createdAt: new Date(),
        });
        await giftCard.save();
        log('info', 'Gift card submitted', { userId: req.user.id, giftCardId: giftCard._id });
        res.json({ message: 'Gift card submitted' });
    } catch (error) {
        log('error', 'Gift card submission error', { userId: req.user.id, error: error.message, stack: error.stack });
        res.status(500).json({ error: 'Server error during gift card submission' });
    }
});

// Admin Endpoints
app.get('/api/admin/payments', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) {
        log('warn', 'Fetch payments failed: Not admin', { userId: req.user.id });
        return res.status(403).json({ error: 'Admin access required' });
    }

    log('info', 'Fetching admin payments', { userId: req.user.id });

    try {
        const payments = await PaymentResponse.find();
        log('info', 'Admin payments retrieved', { userId: req.user.id, count: payments.length });
        res.json(payments);
    } catch (error) {
        log('error', 'Fetch payments error', { userId: req.user.id, error: error.message, stack: error.stack });
        res.status(500).json({ error: 'Server error fetching payments' });
    }
});

app.get('/api/admin/giftcards', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) {
        log('warn', 'Fetch gift cards failed: Not admin', { userId: req.user.id });
        return res.status(403).json({ error: 'Admin access required' });
    }

    log('info', 'Fetching admin gift cards', { userId: req.user.id });

    try {
        const giftCards = await GiftCard.find();
        log('info', 'Admin gift cards retrieved', { userId: req.user.id, count: giftCards.length });
        res.json(giftCards);
    } catch (error) {
        log('error', 'Fetch gift cards error', { userId: req.user.id, error: error.message, stack: error.stack });
        res.status(500).json({ error: 'Server error fetching gift cards' });
    }
});

app.post('/api/admin/response', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) {
        log('warn', 'Send response failed: Not admin', { userId: req.user.id });
        return res.status(403).json({ error: 'Admin access required' });
    }

    const { userEmail, message } = req.body;

    log('info', 'Admin response attempt', { userId: req.user.id, userEmail });

    if (!userEmail.match(/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/)) {
        log('warn', 'Admin response failed: Invalid email', { userId: req.user.id, userEmail });
        return res.status(400).json({ errors: ['Invalid email format'] });
    }
    if (!message) {
        log('warn', 'Admin response failed: Message required', { userId: req.user.id });
        return res.status(400).json({ errors: ['Message required'] });
    }

    try {
        const paymentResponse = new PaymentResponse({
            user: userEmail,
            message,
            createdAt: new Date(),
        });
        await paymentResponse.save();
        log('info', 'Admin response sent', { userId: req.user.id, userEmail, responseId: paymentResponse._id });
        res.json({ message: 'Response sent' });
    } catch (error) {
        log('error', 'Send response error', { userId: req.user.id, error: error.message, stack: error.stack });
        res.status(500).json({ error: 'Server error sending response' });
    }
});

// Payment Callback Endpoint (for NOWPayments)
app.post('/api/payment/callback', async (req, res) => {
    const { payment_id, payment_status } = req.body;

    log('info', 'Received NOWPayments callback', { paymentId: payment_id, status: payment_status });

    try {
        const payment = await PaymentResponse.findOne({ paymentId: payment_id });
        if (payment && payment_status === 'finished') {
            payment.message = 'Payment confirmed';
            await payment.save();
            log('info', 'Payment confirmed', { paymentId: payment_id });
            // Process VIP unlocks or other logic here
        }
        res.sendStatus(200);
    } catch (error) {
        log('error', 'Payment callback error', { paymentId: payment_id, error: error.message, stack: error.stack });
        res.sendStatus(500);
    }
});

// Combined HTTP and WebSocket Server
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

wss.on('connection', async (ws, req) => {
    const token = new URLSearchParams(req.url.split('?')[1]).get('token');
    let user;
    try {
        user = jwt.verify(token, jwtSecret);
        log('info', 'WebSocket connection established', { userId: user.id, email: user.email });
    } catch (err) {
        log('warn', 'WebSocket connection failed: Invalid token', { token: token ? token.slice(0, 10) + '...' : 'null' });
        ws.send(JSON.stringify({ type: 'error', message: 'Invalid token' }));
        ws.close();
        return;
    }

    try {
        const messages = await ChatMessage.find().sort({ createdAt: -1 }).limit(100);
        log('info', 'Sent initial chat messages', { userId: user.id, count: messages.length });
        ws.send(JSON.stringify({ type: 'init', messages }));
    } catch (error) {
        log('error', 'Fetch chat messages error', { userId: user.id, error: error.message, stack: error.stack });
        ws.send(JSON.stringify({ type: 'error', message: 'Failed to load messages' }));
    }

    ws.on('message', async (data) => {
        let message;
        try {
            message = JSON.parse(data);
        } catch (error) {
            log('warn', 'Invalid WebSocket message', { userId: user.id, error: error.message });
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
            return;
        }

        if (message.type === 'message' && message.text && message.text.length <= 500) {
            try {
                const chatMessage = new ChatMessage({
                    user: user.email,
                    text: message.text,
                    createdAt: new Date(),
                });
                await chatMessage.save();
                log('info', 'Chat message saved', { userId: user.id, messageId: chatMessage._id });

                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(JSON.stringify({ type: 'message', ...chatMessage.toObject() }));
                    }
                });
            } catch (error) {
                log('error', 'Chat message error', { userId: user.id, error: error.message, stack: error.stack });
                ws.send(JSON.stringify({ type: 'error', message: 'Failed to send message' }));
            }
        } else {
            log('warn', 'Invalid chat message', { userId: user.id, textLength: message.text?.length || 0 });
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid message or too long' }));
        }
    });

    ws.on('close', () => {
        log('info', 'WebSocket client disconnected', { userId: user.id });
    });
});

// Start Server
server.listen(port, () => {
    log('info', `Server started on port ${port}`, { url: `http://localhost:${port}` });
});