/**
 * BACKEND SERVER CODE (Node.js / Express / MongoDB)
 * 
 * Dependencies: npm install express cors body-parser google-auth-library mongoose dotenv uuid bcryptjs
 * Run: node server.js
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { OAuth2Client } = require('google-auth-library');
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3001;
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID_HERE';

// --- MONGODB CONNECTION ---
// Use environment variable or fallback (password is URL-encoded: @ = %40)
let MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://sahilhaq2003:Sahil%402003Haq@cluster0.buir1zc.mongodb.net/minihaai?retryWrites=true&w=majority';

// Fix: If Railway decoded %40 to @, re-encode it
if (MONGODB_URI.includes('@') && !MONGODB_URI.includes('%40')) {
  // Check if password contains @ that should be %40
  const uriMatch = MONGODB_URI.match(/mongodb\+srv:\/\/([^:]+):([^@]+)@/);
  if (uriMatch && uriMatch[2].includes('@')) {
    const password = uriMatch[2].replace(/@/g, '%40');
    MONGODB_URI = MONGODB_URI.replace(/mongodb\+srv:\/\/[^:]+:[^@]+@/, `mongodb+srv://${uriMatch[1]}:${password}@`);
    console.log('⚠️  Fixed MongoDB URI encoding');
  }
}

console.log('🔧 Environment Check:');
if (!process.env.MONGODB_URI) {
  console.warn('⚠️  MONGODB_URI not set in environment variables!');
  console.warn('   Using fallback URI. Make sure to set MONGODB_URI in Railway!');
} else {
  console.log('  MONGODB_URI: Set ✓');
  // Show first part of URI for debugging (without password)
  const uriPreview = MONGODB_URI.replace(/mongodb\+srv:\/\/[^:]+:[^@]+@/, 'mongodb+srv://***:***@');
  console.log('  URI Preview:', uriPreview.substring(0, 80) + '...');
}
console.log('  GOOGLE_CLIENT_ID:', CLIENT_ID !== 'YOUR_GOOGLE_CLIENT_ID_HERE' ? 'Set ✓' : 'Missing ⚠️');
console.log('  PORT:', PORT);

// Connect to MongoDB with retry logic
async function connectMongoDB() {
  // Close existing connection if any
  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection.close();
  }
  
  try {
    console.log('🔄 Attempting to connect to MongoDB...');
    console.log('  Timeout: 15 seconds');
    
    // Use shorter timeout to fail faster and show errors
    await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 15000, // Reduced from 30000
      socketTimeoutMS: 30000,
      connectTimeoutMS: 15000,
      maxPoolSize: 10,
      retryWrites: true,
      w: 'majority'
    });
    
    console.log('✅ Connected to MongoDB Atlas');
    console.log('Database:', mongoose.connection.name);
    console.log('Host:', mongoose.connection.host);
    console.log('Ready State:', mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected');
    
    // Handle connection events
    mongoose.connection.on('error', (err) => {
      console.error('❌ MongoDB connection error:', err.message);
    });
    
    mongoose.connection.on('disconnected', () => {
      console.warn('⚠️  MongoDB disconnected. Attempting to reconnect...');
      setTimeout(connectMongoDB, 5000);
    });
    
    mongoose.connection.on('reconnected', () => {
      console.log('✅ MongoDB reconnected');
    });
    
  } catch (err) {
    console.error('❌ MongoDB connection failed:');
    console.error('  Message:', err.message);
    console.error('  Code:', err.code);
    console.error('  Name:', err.name);
    
    // More specific error messages
    if (err.message.includes('authentication failed') || err.message.includes('bad auth')) {
      console.error('  ⚠️  AUTHENTICATION FAILED');
      console.error('     → Check username and password in MongoDB Atlas');
      console.error('     → Verify Database Access user: sahilhaq2003');
    } else if (err.message.includes('ENOTFOUND') || err.message.includes('getaddrinfo')) {
      console.error('  ⚠️  DNS/URL ERROR');
      console.error('     → Check MongoDB cluster URL is correct');
      console.error('     → Verify cluster0.buir1zc.mongodb.net is accessible');
    } else if (err.message.includes('timeout') || err.message.includes('ETIMEDOUT')) {
      console.error('  ⚠️  CONNECTION TIMEOUT');
      console.error('     → Check Network Access in MongoDB Atlas');
      console.error('     → Add IP: 0.0.0.0/0 (Allow from anywhere)');
      console.error('     → Railway IPs may be blocked');
    } else if (err.message.includes('MongoServerError')) {
      console.error('  ⚠️  MONGODB SERVER ERROR');
      console.error('     → Check MongoDB Atlas cluster status');
    } else {
      console.error('  ⚠️  UNKNOWN ERROR');
      console.error('     → Full error:', JSON.stringify(err, null, 2));
    }
    
    // Retry after 10 seconds (longer delay to avoid spam)
    console.log('🔄 Retrying connection in 10 seconds...');
    setTimeout(connectMongoDB, 10000);
  }
}

// Start MongoDB connection
connectMongoDB();

// Monitor connection state every 10 seconds
setInterval(() => {
  const state = mongoose.connection.readyState;
  const states = { 0: 'disconnected', 1: 'connected', 2: 'connecting', 3: 'disconnecting' };
  
  if (state !== 1) {
    console.log(`⏳ MongoDB Status: ${states[state]} (${state})`);
    
    if (state === 2) {
      console.log('   → Connection attempt in progress...');
      console.log('   → If stuck here, check:');
      console.log('      1. MongoDB Atlas Network Access (allow 0.0.0.0/0)');
      console.log('      2. MongoDB credentials in Railway variables');
      console.log('      3. Railway logs for detailed errors');
    }
  }
}, 10000); // Every 10 seconds

// --- MONGOOSE SCHEMAS ---
const userSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  name: { type: String },
  picture: { type: String },
  provider: { type: String, default: 'email' },
  is_premium: { type: Boolean, default: false },
  google_id: { type: String },
  created_at: { type: Date, default: Date.now }
});

const transactionSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  user_id: { type: String, required: true },
  amount: { type: String },
  status: { type: String },
  date: { type: Date, default: Date.now },
  invoice_id: { type: String },
  plan_type: { type: String }
});

const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);

const client = new OAuth2Client(CLIENT_ID);

// --- CORS CONFIGURATION ---
const allowedOrigins = [
  'https://minihaai.netlify.app',
  'http://localhost:5173',
  'http://localhost:3000'
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(null, true);
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(bodyParser.json());

// --- Health Check ---
app.get('/', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'MinihaAI Backend API is running!',
    database: 'MongoDB Atlas',
    timestamp: new Date().toISOString()
  });
});

app.get('/api/health', (req, res) => {
  const dbState = mongoose.connection.readyState;
  const states = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting'
  };
  
  const isHealthy = dbState === 1;
  
  res.json({ 
    status: isHealthy ? 'healthy' : 'unhealthy',
    database: states[dbState] || 'unknown',
    readyState: dbState,
    message: isHealthy 
      ? 'MongoDB connected successfully' 
      : `MongoDB is ${states[dbState]}. Check Railway logs for connection errors.`
  });
});

// Diagnostic endpoint
app.get('/api/diagnose', async (req, res) => {
  const dbState = mongoose.connection.readyState;
  const states = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting'
  };
  
  const diagnostics = {
    mongodb: {
      state: states[dbState] || 'unknown',
      readyState: dbState,
      host: mongoose.connection.host || 'N/A',
      name: mongoose.connection.name || 'N/A',
      hasEnvVar: !!process.env.MONGODB_URI
    },
    environment: {
      nodeEnv: process.env.NODE_ENV || 'not set',
      port: PORT,
      hasGoogleClientId: CLIENT_ID !== 'YOUR_GOOGLE_CLIENT_ID_HERE'
    }
  };
  
  // Try a simple query if connected
  if (dbState === 1) {
    try {
      await mongoose.connection.db.admin().ping();
      diagnostics.mongodb.ping = 'success';
    } catch (err) {
      diagnostics.mongodb.ping = `failed: ${err.message}`;
    }
  }
  
  res.json(diagnostics);
});

// --- GOOGLE AUTH ---
app.post('/api/auth/google', async (req, res) => {
  const { token } = req.body;

  try {
    // SPECIAL HANDLING FOR DEMO/TESTING
    if (token === 'dummy_token_for_simulation') {
      const demoEmail = 'demo_user@example.com';
      let user = await User.findOne({ email: demoEmail });
      
      if (!user) {
        user = new User({
          id: uuidv4(),
          email: demoEmail,
          name: 'Demo Google User',
          picture: 'https://api.dicebear.com/7.x/avataaars/svg?seed=google_demo',
          provider: 'google',
          google_id: 'dummy_google_id_12345',
          is_premium: false,
          created_at: new Date()
        });
        await user.save();
      }
      
      return res.status(200).json({
        success: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          avatar: user.picture,
          isPremium: user.is_premium
        }
      });
    }

    // REAL GOOGLE VERIFICATION
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: CLIENT_ID,
    });
    
    const payload = ticket.getPayload();
    const googleUserId = payload['sub'];
    const email = payload['email'];
    const name = payload['name'];
    const picture = payload['picture'];

    let user = await User.findOne({ email });

    if (!user) {
      user = new User({
        id: uuidv4(),
        email,
        name,
        picture,
        provider: 'google',
        google_id: googleUserId,
        is_premium: false,
        created_at: new Date()
      });
      await user.save();
    } else if (user.provider !== 'google') {
      user.google_id = googleUserId;
      user.provider = 'google';
      user.picture = picture;
      await user.save();
    }

    res.status(200).json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        avatar: user.picture,
        isPremium: user.is_premium
      }
    });

  } catch (error) {
    console.error('Google Auth Error:', error);
    res.status(401).json({ success: false, message: 'Invalid Token' });
  }
});

// --- EMAIL SIGNUP ---
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  console.log('📝 Signup attempt for:', email);

  // Check MongoDB connection
  if (mongoose.connection.readyState !== 1) {
    console.error('❌ MongoDB not connected. State:', mongoose.connection.readyState);
    return res.status(503).json({ 
      success: false, 
      message: 'Database connection unavailable. Please try again later.' 
    });
  }

  try {
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log('❌ User already exists:', email);
      return res.status(400).json({ success: false, message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      id: uuidv4(),
      email,
      password: hashedPassword,
      name: email.split('@')[0],
      picture: `https://api.dicebear.com/7.x/avataaars/svg?seed=${encodeURIComponent(email)}`,
      provider: 'email',
      is_premium: false,
      created_at: new Date()
    });

    const savedUser = await user.save();
    console.log('✅ User saved to MongoDB:', savedUser.email);

    res.status(201).json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        avatar: user.picture,
        isPremium: user.is_premium
      }
    });
  } catch (error) {
    console.error("Signup Error Details:", {
      message: error.message,
      name: error.name,
      stack: error.stack
    });
    
    // More specific error messages
    if (error.name === 'MongoServerError' && error.code === 11000) {
      return res.status(400).json({ success: false, message: 'User already exists' });
    }
    
    res.status(500).json({ 
      success: false, 
      message: "Server error during signup",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// --- EMAIL LOGIN ---
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ success: false, message: 'User not found' });
    }

    if (user.provider === 'google') {
      return res.status(400).json({ success: false, message: 'Please login with Google' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }

    res.status(200).json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        avatar: user.picture,
        isPremium: user.is_premium
      }
    });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ success: false, message: "Server error during login" });
  }
});

// --- BILLING HISTORY ---
app.get('/api/user/:userId/transactions', async (req, res) => {
  try {
    const { userId } = req.params;
    const transactions = await Transaction.find({ user_id: userId }).sort({ date: -1 });
    
    const formatted = transactions.map(t => ({
      id: t.id,
      date: new Date(t.date).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }),
      amount: t.amount,
      status: t.status,
      invoice: t.invoice_id
    }));

    res.status(200).json({ success: true, transactions: formatted });
  } catch (error) {
    console.error("Tx Error:", error);
    res.status(500).json({ success: false, message: "Error fetching transactions" });
  }
});

// --- PAYMENT ---
app.post('/api/payment/create', async (req, res) => {
  const { userId, amount } = req.body;
  try {
    // Update User to Premium
    await User.findOneAndUpdate({ id: userId }, { is_premium: true });
    
    // Record Transaction
    const transaction = new Transaction({
      id: uuidv4(),
      user_id: userId,
      amount,
      status: 'Paid',
      date: new Date(),
      invoice_id: '#INV-' + Math.floor(Math.random() * 1000000),
      plan_type: 'Pro Plan'
    });
    
    await transaction.save();

    res.status(200).json({ success: true, transaction });
  } catch (error) {
    console.error("Payment Error:", error);
    res.status(500).json({ success: false, message: "Payment failed" });
  }
});

// --- GET USER BY ID ---
app.get('/api/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await User.findOne({ id: userId });
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.status(200).json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        avatar: user.picture,
        isPremium: user.is_premium
      }
    });
  } catch (error) {
    console.error("Get User Error:", error);
    res.status(500).json({ success: false, message: "Error fetching user" });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 Health check: http://localhost:${PORT}/api/health`);
  console.log(`📊 MongoDB Status: ${mongoose.connection.readyState === 1 ? '✅ Connected' : '❌ Disconnected'}`);
  
  if (mongoose.connection.readyState !== 1) {
    console.log('⏳ Waiting for MongoDB connection...');
  }
});
