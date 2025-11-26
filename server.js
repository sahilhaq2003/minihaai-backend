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
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const nodemailer = require('nodemailer');
const crypto = require('crypto');

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
  email_verified: { type: Boolean, default: false },
  verification_token: { type: String },
  verification_token_expires: { type: Date },
  reset_password_token: { type: String },
  reset_password_expires: { type: Date },
  created_at: { type: Date, default: Date.now }
});

const transactionSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  user_id: { type: String, required: true },
  amount: { type: String },
  status: { type: String },
  date: { type: Date, default: Date.now },
  invoice_id: { type: String },
  plan_type: { type: String },
  stripe_payment_intent_id: { type: String },
  stripe_customer_id: { type: String }
});

const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);

const client = new OAuth2Client(CLIENT_ID);

// --- EMAIL SERVICE SETUP ---
const createEmailTransporter = () => {
  // Use Gmail SMTP or any SMTP service
  // For production, use environment variables
  return nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE || 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });
};

// Helper function to send emails
const sendEmail = async (to, subject, html) => {
  try {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
      console.warn('⚠️  Email not configured. Set EMAIL_USER and EMAIL_PASSWORD in environment variables.');
      return { success: false, message: 'Email service not configured' };
    }
    
    const transporter = createEmailTransporter();
    const info = await transporter.sendMail({
      from: `"MinihaAI" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html
    });
    
    console.log('✅ Email sent:', info.messageId);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error('❌ Email send error:', error);
    return { success: false, error: error.message };
  }
};

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
        isPremium: user.is_premium,
        emailVerified: user.email_verified || true // Google users are auto-verified
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
    
    // Generate verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationTokenExpires = new Date();
    verificationTokenExpires.setHours(verificationTokenExpires.getHours() + 24); // 24 hours

    const user = new User({
      id: uuidv4(),
      email,
      password: hashedPassword,
      name: email.split('@')[0],
      picture: `https://api.dicebear.com/7.x/avataaars/svg?seed=${encodeURIComponent(email)}`,
      provider: 'email',
      is_premium: false,
      email_verified: false,
      verification_token: verificationToken,
      verification_token_expires: verificationTokenExpires,
      created_at: new Date()
    });

    const savedUser = await user.save();
    console.log('✅ User saved to MongoDB:', savedUser.email);

    // Send verification email
    const frontendUrl = process.env.FRONTEND_URL || 'https://minihaai.netlify.app';
    const verificationUrl = `${frontendUrl}/verify-email?token=${verificationToken}&email=${encodeURIComponent(email)}`;
    
    const emailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #e11d48;">Welcome to MinihaAI!</h2>
        <p>Hi ${user.name},</p>
        <p>Thank you for signing up! Please verify your email address by clicking the button below:</p>
        <a href="${verificationUrl}" style="display: inline-block; padding: 12px 24px; background-color: #e11d48; color: white; text-decoration: none; border-radius: 8px; margin: 20px 0;">Verify Email Address</a>
        <p>Or copy and paste this link into your browser:</p>
        <p style="color: #666; word-break: break-all;">${verificationUrl}</p>
        <p>This link will expire in 24 hours.</p>
        <p>If you didn't create an account, please ignore this email.</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="color: #999; font-size: 12px;">© 2025 MinihaAI. All rights reserved.</p>
      </div>
    `;
    
    await sendEmail(email, 'Verify your MinihaAI account', emailHtml);

    res.status(201).json({
      success: true,
      message: 'Account created! Please check your email to verify your account.',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        avatar: user.picture,
        isPremium: user.is_premium,
        emailVerified: user.email_verified
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

    // Check if email is verified (optional - you can make it required)
    if (!user.email_verified && user.provider === 'email') {
      return res.status(403).json({ 
        success: false, 
        message: 'Please verify your email address before logging in. Check your inbox for the verification link.',
        requiresVerification: true
      });
    }

    res.status(200).json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        avatar: user.picture,
        isPremium: user.is_premium,
        emailVerified: user.email_verified
      }
    });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ success: false, message: "Server error during login" });
  }
});

// --- EMAIL VERIFICATION ---
app.get('/api/auth/verify-email', async (req, res) => {
  const { token, email } = req.query;
  
  try {
    if (!token || !email) {
      return res.status(400).json({ success: false, message: 'Token and email are required' });
    }

    const user = await User.findOne({ 
      email,
      verification_token: token,
      verification_token_expires: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid or expired verification token' 
      });
    }

    user.email_verified = true;
    user.verification_token = undefined;
    user.verification_token_expires = undefined;
    await user.save();

    res.status(200).json({ 
      success: true, 
      message: 'Email verified successfully!' 
    });
  } catch (error) {
    console.error("Email Verification Error:", error);
    res.status(500).json({ success: false, message: "Email verification failed" });
  }
});

// Resend verification email
app.post('/api/auth/resend-verification', async (req, res) => {
  const { email } = req.body;
  
  try {
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.email_verified) {
      return res.status(400).json({ success: false, message: 'Email already verified' });
    }

    // Generate new verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationTokenExpires = new Date();
    verificationTokenExpires.setHours(verificationTokenExpires.getHours() + 24);

    user.verification_token = verificationToken;
    user.verification_token_expires = verificationTokenExpires;
    await user.save();

    // Send verification email
    const frontendUrl = process.env.FRONTEND_URL || 'https://minihaai.netlify.app';
    const verificationUrl = `${frontendUrl}/verify-email?token=${verificationToken}&email=${encodeURIComponent(email)}`;
    
    const emailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #e11d48;">Verify your MinihaAI account</h2>
        <p>Hi ${user.name},</p>
        <p>Please verify your email address by clicking the button below:</p>
        <a href="${verificationUrl}" style="display: inline-block; padding: 12px 24px; background-color: #e11d48; color: white; text-decoration: none; border-radius: 8px; margin: 20px 0;">Verify Email Address</a>
        <p>Or copy and paste this link into your browser:</p>
        <p style="color: #666; word-break: break-all;">${verificationUrl}</p>
        <p>This link will expire in 24 hours.</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="color: #999; font-size: 12px;">© 2025 MinihaAI. All rights reserved.</p>
      </div>
    `;
    
    await sendEmail(email, 'Verify your MinihaAI account', emailHtml);

    res.status(200).json({ 
      success: true, 
      message: 'Verification email sent!' 
    });
  } catch (error) {
    console.error("Resend Verification Error:", error);
    res.status(500).json({ success: false, message: "Failed to send verification email" });
  }
});

// --- PASSWORD RESET ---
// Request password reset
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  try {
    const user = await User.findOne({ email });
    
    // Don't reveal if user exists (security best practice)
    if (!user) {
      return res.status(200).json({ 
        success: true, 
        message: 'If an account exists with this email, a password reset link has been sent.' 
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = new Date();
    resetTokenExpires.setHours(resetTokenExpires.getHours() + 1); // 1 hour expiry

    user.reset_password_token = resetToken;
    user.reset_password_expires = resetTokenExpires;
    await user.save();

    // Send reset email
    const frontendUrl = process.env.FRONTEND_URL || 'https://minihaai.netlify.app';
    const resetUrl = `${frontendUrl}/reset-password?token=${resetToken}&email=${encodeURIComponent(email)}`;
    
    const emailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #e11d48;">Reset your password</h2>
        <p>Hi ${user.name},</p>
        <p>You requested to reset your password. Click the button below to reset it:</p>
        <a href="${resetUrl}" style="display: inline-block; padding: 12px 24px; background-color: #e11d48; color: white; text-decoration: none; border-radius: 8px; margin: 20px 0;">Reset Password</a>
        <p>Or copy and paste this link into your browser:</p>
        <p style="color: #666; word-break: break-all;">${resetUrl}</p>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email and your password will remain unchanged.</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="color: #999; font-size: 12px;">© 2025 MinihaAI. All rights reserved.</p>
      </div>
    `;
    
    await sendEmail(email, 'Reset your MinihaAI password', emailHtml);

    res.status(200).json({ 
      success: true, 
      message: 'If an account exists with this email, a password reset link has been sent.' 
    });
  } catch (error) {
    console.error("Forgot Password Error:", error);
    res.status(500).json({ success: false, message: "Failed to send reset email" });
  }
});

// Reset password with token
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, email, newPassword } = req.body;
  
  try {
    if (!token || !email || !newPassword) {
      return res.status(400).json({ 
        success: false, 
        message: 'Token, email, and new password are required' 
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 6 characters' 
      });
    }

    const user = await User.findOne({ 
      email,
      reset_password_token: token,
      reset_password_expires: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid or expired reset token' 
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    user.password = hashedPassword;
    user.reset_password_token = undefined;
    user.reset_password_expires = undefined;
    await user.save();

    res.status(200).json({ 
      success: true, 
      message: 'Password reset successfully!' 
    });
  } catch (error) {
    console.error("Reset Password Error:", error);
    res.status(500).json({ success: false, message: "Password reset failed" });
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

// --- STRIPE PAYMENT ---
// Create Stripe Checkout Session
app.post('/api/payment/create-session', async (req, res) => {
  const { userId, amount } = req.body;
  
  try {
    if (!process.env.STRIPE_SECRET_KEY) {
      return res.status(500).json({ success: false, message: 'Stripe not configured' });
    }

    const user = await User.findOne({ id: userId });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Create or get Stripe customer
    let customerId = user.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: user.email,
        name: user.name,
        metadata: { userId: user.id }
      });
      customerId = customer.id;
      await User.findOneAndUpdate({ id: userId }, { stripe_customer_id: customerId });
    }

    // Create checkout session
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: 'MinihaAI Pro Plan',
            description: 'Unlimited humanizations and advanced features'
          },
          unit_amount: Math.round(parseFloat(amount.replace('$', '')) * 100) // Convert to cents
        },
        quantity: 1
      }],
      mode: 'payment',
      success_url: `${process.env.FRONTEND_URL || 'https://minihaai.netlify.app'}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL || 'https://minihaai.netlify.app'}/pricing`,
      metadata: { userId }
    });

    res.status(200).json({ 
      success: true, 
      sessionId: session.id,
      url: session.url 
    });
  } catch (error) {
    console.error("Stripe Session Error:", error);
    res.status(500).json({ success: false, message: "Payment session creation failed" });
  }
});

// Stripe webhook handler (for production)
app.post('/api/payment/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.metadata.userId;

    // Update user to premium
    await User.findOneAndUpdate({ id: userId }, { is_premium: true });

    // Record transaction
    const transaction = new Transaction({
      id: uuidv4(),
      user_id: userId,
      amount: `$${(session.amount_total / 100).toFixed(2)}`,
      status: 'Paid',
      date: new Date(),
      invoice_id: `#INV-${session.id.substring(0, 8)}`,
      plan_type: 'Pro Plan',
      stripe_payment_intent_id: session.payment_intent,
      stripe_customer_id: session.customer
    });
    
    await transaction.save();
    console.log('✅ Payment processed for user:', userId);
  }

  res.json({ received: true });
});

// Verify payment and upgrade user (for frontend callback)
app.post('/api/payment/verify', async (req, res) => {
  const { sessionId } = req.body;
  
  try {
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    
    if (session.payment_status === 'paid') {
      const userId = session.metadata.userId;
      
      // Update user to premium
      await User.findOneAndUpdate({ id: userId }, { is_premium: true });
      
      // Check if transaction already exists
      let transaction = await Transaction.findOne({ stripe_payment_intent_id: session.payment_intent });
      
      if (!transaction) {
        transaction = new Transaction({
          id: uuidv4(),
          user_id: userId,
          amount: `$${(session.amount_total / 100).toFixed(2)}`,
          status: 'Paid',
          date: new Date(),
          invoice_id: `#INV-${session.id.substring(0, 8)}`,
          plan_type: 'Pro Plan',
          stripe_payment_intent_id: session.payment_intent,
          stripe_customer_id: session.customer
        });
        await transaction.save();
      }

      const user = await User.findOne({ id: userId });
      
      res.status(200).json({ 
        success: true, 
        message: 'Payment successful!',
        user: {
          id: user.id,
          isPremium: user.is_premium
        },
        transaction
      });
    } else {
      res.status(400).json({ success: false, message: 'Payment not completed' });
    }
  } catch (error) {
    console.error("Payment Verification Error:", error);
    res.status(500).json({ success: false, message: "Payment verification failed" });
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
        isPremium: user.is_premium,
        emailVerified: user.email_verified || true // Google users are auto-verified
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
