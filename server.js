/**
 * BACKEND SERVER CODE (Node.js / Express / MongoDB)
 * 
 * Dependencies: npm install express cors body-parser mongoose dotenv uuid bcryptjs
 * Run: node server.js
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3001;

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
  mobile_number: { type: String },
  provider: { type: String, default: 'email' },
  is_premium: { type: Boolean, default: false },
  premium_expires_at: { type: Date },
  email_verified: { type: Boolean, default: false },
  verification_token: { type: String },
  verification_token_expires: { type: Date },
  reset_password_token: { type: String },
  reset_password_expires: { type: Date },
  otp_code: { type: String },
  otp_expires: { type: Date },
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
  payment_method: { type: String, default: 'simulation' }
});

const paymentRequestSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  user_id: { type: String, required: true },
  user_email: { type: String, required: true },
  user_name: { type: String },
  amount: { type: String, required: true },
  payment_id: { type: String, required: true },
  payment_receipt: { type: String }, // Receipt screenshot/image URL or text
  payment_method: { type: String, default: 'manual' },
  status: { type: String, default: 'pending', enum: ['pending', 'approved', 'rejected'] },
  admin_notes: { type: String },
  submitted_at: { type: Date, default: Date.now },
  reviewed_at: { type: Date },
  reviewed_by: { type: String }
});

const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const PaymentRequest = mongoose.model('PaymentRequest', paymentRequestSchema);

// Helper function to check and update expired premium status
const checkAndUpdatePremiumExpiration = async (user) => {
  if (!user || !user.is_premium) {
    return user;
  }

  // If premium_expires_at is set and has passed, expire the premium
  if (user.premium_expires_at && new Date() > user.premium_expires_at) {
    user.is_premium = false;
    user.premium_expires_at = null;
    await user.save();
    console.log(`⏰ Premium expired for user: ${user.email} (${user.id})`);
  }

  return user;
};

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
  'https://minihaai.vercel.app',
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

    // Send response immediately (don't wait for email)
    res.status(201).json({
      success: true,
      message: 'Account created successfully! Please check your email to verify your account.',
      user: {
        id: savedUser.id,
        name: savedUser.name,
        email: savedUser.email,
        avatar: savedUser.picture,
        isPremium: savedUser.is_premium,
        emailVerified: savedUser.email_verified,
        createdAt: savedUser.created_at || null
      }
    });

    // Send verification email in the background (non-blocking)
    // This doesn't delay the response to the user
    (async () => {
      try {
        const frontendUrl = process.env.FRONTEND_URL || 'https://minihaai.vercel.app';
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
        
        const emailResult = await sendEmail(email, 'Verify your MinihaAI account', emailHtml);
        
        if (emailResult.success) {
          console.log('✅ Verification email sent successfully to:', email);
        } else {
          console.error('❌ Failed to send verification email:', emailResult.message || emailResult.error);
        }
      } catch (error) {
        console.error('❌ Error sending verification email in background:', error);
        // Email failure doesn't affect user signup - they can resend later
      }
    })();
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

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }

    // Email verification is optional - users can login without verification
    // If you want to require verification, uncomment the code below:
    /*
    if (!user.email_verified && user.provider === 'email') {
      return res.status(403).json({ 
        success: false, 
        message: 'Please verify your email address before logging in. Check your inbox for the verification link.',
        requiresVerification: true
      });
    }
    */

    // Check and update premium expiration
    await checkAndUpdatePremiumExpiration(user);
    const updatedUser = await User.findOne({ id: user.id });

    res.status(200).json({
      success: true,
      user: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        avatar: updatedUser.picture,
        isPremium: updatedUser.is_premium,
        emailVerified: updatedUser.email_verified,
        premiumExpiresAt: updatedUser.premium_expires_at || null,
        createdAt: updatedUser.created_at || null
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
    const frontendUrl = process.env.FRONTEND_URL || 'https://minihaai.vercel.app';
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
    
    const emailResult = await sendEmail(email, 'Verify your MinihaAI account', emailHtml);
    
    if (!emailResult.success) {
      console.error('❌ Failed to resend verification email:', emailResult.message || emailResult.error);
      return res.status(500).json({ 
        success: false, 
        message: emailResult.message || 'Failed to send verification email. Please check email configuration.' 
      });
    }

    res.status(200).json({ 
      success: true, 
      message: 'Verification email sent!' 
    });
  } catch (error) {
    console.error("Resend Verification Error:", error);
    res.status(500).json({ success: false, message: "Failed to send verification email" });
  }
});

// --- PASSWORD RESET WITH MOBILE NUMBER & OTP ---
// Request OTP via mobile number
app.post('/api/auth/forgot-password', async (req, res) => {
  const { mobileNumber, email } = req.body;
  
  try {
    if (!mobileNumber || !email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Mobile number and email are required' 
      });
    }

    // Find user by email
    const user = await User.findOne({ email });
    
    // Don't reveal if user exists (security best practice)
    if (!user) {
      return res.status(200).json({ 
        success: true, 
        message: 'If an account exists with this email and mobile number, an OTP has been sent.' 
      });
    }

    // Verify mobile number matches (if user has mobile number stored)
    if (user.mobile_number && user.mobile_number !== mobileNumber) {
      return res.status(200).json({ 
        success: true, 
        message: 'If an account exists with this email and mobile number, an OTP has been sent.' 
      });
    }

    // Generate 6-digit OTP
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date();
    otpExpires.setMinutes(otpExpires.getMinutes() + 10); // 10 minutes expiry

    // Store OTP and update mobile number if not set
    user.otp_code = otpCode;
    user.otp_expires = otpExpires;
    if (!user.mobile_number) {
      user.mobile_number = mobileNumber;
    }
    await user.save();

    // Send OTP via SMS service (WORKS GLOBALLY - All Countries)
    // Using Twilio Verify API (RECOMMENDED - Best for OTP verification)
    // Fallback: AWS SNS or manual OTP storage
    
    let smsSent = false;
    let smsError = null;

    // Helper function to format international phone number
    const formatInternationalNumber = (number) => {
      // Remove all non-digit characters except +
      let cleaned = number.replace(/[^\d+]/g, '');
      
      // If it doesn't start with +, we need to add country code
      if (!cleaned.startsWith('+')) {
        // Check if it starts with 00 (international format)
        if (cleaned.startsWith('00')) {
          cleaned = '+' + cleaned.substring(2);
        } else {
          // If no country code, return as is (will be validated)
          return cleaned;
        }
      }
      
      return cleaned;
    };

    const formattedNumber = formatInternationalNumber(mobileNumber);

    // Validate that number has country code for international support
    if (!formattedNumber.startsWith('+')) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please include country code with your mobile number (e.g., +1234567890 for US, +919876543210 for India)' 
      });
    }

    // Try Twilio Verify API first (BEST for OTP - works in all countries)
    if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_VERIFY_SERVICE_SID) {
      try {
        const twilio = require('twilio');
        const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

        // Use Twilio Verify API to send OTP
        await client.verify.v2
          .services(process.env.TWILIO_VERIFY_SERVICE_SID)
          .verifications
          .create({ to: formattedNumber, channel: 'sms' });
        
        // Store the verification SID for later verification
        // Note: With Twilio Verify, we don't need to store OTP manually
        // Twilio handles the OTP generation and verification
        smsSent = true;
        console.log(`✅ OTP sent via Twilio Verify to ${formattedNumber} (International)`);
        
        // Return success - Twilio will handle OTP verification
        return res.status(200).json({ 
          success: true, 
          message: 'OTP has been sent to your mobile number. Please check your phone.',
          useTwilioVerify: true // Flag to indicate we're using Twilio Verify
        });
      } catch (error) {
        console.error('❌ Twilio Verify Error:', error.message);
        smsError = error.message;
      }
    }

    // Fallback: Try regular Twilio SMS (if Verify service not configured)
    if (!smsSent && process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_PHONE_NUMBER) {
      try {
        const twilio = require('twilio');
        const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

        await client.messages.create({
          body: `Your MinihaAI password reset OTP is: ${otpCode}. Valid for 10 minutes.`,
          to: formattedNumber,
          from: process.env.TWILIO_PHONE_NUMBER
        });
        
        smsSent = true;
        console.log(`✅ OTP sent via Twilio SMS to ${formattedNumber} (International)`);
      } catch (error) {
        console.error('❌ Twilio SMS Error:', error.message);
        smsError = error.message;
      }
    }

    // Try AWS SNS if Twilio failed or not configured
    if (!smsSent && process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY && process.env.AWS_REGION) {
      try {
        const AWS = require('aws-sdk');
        const sns = new AWS.SNS({
          accessKeyId: process.env.AWS_ACCESS_KEY_ID,
          secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
          region: process.env.AWS_REGION || 'us-east-1'
        });

        const params = {
          Message: `Your MinihaAI password reset OTP is: ${otpCode}. Valid for 10 minutes.`,
          PhoneNumber: formattedNumber
        };

        await sns.publish(params).promise();
        smsSent = true;
        console.log(`✅ OTP sent via AWS SNS to ${formattedNumber} (International)`);
      } catch (error) {
        console.error('❌ AWS SNS Error:', error.message);
        smsError = error.message;
      }
    }

    // Fallback: Log OTP if no SMS service configured (development mode)
    if (!smsSent) {
      console.log(`📱 OTP for ${email} (${mobileNumber}): ${otpCode}`);
      console.log('⚠️  No SMS service configured. OTP logged for development. OTP expires in 10 minutes.');
      if (smsError) {
        console.log('⚠️  SMS service error:', smsError);
      }
      
      // Return success with OTP for development (manual verification will be used)
      return res.status(200).json({ 
        success: true, 
        message: 'OTP has been sent to your mobile number. Please check your phone.',
        // Remove this in production - only for development
        ...(process.env.NODE_ENV === 'development' && { otpCode })
      });
    }

    // If SMS was sent via non-Verify method, return success
    res.status(200).json({ 
      success: true, 
      message: 'OTP has been sent to your mobile number. Please check your phone.',
      // Remove this in production - only for development
      ...(process.env.NODE_ENV === 'development' && { otpCode })
    });
  } catch (error) {
    console.error("Send OTP Error:", error);
    res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
});

// Verify OTP
app.post('/api/auth/verify-otp', async (req, res) => {
  const { email, otpCode, mobileNumber, useTwilioVerify } = req.body;
  
  try {
    if (!email || !otpCode) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and OTP code are required' 
      });
    }

    // If using Twilio Verify API, verify with Twilio first
    if (useTwilioVerify && process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_VERIFY_SERVICE_SID && mobileNumber) {
      try {
        const twilio = require('twilio');
        const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

        // Format mobile number
        let formattedNumber = mobileNumber.replace(/[^\d+]/g, '');
        if (!formattedNumber.startsWith('+')) {
          if (formattedNumber.startsWith('00')) {
            formattedNumber = '+' + formattedNumber.substring(2);
          } else {
            formattedNumber = '+' + formattedNumber;
          }
        }

        // Verify OTP with Twilio
        const verificationCheck = await client.verify.v2
          .services(process.env.TWILIO_VERIFY_SERVICE_SID)
          .verificationChecks
          .create({ to: formattedNumber, code: otpCode });

        if (verificationCheck.status === 'approved') {
          // Find user by email
          const user = await User.findOne({ email });
          
          if (!user) {
            return res.status(404).json({ 
              success: false, 
              message: 'User not found' 
            });
          }

          // Generate reset token for password reset
          const resetToken = crypto.randomBytes(32).toString('hex');
          const resetTokenExpires = new Date();
          resetTokenExpires.setHours(resetTokenExpires.getHours() + 1); // 1 hour expiry

          user.reset_password_token = resetToken;
          user.reset_password_expires = resetTokenExpires;
          user.otp_code = undefined; // Clear OTP if exists
          user.otp_expires = undefined;
          await user.save();

          return res.status(200).json({ 
            success: true, 
            message: 'OTP verified successfully',
            resetToken: resetToken
          });
        } else {
          return res.status(400).json({ 
            success: false, 
            message: 'Invalid or expired OTP code' 
          });
        }
      } catch (error) {
        console.error('❌ Twilio Verify Check Error:', error.message);
        return res.status(400).json({ 
          success: false, 
          message: error.message || 'Invalid or expired OTP code' 
        });
      }
    }

    // Fallback: Manual OTP verification (for non-Twilio Verify or fallback)
    const user = await User.findOne({ 
      email,
      otp_code: otpCode,
      otp_expires: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid or expired OTP code' 
      });
    }

    // Generate reset token for password reset
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = new Date();
    resetTokenExpires.setHours(resetTokenExpires.getHours() + 1); // 1 hour expiry

    user.reset_password_token = resetToken;
    user.reset_password_expires = resetTokenExpires;
    user.otp_code = undefined; // Clear OTP after verification
    user.otp_expires = undefined;
    await user.save();

    res.status(200).json({ 
      success: true, 
      message: 'OTP verified successfully',
      resetToken: resetToken
    });
  } catch (error) {
    console.error("Verify OTP Error:", error);
    res.status(500).json({ success: false, message: "OTP verification failed" });
  }
});

// Reset password with token - Available for ANY user with valid token
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, email, newPassword, confirmPassword } = req.body;
  
  try {
    if (!token || !email || !newPassword || !confirmPassword) {
      return res.status(400).json({ 
        success: false, 
        message: 'Token, email, new password, and confirm password are required' 
      });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ 
        success: false, 
        message: 'Passwords do not match' 
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 6 characters' 
      });
    }

    // Find user by email and valid token - works for ANY user
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

// Change password - For logged-in users
app.post('/api/auth/change-password', async (req, res) => {
  const { userId, currentPassword, newPassword } = req.body;
  
  try {
    if (!userId || !currentPassword || !newPassword) {
      return res.status(400).json({ 
        success: false, 
        message: 'User ID, current password, and new password are required' 
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: 'New password must be at least 6 characters' 
      });
    }

    // Find user by userId
    const user = await User.findOne({ id: userId });

    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    
    if (!isCurrentPasswordValid) {
      return res.status(400).json({ 
        success: false, 
        message: 'Current password is incorrect' 
      });
    }

    // Check if new password is different from current password
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({ 
        success: false, 
        message: 'New password must be different from current password' 
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    user.password = hashedPassword;
    await user.save();

    console.log('✅ Password changed for user:', userId);

    res.status(200).json({ 
      success: true, 
      message: 'Password changed successfully!' 
    });
  } catch (error) {
    console.error("Change Password Error:", error);
    res.status(500).json({ success: false, message: "Password change failed" });
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

// --- MANUAL PAYMENT REQUEST ---
// Submit payment request (user submits payment ID/receipt)
app.post('/api/payment/submit', async (req, res) => {
  const { userId, paymentId, paymentReceipt, amount } = req.body;
  
  try {
    if (!userId || !paymentId) {
      return res.status(400).json({ success: false, message: 'User ID and Payment ID are required' });
    }

    const user = await User.findOne({ id: userId });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Check if user already has a pending payment request
    const existingRequest = await PaymentRequest.findOne({ 
      user_id: userId, 
      status: 'pending' 
    });

    if (existingRequest) {
      return res.status(400).json({ 
        success: false, 
        message: 'You already have a pending payment request. Please wait for admin approval.' 
      });
    }

    // Create payment request
    const requestId = uuidv4();
    const paymentRequest = new PaymentRequest({
      id: requestId,
      user_id: userId,
      user_email: user.email,
      user_name: user.name,
      amount: amount || '$5.00',
      payment_id: paymentId,
      payment_receipt: paymentReceipt || '',
      payment_method: 'manual',
      status: 'pending',
      submitted_at: new Date()
    });

    await paymentRequest.save();

    console.log('✅ Payment request submitted:', requestId);

    res.status(200).json({ 
      success: true, 
      message: 'Payment request submitted successfully! Admin will review and approve your Pro plan.',
      requestId: requestId
    });
  } catch (error) {
    console.error("Payment Request Error:", error);
    res.status(500).json({ success: false, message: "Failed to submit payment request" });
  }
});

// --- ADMIN: Get all pending payment requests ---
app.get('/api/admin/payments', async (req, res) => {
  const { adminPassword } = req.query;
  
  // Simple admin authentication (in production, use proper auth)
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
  
  if (adminPassword !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }

  try {
    const pendingPayments = await PaymentRequest.find({ status: 'pending' })
      .sort({ submitted_at: -1 });
    
    const allPayments = await PaymentRequest.find()
      .sort({ submitted_at: -1 })
      .limit(100);

    res.status(200).json({ 
      success: true, 
      pending: pendingPayments,
      all: allPayments
    });
  } catch (error) {
    console.error("Admin Payments Error:", error);
    res.status(500).json({ success: false, message: "Error fetching payment requests" });
  }
});

// --- ADMIN: Approve payment request ---
app.post('/api/admin/payments/approve', async (req, res) => {
  const { requestId, adminPassword, adminNotes } = req.body;
  
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
  
  if (adminPassword !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }

  try {
    const paymentRequest = await PaymentRequest.findOne({ id: requestId });
    if (!paymentRequest) {
      return res.status(404).json({ success: false, message: 'Payment request not found' });
    }

    if (paymentRequest.status !== 'pending') {
      return res.status(400).json({ success: false, message: 'Payment request already processed' });
    }

    // Update payment request
    paymentRequest.status = 'approved';
    paymentRequest.reviewed_at = new Date();
    paymentRequest.reviewed_by = 'admin';
    paymentRequest.admin_notes = adminNotes || '';
    await paymentRequest.save();

    // Calculate expiration date (30 days from now)
    const expirationDate = new Date();
    expirationDate.setDate(expirationDate.getDate() + 30);

    // Update user to premium with 30-day expiration
    await User.findOneAndUpdate(
      { id: paymentRequest.user_id }, 
      { 
        is_premium: true,
        premium_expires_at: expirationDate
      }
    );

    // Create transaction record
    const transactionId = uuidv4();
    const transaction = new Transaction({
      id: transactionId,
      user_id: paymentRequest.user_id,
      amount: paymentRequest.amount,
      status: 'Paid',
      date: new Date(),
      invoice_id: `#INV-${transactionId.substring(0, 8).toUpperCase()}`,
      plan_type: 'Pro Plan',
      payment_method: 'manual'
    });
    await transaction.save();

    console.log('✅ Payment approved:', requestId, 'User:', paymentRequest.user_id);

    res.status(200).json({ 
      success: true, 
      message: 'Payment approved and user upgraded to Pro plan',
      paymentRequest,
      transaction
    });
  } catch (error) {
    console.error("Approve Payment Error:", error);
    res.status(500).json({ success: false, message: "Failed to approve payment" });
  }
});

// --- ADMIN: Reject payment request ---
app.post('/api/admin/payments/reject', async (req, res) => {
  const { requestId, adminPassword, adminNotes } = req.body;
  
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
  
  if (adminPassword !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }

  try {
    const paymentRequest = await PaymentRequest.findOne({ id: requestId });
    if (!paymentRequest) {
      return res.status(404).json({ success: false, message: 'Payment request not found' });
    }

    if (paymentRequest.status !== 'pending') {
      return res.status(400).json({ success: false, message: 'Payment request already processed' });
    }

    paymentRequest.status = 'rejected';
    paymentRequest.reviewed_at = new Date();
    paymentRequest.reviewed_by = 'admin';
    paymentRequest.admin_notes = adminNotes || '';
    await paymentRequest.save();

    console.log('❌ Payment rejected:', requestId);

    res.status(200).json({ 
      success: true, 
      message: 'Payment request rejected',
      paymentRequest
    });
  } catch (error) {
    console.error("Reject Payment Error:", error);
    res.status(500).json({ success: false, message: "Failed to reject payment" });
  }
});

// --- Get user's payment request status ---
app.get('/api/payment/status/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Check for any recent payment requests (pending or approved)
    const paymentRequest = await PaymentRequest.findOne({ 
      user_id: userId
    }).sort({ submitted_at: -1 });

    // Get current user to check premium status
    const user = await User.findOne({ id: userId });
    
    let isPremium = false;
    if (user) {
      // Check and update premium expiration
      await checkAndUpdatePremiumExpiration(user);
      const updatedUser = await User.findOne({ id: userId });
      isPremium = updatedUser?.is_premium || false;
    }

    if (!paymentRequest) {
      return res.status(200).json({ 
        success: true, 
        hasPending: false,
        isPremium: isPremium
      });
    }

    res.status(200).json({ 
      success: true, 
      hasPending: paymentRequest.status === 'pending',
      isPremium: isPremium,
      paymentRequest: {
        id: paymentRequest.id,
        status: paymentRequest.status,
        submitted_at: paymentRequest.submitted_at,
        amount: paymentRequest.amount,
        reviewed_at: paymentRequest.reviewed_at
      }
    });
  } catch (error) {
    console.error("Payment Status Error:", error);
    res.status(500).json({ success: false, message: "Error fetching payment status" });
  }
});

// --- FREE SIMULATION PAYMENT (Keep for direct payment option) ---
// Process payment (simulation - no real payment processor needed)
app.post('/api/payment/process', async (req, res) => {
  const { userId, amount } = req.body;
  
  try {
    const user = await User.findOne({ id: userId });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Simulate payment processing delay
    await new Promise(resolve => setTimeout(resolve, 1500));

    // Calculate expiration date (30 days from now)
    const expirationDate = new Date();
    expirationDate.setDate(expirationDate.getDate() + 30);

    // Update user to premium with 30-day expiration
    await User.findOneAndUpdate(
      { id: userId }, 
      { 
        is_premium: true,
        premium_expires_at: expirationDate
      }
    );

    // Record transaction
    const transactionId = uuidv4();
    const transaction = new Transaction({
      id: transactionId,
      user_id: userId,
      amount: amount || '$9.99',
      status: 'Paid',
      date: new Date(),
      invoice_id: `#INV-${transactionId.substring(0, 8).toUpperCase()}`,
      plan_type: 'Pro Plan',
      payment_method: 'simulation'
    });
    
    await transaction.save();
    
    const updatedUser = await User.findOne({ id: userId });

    console.log('✅ Payment processed (simulation) for user:', userId);

    res.status(200).json({ 
      success: true, 
      message: 'Payment successful!',
      user: {
        id: updatedUser.id,
        isPremium: updatedUser.is_premium
      },
      transaction
    });
  } catch (error) {
    console.error("Payment Processing Error:", error);
    res.status(500).json({ success: false, message: "Payment processing failed" });
  }
});

// --- GET USER BY ID ---
// --- GEMINI API PROXY (Secure - API key on backend only) ---
// Initialize Gemini client
const getGeminiClient = () => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('GEMINI_API_KEY not configured');
  }
  return new GoogleGenerativeAI(apiKey);
};

// Cache for available models
let availableModelsCache = null;
let modelsCacheTime = 0;
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// Get available models from API
const getAvailableModels = async (apiKey) => {
  const now = Date.now();
  if (availableModelsCache && (now - modelsCacheTime) < CACHE_DURATION) {
    return availableModelsCache;
  }

  try {
    const url = `https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`;
    const response = await axios.get(url);
    const models = (response.data.models || [])
      .filter(m => m.supportedGenerationMethods?.includes('generateContent'))
      .map(m => m.name.replace('models/', ''));
    
    availableModelsCache = models;
    modelsCacheTime = now;
    console.log(`📋 Available models: ${models.join(', ')}`);
    return models;
  } catch (error) {
    console.log('⚠️ Could not fetch available models, using defaults');
    // Fallback to default models
    return ['gemini-pro', 'gemini-1.5-flash', 'gemini-1.5-pro'];
  }
};

// Use REST API directly for better control and error handling
const callGeminiAPI = async (prompt, config = {}) => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('GEMINI_API_KEY not configured');
  }

  // Get available models dynamically
  let availableModels = await getAvailableModels(apiKey);
  const errors = [];
  
  // OPTIMIZED: Prioritize faster models first (Flash is faster than Pro)
  availableModels = availableModels.sort((a, b) => {
    // Prioritize flash models for speed
    if (a.includes('flash') && !b.includes('flash')) return -1;
    if (!a.includes('flash') && b.includes('flash')) return 1;
    // If same type, keep original order
    return 0;
  });
  
  for (const modelName of availableModels) {
    try {
      // Use v1beta API (standard for Gemini)
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey}`;
      
      const response = await axios.post(url, {
        contents: [{
          parts: [{ text: prompt }]
        }],
        generationConfig: {
          temperature: config.temperature || 0.9,
          topP: config.topP || 0.95,
          topK: config.topK || 40,
          maxOutputTokens: config.maxOutputTokens || 8192, // Limit tokens for faster response
          ...(config.responseMimeType && { responseMimeType: config.responseMimeType }),
          ...Object.fromEntries(Object.entries(config).filter(([k]) => !['temperature', 'topP', 'topK', 'responseMimeType', 'maxOutputTokens'].includes(k)))
        }
      }, {
        headers: {
          'Content-Type': 'application/json',
        },
        timeout: 45000 // 45 second timeout (reduced from default for faster failure)
      });

      const data = response.data;
      if (data.candidates && data.candidates[0] && data.candidates[0].content) {
        console.log(`✅ Using model: ${modelName}`);
        return {
          text: data.candidates[0].content.parts[0].text,
          modelName
        };
      } else {
        errors.push(`${modelName}: Invalid response format`);
        console.log(`❌ Model ${modelName}: Invalid response format`);
      }
    } catch (error) {
      let errorMsg = error.message;
      if (error.response) {
        // Axios error with response
        const errorData = error.response.data || {};
        errorMsg = errorData.error?.message || error.response.statusText || error.message;
        errors.push(`${modelName}: ${error.response.status} - ${errorMsg}`);
        console.log(`❌ Model ${modelName} failed: ${error.response.status} - ${errorMsg}`);
      } else {
        errors.push(`${modelName}: ${errorMsg}`);
        console.log(`❌ Model ${modelName} error: ${errorMsg}`);
      }
      continue;
    }
  }
  
  // Return detailed error with all attempted models
  throw new Error(`All Gemini models failed. Errors: ${errors.join('; ')}. Please check your API key in Railway and verify it's active in Google AI Studio.`);
};

// Helper functions
const preprocessText = (text) => {
  return text
    .replace(/\*\*/g, '') // Remove bold markdown
    .replace(/```[\s\S]*?```/g, '') // Remove code blocks
    .replace(/`([^`]+)`/g, '$1') // Remove inline code
    .trim();
};

const postprocessText = (text) => {
  let result = text.trim();
  
  // Remove all markdown formatting - do this first
  result = result.replace(/```[\s\S]*?```/g, ''); // Remove code blocks first
  result = result.replace(/`([^`]+)`/g, '$1'); // Remove inline code
  result = result.replace(/\*\*/g, ''); // Remove bold **text** (double asterisks)
  result = result.replace(/\*/g, ''); // Remove ALL single asterisks (italic *text* and standalone *)
  result = result.replace(/__/g, ''); // Remove bold __text__
  result = result.replace(/_/g, ''); // Remove italic _text_ and single underscores
  result = result.replace(/~~/g, ''); // Remove strikethrough ~~text~~
  result = result.replace(/#{1,6}\s/g, ''); // Remove markdown headers (# ## ###)
  result = result.replace(/\[([^\]]+)\]\([^\)]+\)/g, '$1'); // Convert [link](url) to just "link"
  
  // Remove any remaining formatting characters
  result = result.replace(/`/g, ''); // Remove any remaining backticks
  
  // Remove quotes around text
  result = result.replace(/^["']|["']$/g, '');
  
  // Clean up excessive newlines
  result = result.replace(/\n{3,}/g, '\n\n');
  
  // Remove any remaining asterisks in various patterns (safety check)
  result = result.replace(/\s\*\s/g, ' '); // Remove " * " patterns
  result = result.replace(/\*\s/g, ''); // Remove "* " at start of words
  result = result.replace(/\s\*/g, ''); // Remove " *" at end of words
  result = result.replace(/\*/g, ''); // Final pass - remove ANY remaining asterisks
  
  // Clean up multiple spaces that may have been created
  result = result.replace(/\s{2,}/g, ' ');
  
  // Clean up spaces around punctuation
  result = result.replace(/\s+([.,!?;:])/g, '$1');
  
  return result.trim();
};

// Helper functions for tone, vocabulary, and intensity settings
const getToneInstructions = (tone) => {
  const toneMap = {
    'Standard': `TONE: Standard/Balanced
- Write in a balanced, clear, and straightforward manner
- Use a mix of formal and casual language naturally
- Maintain professional clarity without being overly formal
- Sound like an educated, thoughtful person writing naturally
- Use contractions moderately (30-40%)
- Include occasional personal touches: "I think", "It seems", "You might notice"
- Keep it engaging but not overly casual or formal`,

    'Casual': `TONE: Casual/Conversational
- Write like you're talking to a friend - relaxed and natural
- Use contractions frequently (60-70%): "don't", "can't", "won't", "it's", "that's", "we're"
- Add conversational fillers naturally: "you know", "I mean", "like", "sort of", "kind of"
- Use casual transitions: "Plus", "Also", "And", "But", "So", "Then", "Now", "Well", "Actually"
- Include personal touches: "I think", "I've noticed", "You might", "Honestly", "Really"
- Use "you" and "we" frequently - make it feel like a conversation
- Add occasional uncertainty: "maybe", "perhaps", "might", "could be", "I guess", "probably"
- Keep sentences shorter and more direct
- Use exclamation marks occasionally for enthusiasm
- Sound friendly and approachable, like a real person chatting`,

    'Professional': `TONE: Professional/Business
- Write in a polished, business-appropriate style
- Use contractions sparingly (20-30%) - more formal but still natural
- Maintain professional clarity and precision
- Use "we" and "you" appropriately for business context
- Include professional phrases: "It's important to note", "One consideration is", "A key point is"
- Keep transitions professional but natural: "Additionally", "However", "Therefore", "In this case"
- Avoid overly casual language but don't sound robotic
- Use active voice for clarity and impact
- Sound like a skilled professional writing naturally, not a corporate robot
- Maintain authority while being approachable`,

    'Academic': `TONE: Academic/Scholarly
- Write in a scholarly, analytical style appropriate for academic work
- Use contractions minimally (10-20%) - more formal structure
- Employ academic vocabulary appropriately but naturally
- Use "one" and passive voice more frequently (40-50% passive) for academic style
- Include analytical phrases: "It can be observed that", "One might argue", "This suggests that", "It appears that"
- Use transitions: "Furthermore", "However", "Consequently", "In contrast", "Similarly"
- Maintain objectivity while showing critical thinking
- Use longer, more complex sentences (but still vary them)
- Sound like a thoughtful academic writing naturally, not a textbook
- Balance formality with readability`,

    'Witty': `TONE: Witty/Clever
- Write with humor, cleverness, and personality
- Use contractions frequently (50-60%) for a lively feel
- Add witty observations and clever turns of phrase
- Include rhetorical questions for effect (3-4 per 500 words)
- Use unexpected word choices and playful language
- Add subtle humor and irony where appropriate
- Use dashes and parentheses for witty asides
- Include conversational elements: "you know", "I mean", "sort of"
- Make it engaging and entertaining while maintaining quality
- Sound like a clever, witty person writing naturally
- Use exclamation marks and question marks for emphasis`,

    'Empathetic': `TONE: Empathetic/Understanding
- Write with warmth, understanding, and emotional intelligence
- Use contractions moderately (40-50%) for a warm, approachable feel
- Include empathetic phrases: "I understand", "It's understandable that", "Many people feel", "You might be experiencing"
- Use "you" frequently to connect with the reader
- Add personal touches: "I've found", "In my experience", "What I've noticed"
- Use softer language and understanding transitions: "And", "But", "So", "Also", "Plus"
- Include questions that show understanding: "Have you ever noticed?", "Does this resonate?"
- Sound caring and understanding, like someone who truly gets it
- Use emotional language appropriately but authentically
- Make it feel supportive and human`,

    'Persuasive': `TONE: Persuasive/Convincing
- Write to persuade and convince while remaining natural
- Use contractions moderately (30-40%) for a balanced persuasive tone
- Employ persuasive techniques naturally: rhetorical questions, strong statements, compelling examples
- Use active voice for impact (80-90%)
- Include persuasive phrases: "Consider this", "Think about it", "Here's the thing", "The key point is"
- Use transitions that build argument: "And", "But", "So", "Plus", "Also", "Now", "Here's why"
- Add personal conviction: "I believe", "I'm convinced", "It's clear that", "The evidence shows"
- Use "you" to directly address the reader
- Sound confident and convincing, like someone who truly believes what they're saying
- Make compelling arguments while maintaining natural human voice
- Use questions strategically to engage and persuade`
  };
  return toneMap[tone] || toneMap['Standard'];
};

const getVocabularyInstructions = (vocabulary) => {
  const vocabMap = {
    'Simple (High School)': `VOCABULARY: Simple/High School Level
- Use everyday, accessible words that most people understand
- Avoid complex or technical terms unless necessary (and explain them if used)
- Use simple, direct language: "use" instead of "utilize", "help" instead of "facilitate", "show" instead of "demonstrate"
- Keep sentences clear and straightforward
- Use common words: "big" instead of "substantial", "good" instead of "beneficial", "bad" instead of "detrimental"
- Explain complex ideas in simple terms
- Use contractions frequently (50-60%) for naturalness
- Sound like an intelligent person writing simply, not condescending`,

    'Standard (College)': `VOCABULARY: Standard/College Level
- Use a balanced mix of everyday and more sophisticated words
- Employ appropriate vocabulary for educated readers
- Mix simple and complex words naturally: "use" and "utilize" both, "help" and "facilitate" both
- Use precise words when needed: "demonstrate" when appropriate, "show" when simpler works
- Balance accessibility with sophistication
- Use contractions moderately (30-40%)
- Sound like a well-educated person writing naturally
- Choose words that fit the context - not too simple, not too complex`,

    'Advanced (PhD)': `VOCABULARY: Advanced/PhD Level
- Use sophisticated, precise vocabulary appropriate for advanced readers
- Employ technical and academic terms when appropriate
- Use precise words: "utilize" when precise, "facilitate" when appropriate, "demonstrate" for clarity
- Include nuanced vocabulary: "substantial" when precise, "beneficial" when appropriate, "detrimental" when needed
- Use complex sentence structures naturally (but still vary them)
- Use contractions sparingly (20-30%) for more formal tone
- Sound like an expert writing naturally, not showing off
- Balance sophistication with clarity - don't be unnecessarily complex`
  };
  return vocabMap[vocabulary] || vocabMap['Standard (College)'];
};

const getIntensityInstructions = (intensity) => {
  const intensityLevel = parseInt(intensity) || 50;
  
  if (intensityLevel <= 30) {
    return `HUMANIZATION INTENSITY: Light (${intensityLevel}%)
- Apply subtle humanization - maintain more of the original structure
- Add moderate sentence variation (20% short, 50% medium, 30% long)
- Use fragments sparingly (3-5% of sentences)
- Add minimal imperfections - keep it polished
- Use contractions moderately
- Keep transitions more standard but still natural
- Maintain closer to original flow while adding human touches`;
  } else if (intensityLevel <= 70) {
    return `HUMANIZATION INTENSITY: Moderate (${intensityLevel}%)
- Apply balanced humanization - natural variation
- Mix sentence lengths: 30% short, 40% medium, 30% long
- Use fragments strategically (5-10% of sentences)
- Add moderate imperfections that feel natural
- Use contractions appropriately (30-50%)
- Vary transitions naturally
- Create natural flow with good variation`;
  } else {
    return `HUMANIZATION INTENSITY: Maximum (${intensityLevel}%)
- Apply aggressive humanization - maximum naturalness
- Heavy sentence variation: 35% short, 30% medium, 35% long
- Use fragments frequently (10-15% of sentences)
- Add more imperfections and natural quirks
- Use contractions frequently (50-70%)
- Vary transitions extensively - no repetition
- Create highly varied, natural flow
- Maximum sentence structure variation
- More personal touches and conversational elements
- More uncertainty markers: "maybe", "perhaps", "might", "could be"
- More natural imperfections and human quirks`;
  }
};

// Humanize text endpoint - OPTIMIZED 2-PASS VERSION (maintains quality, ~2x faster)
// Pass 1: Deep humanization with anti-detection rules
// Pass 2: Combined quality enhancement & final polish (merges previous passes 2, 3, 4)
app.post('/api/ai/humanize', async (req, res) => {
  try {
    const { text, tone = 'Standard', vocabulary = 'Standard (College)', intensity = 50 } = req.body;

    if (!text || !text.trim()) {
      return res.status(400).json({ success: false, message: 'Text is required' });
    }

    const cleanInput = preprocessText(text);
    // Higher temperature for maximum human-like variation (100% AI-free)
    const baseTemp = 1.0 + (intensity / 100) * 0.9;
    const temperature = Math.min(Math.max(baseTemp, 0.9), 2.0);

    // Get setting-specific instructions
    const toneInstructions = getToneInstructions(tone);
    const vocabInstructions = getVocabularyInstructions(vocabulary);
    const intensityInstructions = getIntensityInstructions(intensity);

    // Pass 1: Deep Humanization - Break AI Patterns & Create Natural Flow
    const promptPass1 = `You are an Elite Anti-Detection Ghostwriter with expertise in bypassing ALL AI detection systems.
Your mission: Rewrite this text to be 100% UNDETECTABLE by Turnitin, GPTZero, Originality.ai, Copyleaks, ZeroGPT, Content at Scale, Writer.com, Sapling, Winston AI, Crossplag, and ALL other detectors.

CRITICAL: The output must be 100% AI-FREE, HIGH QUALITY, natural, and completely human-written. This text must pass every AI detector with 0% detection rate. Maintain all meaning while making it completely undetectable.

${toneInstructions}

${vocabInstructions}

${intensityInstructions}

CRITICAL ANTI-DETECTION RULES (100% AI-FREE REQUIREMENTS):

1. SENTENCE STRUCTURE VARIATION (CRITICAL - AI DETECTORS LOOK FOR PATTERNS):
   - Mix sentence lengths aggressively based on intensity level above
   - NEVER have 3 consecutive sentences of similar length
   - Vary sentence beginnings randomly: Start with subjects, prepositions, conjunctions, adverbs, questions, fragments
   - Use fragments strategically based on intensity level (humans use fragments, AI rarely does)
   - Add occasional run-on sentences that feel natural (AI avoids these)
   - Break parallel structures completely - humans NEVER write perfectly parallel
   - Vary sentence complexity: simple, compound, complex, compound-complex randomly
   - Add occasional incomplete thoughts or trailing sentences
   - Use one-word sentences occasionally for emphasis

2. BANNED AI WORDS (NEVER USE - THESE ARE AI RED FLAGS):
   "delve", "tapestry", "realm", "landscape", "underscores", "crucial", "leverage", "utilize", "orchestrate", 
   "testament", "pivotal", "nuance", "foster", "harness", "unveil", "embark", "navigate", "unlock", 
   "catalyst", "cornerstone", "showcase", "facilitate", "endeavor", "paramount", "myriad", "plethora",
   "inherent", "intrinsic", "comprehensive", "robust", "seamless", "streamline", "optimize", "synergy",
   "delve into", "in the realm of", "it is worth noting", "it should be noted", "it is important to",
   "in order to", "with regard to", "in terms of", "as a result of", "due to the fact that"

3. BANNED AI TRANSITIONS (NEVER USE - INSTANT AI DETECTION):
   "Moreover", "Furthermore", "In conclusion", "Additionally", "Conversely", "Notably", "Thus", "Hence",
   "Consequently", "Accordingly", "Subsequently", "Nevertheless", "Nonetheless", "In essence", "To summarize",
   "In summary", "Ultimately", "In other words", "That is to say", "To begin with", "First and foremost",
   "Last but not least", "In the final analysis", "To put it simply", "In a nutshell"

4. USE HUMAN TRANSITIONS INSTEAD (based on tone - these sound natural):
   "Plus", "Also", "And", "But", "So", "Then", "Now", "Well", "Actually", "Honestly", "Really", "I mean",
   "You know", "Like", "Kind of", "Sort of", "Pretty much", "Basically", "Anyway", "Oh", "Yeah", "Right",
   "See", "Look", "I guess", "I suppose", "Or", "Though", "Still", "Yet", "Even so", "At the same time"

5. VOCABULARY & WORD CHOICE (CRITICAL FOR AI DETECTION):
   - Follow vocabulary level instructions above strictly
   - Use contractions based on tone instructions (AI underuses contractions)
   - Add filler words based on tone (casual tones use more) - AI avoids these
   - Use "really", "very", "pretty", "quite", "sort of", "kind of" naturally (humans overuse these, AI doesn't)
   - Avoid perfect synonyms - repeat words occasionally (humans do this, AI avoids it)
   - Use specific, concrete words instead of vague abstract ones when possible
   - Choose words that feel natural in context, not forced or overly formal
   - Vary word choice - don't use the same word twice in close proximity unless intentional
   - Use colloquialisms and informal expressions where appropriate
   - Mix formal and informal language naturally (AI tends to be consistent)
   - Use "thing", "stuff", "get", "go", "make" - simple words humans use frequently

6. GRAMMAR & PUNCTUATION (IMPERFECTIONS = HUMAN):
   - Allow intentional comma splices based on intensity (5-8% for moderate, 3-5% for light, 8-12% for maximum)
   - Use dashes (-) for emphasis, not just commas (AI underuses dashes)
   - Add occasional ellipses (...) for natural pauses (AI rarely uses these)
   - Use parentheses for asides (humans do this, AI rarely does)
   - Mix question marks and exclamation marks naturally
   - Don't fix every grammar "error" - keep some for authenticity
   - Use semicolons sparingly (humans rarely use them, AI overuses them)
   - Add occasional typos-like patterns: "its" vs "it's" confusion (but be careful)
   - Use sentence fragments that feel natural

7. PARAGRAPH STRUCTURE (CRITICAL - AI DETECTORS ANALYZE STRUCTURE):
   - Vary paragraph lengths dramatically: 1-10 sentences per paragraph (AI tends to be consistent)
   - Some paragraphs should be 1-2 sentences (humans do this, AI rarely does)
   - Some paragraphs should be longer (8-10 sentences) - AI tends to keep them medium
   - Don't always start paragraphs with topic sentences (AI always does this)
   - Bury main points in the middle of paragraphs sometimes (AI puts them at start/end)
   - End paragraphs with questions or incomplete thoughts occasionally
   - Start some paragraphs mid-thought or with a continuation
   - Mix short and long paragraphs randomly - no pattern

8. VOICE & TONE (HUMAN VOICE = UNDETECTABLE):
   - Follow tone instructions above strictly
   - Add personal touches based on tone (see tone instructions) - AI avoids personal touches
   - Use rhetorical questions based on tone (witty uses more, academic uses fewer) - AI underuses questions
   - Add conversational asides in parentheses (humans do this naturally, AI rarely does)
   - Use "we" and "you" based on tone instructions (AI overuses "one" and passive voice)
   - Include occasional uncertainty based on tone and intensity: "maybe", "perhaps", "might", "could be", "I think", "probably", "I guess", "I suppose" (AI is too confident)
   - Add subtle opinions or observations that show human thinking (AI avoids opinions)
   - Use active voice based on tone (persuasive uses more, academic uses less) - but vary it
   - Make the writing engaging and readable, not robotic
   - Add emotional language where appropriate (AI avoids emotions)
   - Use "I", "me", "my" occasionally to show personal perspective (AI avoids first person)
   - Include occasional self-corrections: "or rather", "I mean", "actually" (AI doesn't self-correct)

9. INFORMATION ORDER (DISORGANIZATION = HUMAN):
   - Don't always present information in logical order (AI is always logical)
   - Add tangents and return to main point (AI stays on topic)
   - Bury important info in the middle, not always at start/end (AI highlights important info)
   - Repeat ideas with different wording (humans do this, AI avoids repetition)
   - Jump between topics slightly (AI maintains strict coherence)
   - Add digressions that feel natural (AI avoids digressions)
   - Present information in a slightly scattered way (AI is too organized)

10. WRITING PATTERNS (BREAK AI PATTERNS):
    - Vary sentence openings: Never start 2 consecutive sentences the same way
    - Mix declarative, interrogative, imperative, exclamatory sentences
    - Use "and" and "but" to start sentences occasionally (AI avoids this)
    - Add interjections: "Oh", "Well", "Hmm", "Ah", "Huh" (AI never uses these)
    - Use repetition for emphasis (AI avoids repetition)
    - Include redundant phrases: "each and every", "first and foremost" (AI avoids redundancy)
    - Use idioms and colloquialisms naturally (AI struggles with idioms)
    - Add regional expressions or casual language (AI uses standard English)

11. FORMATTING (PLAIN TEXT = HUMAN):
    - NO bullet points, NO numbered lists (AI loves lists)
    - NO bold, NO headings, NO subheadings (AI uses structure)
    - NO markdown formatting (NO asterisks, NO underscores, NO backticks)
    - NO special characters for formatting
    - Continuous natural paragraphs only
    - Use line breaks sparingly
    - Write plain text only - no formatting symbols
    - NO emojis or special characters

12. AI DETECTION BYPASS TECHNIQUES (CRITICAL):
    - Add "thinking out loud" moments: "I'm thinking...", "Let me see...", "Hmm..."
    - Include self-doubt: "I'm not sure but...", "This might be wrong but...", "I could be mistaken but..."
    - Add personal anecdotes or examples (AI avoids personal stories)
    - Use specific numbers and dates (AI uses vague references)
    - Include cultural references or pop culture (AI avoids these)
    - Add humor or wit where appropriate (AI struggles with humor)
    - Use metaphors and similes naturally (AI overuses or underuses them)
    - Include contradictions or changing opinions (AI is consistent)
    - Add "stream of consciousness" moments (AI is too structured)

INPUT TEXT TO HUMANIZE:
"${cleanInput}"

Rewrite this text following ALL rules above, especially the TONE, VOCABULARY, and INTENSITY settings. This text MUST be 100% AI-FREE and pass ALL detectors with 0% detection rate. Make it sound like a real, skilled human wrote it in the specified tone and vocabulary level - natural, engaging, high-quality, and completely undetectable. Add human imperfections, personal touches, and natural variation. Maintain all original meaning while making it feel authentically human. This is critical - the output must be completely undetectable as AI.`;

    const result1 = await callGeminiAPI(promptPass1, {
      temperature: temperature,
      topP: 0.998, // Higher for more variation
      topK: 150, // Higher for more word variety
    });

    const draft1 = result1.text || '';
    if (!draft1) throw new Error('Phase 1 generation failed');

    // OPTIMIZED Pass 2: Combined Quality Enhancement & Final Polish (Merges Pass 2, 3, 4 into one efficient pass)
    const promptPass2 = `You are a Master Humanization Editor. This text MUST be 100% AI-FREE and pass ALL detectors. Perform final quality enhancement and polish in ONE pass.

SETTINGS:
- Tone: ${tone}
- Vocabulary: ${vocabulary}
- Intensity: ${intensity}%

${toneInstructions}

${vocabInstructions}

${intensityInstructions}

CRITICAL FINAL CHECKS (ALL IN ONE PASS):
1. SENTENCE VARIETY: Ensure NO two consecutive sentences share structure, length, or opening. Vary rhythm aggressively.
2. HUMAN IMPERFECTIONS: Add natural imperfections based on intensity (light: 3-4, moderate: 5-7, max: 7-10) - awkward phrases, slight contradictions, incomplete thoughts.
3. WORD REPETITION: Repeat key words 2-4 times naturally (humans repeat, AI doesn't).
4. TRANSITION VARIETY: Vary transitions constantly. Use simple ones: "Plus", "But", "So" (NOT "Moreover", "Furthermore").
5. PERSONAL TOUCHES: Add "maybe", "I think", "probably", "you know", "sort of" based on tone.
6. HUMAN QUIRKS: Include self-corrections ("or rather", "I mean"), thinking out loud ("Hmm...", "Well..."), personal asides in parentheses.
7. GRAMMAR IMPERFECTIONS: Keep intentional quirks (fragments, comma splices, run-ons) based on intensity.
8. PUNCTUATION VARIETY: Use dashes, ellipses, parentheses naturally.
9. REMOVE ROBOTIC PHRASES: Eliminate "In conclusion", "Furthermore", "Moreover", "Additionally" - these are AI red flags.
10. COHERENCE: Ideas flow logically but imperfectly - add slight disorganization.
11. TONE/VOCAB CONSISTENCY: Verify matches specified tone and vocabulary throughout.
12. AI PATTERN CHECK: Break perfect structures, eliminate repetitive patterns, remove overly formal language.
13. QUALITY & CLARITY: Ensure meaning is clear and writing is engaging despite imperfections.
14. PLAIN TEXT ONLY: Remove ALL markdown, asterisks, formatting symbols.
15. FINAL VERIFICATION: If ANY part sounds like AI, rewrite it with more human touches.

DRAFT TEXT:
"${draft1}"

Apply final humanization polish. This MUST be 100% AI-FREE, HIGH QUALITY, and read like a skilled human wrote it in the specified tone and vocabulary. Output ONLY plain text - no markdown, no formatting symbols.`;

    const result2 = await callGeminiAPI(promptPass2, {
      temperature: Math.max(temperature - 0.05, 0.85), // Keep higher for variation
      topP: 0.995, // Higher for more variation
      topK: 145, // Higher for more word variety
    });

    const finalDraft = result2.text || draft1;
    const finalText = postprocessText(finalDraft);

    res.status(200).json({ success: true, text: finalText });
  } catch (error) {
    console.error('Humanize Error:', error);
    res.status(500).json({ 
      success: false, 
      message: error.message || 'Failed to humanize text. Please try again.' 
    });
  }
});

// Helper function to split text into sentences
const splitIntoSentences = (text) => {
  // Split by sentence-ending punctuation, but keep the punctuation
  const sentences = text.match(/[^.!?]+[.!?]+/g) || [];
  // Also handle sentences without ending punctuation
  const remaining = text.replace(/[^.!?]+[.!?]+/g, '').trim();
  if (remaining) {
    sentences.push(remaining);
  }
  return sentences.filter(s => s.trim().length > 0);
};

// Helper function to calculate text metrics
const calculateTextMetrics = (text) => {
  const sentences = splitIntoSentences(text);
  const words = text.split(/\s+/).filter(w => w.length > 0);
  const uniqueWords = new Set(words.map(w => w.toLowerCase()));
  
  const avgSentenceLength = sentences.length > 0 
    ? words.length / sentences.length 
    : 0;
  
  const vocabularyRichness = words.length > 0 
    ? (uniqueWords.size / words.length) * 100 
    : 0;
  
  // Calculate burstiness (variation in sentence lengths)
  const sentenceLengths = sentences.map(s => s.split(/\s+/).length);
  const avgLength = sentenceLengths.reduce((a, b) => a + b, 0) / sentenceLengths.length || 1;
  const variance = sentenceLengths.reduce((sum, len) => sum + Math.pow(len - avgLength, 2), 0) / sentenceLengths.length || 0;
  const burstiness = Math.sqrt(variance) / avgLength;
  
  return {
    averageSentenceLength: Math.round(avgSentenceLength * 10) / 10,
    vocabularyRichness: Math.round(vocabularyRichness * 10) / 10,
    burstiness: Math.round(burstiness * 100) / 100
  };
};

// Detect AI content endpoint - Enhanced with advanced detection
app.post('/api/ai/detect', async (req, res) => {
  try {
    const { text } = req.body;

    if (!text || !text.trim()) {
      return res.status(400).json({ success: false, message: 'Text is required' });
    }

    // Limit text length for processing (15,000 characters like ZeroGPT)
    const maxLength = 15000;
    const processedText = text.length > maxLength ? text.substring(0, maxLength) : text;

    // Calculate text metrics
    const metrics = calculateTextMetrics(processedText);

    // Split into sentences for detailed analysis
    const sentences = splitIntoSentences(processedText);

    // Advanced AI detection prompt
    const detectionPrompt = `You are an expert AI content detector analyzing text to determine if it was generated by AI (ChatGPT, GPT-4, GPT-5, Gemini, Claude, etc.) or written by a human.

ANALYSIS CRITERIA:
1. Sentence Structure: AI tends to use consistent, parallel structures. Humans vary sentence length and structure.
2. Vocabulary Patterns: AI often uses formal, repetitive word choices. Humans use more varied, natural vocabulary.
3. Transitions: AI uses formal transitions like "Furthermore", "Moreover", "Additionally". Humans use casual ones like "Plus", "Also", "But", "So".
4. Perplexity: AI text has lower perplexity (more predictable). Human text has higher perplexity.
5. Burstiness: AI has low burstiness (consistent sentence lengths). Humans have high burstiness (varied lengths).
6. Personal Touch: AI avoids personal pronouns and opinions. Humans include personal touches.
7. Imperfections: AI text is too perfect. Human text has natural imperfections.
8. Repetition: AI avoids word repetition. Humans repeat words naturally.
9. Sentence Variety: AI uses similar sentence structures. Humans vary extensively.

TEXT TO ANALYZE (${processedText.length} characters):
"${processedText}"

TEXT METRICS:
- Average Sentence Length: ${metrics.averageSentenceLength} words
- Vocabulary Richness: ${metrics.vocabularyRichness}%
- Burstiness: ${metrics.burstiness}

Provide a comprehensive analysis in JSON format:
{
  "score": 0-100 (0 = definitely human, 100 = definitely AI),
  "label": "Human-Written" | "Mixed/Edited" | "Fully AI-Generated",
  "analysis": "Detailed explanation of why this text appears to be AI or human, citing specific patterns, metrics, and evidence",
  "sentences": [
    {
      "sentence": "exact sentence text",
      "aiProbability": 0-100,
      "isHighlighted": true/false (true if aiProbability > 50)
    }
  ],
  "detectedModels": ["possible AI models that might have generated this, e.g., ChatGPT, GPT-4, Gemini, Claude, or empty array if human"]
}

Analyze each sentence individually and provide sentence-by-sentence AI probability scores. Highlight sentences with AI probability > 50%.`;

    const result = await callGeminiAPI(detectionPrompt, {
      responseMimeType: 'application/json',
      temperature: 0.3 // Lower temperature for more consistent detection
    });

    const responseText = result.text;
    let detectionResult;
    
    try {
      // Try to parse JSON, handling cases where it might be wrapped in markdown
      let cleanedText = responseText.trim();
      if (cleanedText.startsWith('```json')) {
        cleanedText = cleanedText.replace(/```json\n?/g, '').replace(/```\n?/g, '');
      } else if (cleanedText.startsWith('```')) {
        cleanedText = cleanedText.replace(/```\n?/g, '');
      }
      
      detectionResult = JSON.parse(cleanedText);
      
      // Ensure score is between 0-100
      detectionResult.score = Math.max(0, Math.min(100, detectionResult.score || 0));
      
      // Add metrics to result
      detectionResult.metrics = metrics;
      
      // Ensure sentences array exists and is properly formatted
      if (!detectionResult.sentences || !Array.isArray(detectionResult.sentences)) {
        // Fallback: create sentence analysis from actual sentences
        detectionResult.sentences = sentences.slice(0, 50).map((sentence, index) => {
          // Estimate AI probability based on overall score and sentence characteristics
          const sentenceLength = sentence.split(/\s+/).length;
          const hasFormalTransitions = /(furthermore|moreover|additionally|consequently|therefore|thus|hence)/i.test(sentence);
          const hasCasualTransitions = /(plus|also|but|so|then|now|well|actually)/i.test(sentence);
          
          let sentenceScore = detectionResult.score;
          if (hasFormalTransitions && !hasCasualTransitions) {
            sentenceScore = Math.min(100, sentenceScore + 15);
          } else if (hasCasualTransitions) {
            sentenceScore = Math.max(0, sentenceScore - 10);
          }
          
          // Adjust based on sentence length variation
          if (sentenceLength < 5 || sentenceLength > 30) {
            sentenceScore = Math.max(0, sentenceScore - 5); // Shorter or longer sentences are more human-like
          }
          
          return {
            sentence: sentence.trim(),
            aiProbability: Math.max(0, Math.min(100, Math.round(sentenceScore))),
            isHighlighted: sentenceScore > 50
          };
        });
      } else {
        // Validate and fix sentence data
        detectionResult.sentences = detectionResult.sentences.map(s => ({
          sentence: s.sentence || '',
          aiProbability: Math.max(0, Math.min(100, s.aiProbability || 0)),
          isHighlighted: (s.aiProbability || 0) > 50
        }));
      }
      
      // Ensure detectedModels is an array
      if (!detectionResult.detectedModels || !Array.isArray(detectionResult.detectedModels)) {
        detectionResult.detectedModels = detectionResult.detectedModels ? [detectionResult.detectedModels] : [];
      }
      
    } catch (e) {
      console.error('JSON Parse Error:', e);
      console.error('Response text:', responseText.substring(0, 500));
      
      // Fallback: create basic detection result
      const sentences = splitIntoSentences(processedText);
      detectionResult = {
        score: 50, // Neutral score
        label: 'Analysis Error',
        analysis: 'Could not parse detailed detection results. Basic analysis: The text shows mixed characteristics that make it difficult to determine with certainty.',
        sentences: sentences.slice(0, 50).map(sentence => ({
          sentence: sentence.trim(),
          aiProbability: 50,
          isHighlighted: false
        })),
        metrics: metrics,
        detectedModels: []
      };
    }

    res.status(200).json({ success: true, ...detectionResult });
  } catch (error) {
    console.error('Detection Error:', error);
    res.status(500).json({ 
      success: false,
      score: 0,
      label: 'Connection Error',
      analysis: 'Unable to reach the detection service. Please try again.',
      sentences: [],
      metrics: {},
      detectedModels: []
    });
  }
});

// Evaluate quality endpoint
app.post('/api/ai/evaluate', async (req, res) => {
  try {
    const { original, rewritten } = req.body;

    if (!original || !rewritten) {
      return res.status(400).json({ success: false, message: 'Original and rewritten text are required' });
    }

    const prompt = `You are a Senior Editor. Compare the ORIGINAL AI text with the REWRITTEN humanized version.

Evaluate on:
1. Human-Likeness: Does it sound authentically human?
2. Meaning Preservation: Is the core message preserved?
3. Sentence Variety: Good mix of short and long sentences?

ORIGINAL: "${original.substring(0, 1000)}"
REWRITTEN: "${rewritten.substring(0, 1000)}"

Provide JSON:
{
  "humanScore": 0-100 (100 = perfectly natural),
  "meaningPreserved": true/false,
  "sentenceVariety": "Short assessment",
  "feedback": "One sentence of constructive feedback"
}`;

    const result = await callGeminiAPI(prompt, {
      responseMimeType: 'application/json'
    });

    const responseText = result.text;
    let evaluationResult;
    
    try {
      evaluationResult = JSON.parse(responseText);
    } catch (e) {
      evaluationResult = {
        humanScore: 0,
        meaningPreserved: false,
        sentenceVariety: 'Unable to evaluate',
        feedback: 'Could not parse evaluation results.'
      };
    }

    res.status(200).json({ success: true, ...evaluationResult });
  } catch (error) {
    console.error('Evaluation Error:', error);
    res.status(500).json({ 
      success: false,
      humanScore: 0,
      meaningPreserved: false,
      sentenceVariety: 'Error',
      feedback: 'Failed to evaluate quality.'
    });
  }
});

// List available models endpoint
app.get('/api/ai/list-models', async (req, res) => {
  try {
    const apiKey = process.env.GEMINI_API_KEY;
    
    if (!apiKey) {
      return res.status(500).json({ 
        success: false, 
        error: 'GEMINI_API_KEY not set in Railway environment variables'
      });
    }

    // List available models
    const url = `https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`;
    const response = await axios.get(url);
    
    const models = response.data.models || [];
    const availableModels = models
      .filter(m => m.supportedGenerationMethods?.includes('generateContent'))
      .map(m => ({
        name: m.name,
        displayName: m.displayName,
        description: m.description
      }));

    res.status(200).json({ 
      success: true, 
      models: availableModels,
      total: availableModels.length
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: error.response?.data?.error?.message || error.message
    });
  }
});

// Diagnostic endpoint to test Gemini API
app.get('/api/ai/test', async (req, res) => {
  try {
    const apiKey = process.env.GEMINI_API_KEY;
    
    if (!apiKey) {
      return res.status(500).json({ 
        success: false, 
        error: 'GEMINI_API_KEY not set in Railway environment variables',
        help: 'Go to Railway → Variables → Add GEMINI_API_KEY'
      });
    }

    // First, list available models
    let availableModels = [];
    try {
      const listUrl = `https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`;
      const listResponse = await axios.get(listUrl);
      availableModels = (listResponse.data.models || [])
        .filter(m => m.supportedGenerationMethods?.includes('generateContent'))
        .map(m => m.name.replace('models/', ''));
    } catch (e) {
      console.log('Could not list models:', e.message);
    }

    // Test with a simple prompt
    const testPrompt = 'Say "Hello" in one word.';
    const testResult = await callGeminiAPI(testPrompt, { temperature: 0.7 });
    
    res.status(200).json({ 
      success: true, 
      message: 'Gemini API is working!',
      modelUsed: testResult.modelName,
      testResponse: testResult.text,
      apiKeySet: true,
      availableModels: availableModels,
      apiKeyPreview: apiKey.substring(0, 10) + '...' + apiKey.substring(apiKey.length - 4)
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: error.message,
      apiKeySet: !!process.env.GEMINI_API_KEY,
      help: 'Check Railway logs for detailed error messages. Try /api/ai/list-models to see available models.'
    });
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

    // Check and update premium expiration
    await checkAndUpdatePremiumExpiration(user);
    
    // Refresh user data after expiration check
    const updatedUser = await User.findOne({ id: userId });

    res.status(200).json({
      success: true,
      user: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        avatar: updatedUser.picture,
        isPremium: updatedUser.is_premium,
        emailVerified: updatedUser.email_verified || true, // Google users are auto-verified
        premiumExpiresAt: updatedUser.premium_expires_at || null,
        createdAt: updatedUser.created_at || null
      }
    });
  } catch (error) {
    console.error("Get User Error:", error);
    res.status(500).json({ success: false, message: "Error fetching user" });
  }
});

// --- UPDATE USER PROFILE PHOTO ---
app.put('/api/user/:userId/photo', async (req, res) => {
  try {
    const { userId } = req.params;
    const { photo } = req.body;

    if (!photo) {
      return res.status(400).json({ success: false, message: 'Photo data is required' });
    }

    // Validate base64 image format
    if (!photo.startsWith('data:image/')) {
      return res.status(400).json({ success: false, message: 'Invalid image format' });
    }

    // Check if base64 string is too large (max 500KB for compressed image)
    const base64Size = (photo.length * 3) / 4;
    if (base64Size > 500 * 1024) {
      return res.status(400).json({ success: false, message: 'Image file is too large' });
    }

    const user = await User.findOne({ id: userId });
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Update user's picture field with base64 image
    user.picture = photo;
    await user.save();

    console.log(`✅ Profile photo updated for user: ${user.email}`);

    res.status(200).json({
      success: true,
      message: 'Profile photo updated successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        avatar: user.picture,
        isPremium: user.is_premium
      }
    });
  } catch (error) {
    console.error("Update Photo Error:", error);
    res.status(500).json({ success: false, message: "Error updating profile photo" });
  }
});

// --- DELETE USER ACCOUNT ---
app.delete('/api/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findOne({ id: userId });
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Delete all user-related data
    // 1. Delete all transactions
    await Transaction.deleteMany({ user_id: userId });
    
    // 2. Delete all payment requests
    await PaymentRequest.deleteMany({ user_id: userId });
    
    // 3. Delete the user account
    await User.deleteOne({ id: userId });

    console.log(`✅ Account deleted for user: ${user.email} (${userId})`);

    res.status(200).json({
      success: true,
      message: 'Account deleted successfully'
    });
  } catch (error) {
    console.error("Delete Account Error:", error);
    res.status(500).json({ success: false, message: "Error deleting account" });
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
