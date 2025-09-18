const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const { RtcTokenBuilder, RtcRole } = require('agora-token');

const app = express();

// Environment variables
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://neondb_owner:npg_hqp6LX2UWlVA@ep-young-sound-adq39fqe-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require';
const JWT_SECRET = process.env.JWT_SECRET || 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6A7B8C9D0E1F2G3H4I5J6K7L8M9N0';
const EMAIL_USER = process.env.EMAIL_USER || 'vidyaskhopade@gmail.com';
const EMAIL_PASS = process.env.EMAIL_PASS || 'axoztnbitektpsva';

// Agora configuration
const AGORA_APP_ID = '1646d8e04dfb4a4b803ce4acea826920';
const AGORA_APP_CERTIFICATE = 'c68f152c0b82444f9a94449682a74b82';

// Simple in-memory cache
const cache = new Map();
const CACHE_TTL = 15 * 60 * 1000;

const getFromCache = (key) => {
  const item = cache.get(key);
  if (item && Date.now() - item.timestamp < CACHE_TTL) {
    return item.data;
  }
  cache.delete(key);
  return null;
};

const setCache = (key, data) => {
  cache.set(key, { data, timestamp: Date.now() });
};

const clearCachePattern = (pattern) => {
  for (const key of cache.keys()) {
    if (key.includes(pattern)) {
      cache.delete(key);
    }
  }
};

// Database connection
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Email transporter
const transporter = nodemailer.createTransporter({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use('/api/login', limiter);
app.use('/api/signup', limiter);
app.use('/api/verify-login', limiter);
app.use('/api/verify-signup', limiter);

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({ message: 'PeerSync Backend is running on Vercel!' });
});

// Generate OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Send OTP email
const sendOTPEmail = async (email, otp, purpose) => {
  const subject = purpose === 'signup' ? 'PeerSync - Email Verification' : 
                  purpose === 'login' ? 'PeerSync - Login Verification' : 
                  'PeerSync - Password Reset';
  
  const html = `
    <h2>PeerSync ${purpose === 'signup' ? 'Email Verification' : purpose === 'login' ? 'Login Verification' : 'Password Reset'}</h2>
    <p>Your OTP code is: <strong>${otp}</strong></p>
    <p>This code will expire in 10 minutes.</p>
  `;

  try {
    await transporter.sendMail({
      from: EMAIL_USER,
      to: email,
      subject,
      html
    });
  } catch (error) {
    console.error('Email sending failed:', error);
  }
};

// Initialize database tables
const initDatabase = async () => {
  try {
    const client = await pool.connect();
    
    // Create video_calls table if it doesn't exist
    await client.query(`
      CREATE TABLE IF NOT EXISTS video_calls (
        id SERIAL PRIMARY KEY,
        mentee_id INTEGER NOT NULL REFERENCES users(id),
        mentor_id INTEGER NOT NULL REFERENCES users(id),
        channel_name VARCHAR(255) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT NOW(),
        accepted_at TIMESTAMP,
        started_at TIMESTAMP,
        ended_at TIMESTAMP,
        duration_minutes INTEGER,
        CONSTRAINT valid_status CHECK (status IN ('pending', 'accepted', 'rejected', 'active', 'completed', 'cancelled'))
      );
      
      CREATE INDEX IF NOT EXISTS idx_video_calls_mentor_id ON video_calls(mentor_id);
      CREATE INDEX IF NOT EXISTS idx_video_calls_mentee_id ON video_calls(mentee_id);
      CREATE INDEX IF NOT EXISTS idx_video_calls_status ON video_calls(status);
    `);
    
    client.release();
    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
};

// Initialize database on startup
initDatabase();

// Check username availability
app.post('/api/check-username', async (req, res) => {
  try {
    const { username } = req.body;
    const result = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    res.json({ available: result.rows.length === 0 });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Signup
app.post('/api/signup', async (req, res) => {
  try {
    const { username, email, phone, password, role } = req.body;

    if (!username || !email || !phone || !password || !role) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1 AND role = $2', 
      [email, role]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists with this email and role' });
    }

    // Check username uniqueness
    const usernameCheck = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (usernameCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Username already taken' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Generate and send OTP
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query(
      'INSERT INTO otp_codes (email, otp_code, purpose, expires_at) VALUES ($1, $2, $3, $4)',
      [email, otp, 'signup', expiresAt]
    );

    await sendOTPEmail(email, otp, 'signup');

    // Store user data temporarily
    const tempUserData = { username, email, phone, password: hashedPassword, role };
    
    res.json({ 
      message: 'OTP sent to email. Please verify to complete signup.',
      tempUserId: Buffer.from(JSON.stringify(tempUserData)).toString('base64')
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Verify signup OTP
app.post('/api/verify-signup', async (req, res) => {
  try {
    const { otp, tempUserId } = req.body;
    const userData = JSON.parse(Buffer.from(tempUserId, 'base64').toString());

    const otpResult = await pool.query(
      'SELECT * FROM otp_codes WHERE email = $1 AND otp_code = $2 AND purpose = $3 AND expires_at > NOW() AND is_used = FALSE',
      [userData.email, otp, 'signup']
    );

    if (otpResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    // Create user
    const result = await pool.query(
      'INSERT INTO users (username, email, phone, password_hash, role, is_verified) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, username, email, role',
      [userData.username, userData.email, userData.phone, userData.password, userData.role, true]
    );

    // Mark OTP as used
    await pool.query('UPDATE otp_codes SET is_used = TRUE WHERE id = $1', [otpResult.rows[0].id]);

    const token = jwt.sign(
      { userId: result.rows[0].id, role: result.rows[0].role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Signup successful',
      token,
      user: result.rows[0]
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password, role } = req.body;

    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND role = $2 AND is_verified = TRUE',
      [email, role]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password_hash);

    if (!isValidPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate and send login OTP
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query(
      'INSERT INTO otp_codes (email, otp_code, purpose, expires_at) VALUES ($1, $2, $3, $4)',
      [user.email, otp, 'login', expiresAt]
    );

    await sendOTPEmail(user.email, otp, 'login');

    res.json({
      message: 'OTP sent to email for verification',
      userId: user.id
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify login OTP
app.post('/api/verify-login', async (req, res) => {
  try {
    const { otp, userId } = req.body;

    const user = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (user.rows.length === 0) {
      return res.status(400).json({ error: 'User not found' });
    }

    const otpResult = await pool.query(
      'SELECT * FROM otp_codes WHERE email = $1 AND otp_code = $2 AND purpose = $3 AND expires_at > NOW() AND is_used = FALSE',
      [user.rows[0].email, otp, 'login']
    );

    if (otpResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    // Mark OTP as used
    await pool.query('UPDATE otp_codes SET is_used = TRUE WHERE id = $1', [otpResult.rows[0].id]);

    const token = jwt.sign(
      { userId: user.rows[0].id, role: user.rows[0].role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.rows[0].id,
        username: user.rows[0].username,
        email: user.rows[0].email,
        role: user.rows[0].role
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Video call token generation
app.post('/api/video-call/token', async (req, res) => {
  try {
    const { channelName, uid, role } = req.body;
    
    if (!channelName || !uid) {
      return res.status(400).json({ error: 'Channel name and UID are required' });
    }
    
    const roleType = role === 'publisher' ? RtcRole.PUBLISHER : RtcRole.SUBSCRIBER;
    const expirationTimeInSeconds = 3600;
    const currentTimestamp = Math.floor(Date.now() / 1000);
    const privilegeExpiredTs = currentTimestamp + expirationTimeInSeconds;
    
    const token = RtcTokenBuilder.buildTokenWithUid(
      AGORA_APP_ID,
      AGORA_APP_CERTIFICATE,
      channelName,
      uid,
      roleType,
      privilegeExpiredTs
    );
    
    res.json({ token, appId: AGORA_APP_ID });
  } catch (error) {
    console.error('Token generation error:', error);
    res.status(500).json({ error: 'Failed to generate token' });
  }
});

// Get all mentors
app.get('/api/mentors', async (req, res) => {
  try {
    const cacheKey = 'mentors_list';
    const cached = getFromCache(cacheKey);
    if (cached) {
      return res.json({ mentors: cached });
    }
    
    const result = await pool.query(
      'SELECT mp.*, u.username, u.email FROM mentor_profiles mp JOIN users u ON mp.user_id = u.id WHERE u.role = $1 AND mp.name IS NOT NULL AND mp.name != \'\'',
      ['mentor']
    );
    
    const mentors = result.rows.map(mentor => {
      let skills = [];
      let interests = [];
      let languages = [];
      let availability = {};
      
      try {
        skills = mentor.skills ? (typeof mentor.skills === 'string' ? JSON.parse(mentor.skills) : mentor.skills) : [];
      } catch (e) { skills = []; }
      
      try {
        const interestsData = mentor.interests ? (typeof mentor.interests === 'string' ? JSON.parse(mentor.interests) : mentor.interests) : [];
        interests = Array.isArray(interestsData) ? interestsData : (interestsData.interests || []);
      } catch (e) { interests = []; }
      
      try {
        languages = mentor.languages ? (typeof mentor.languages === 'string' ? JSON.parse(mentor.languages) : mentor.languages) : [];
      } catch (e) { languages = []; }
      
      try {
        availability = mentor.availability ? (typeof mentor.availability === 'string' ? JSON.parse(mentor.availability) : mentor.availability) : {};
      } catch (e) { availability = {}; }
      
      return {
        id: mentor.user_id,
        name: mentor.name || mentor.username,
        bio: mentor.bio || 'Experienced mentor ready to help you grow.',
        profilePicture: mentor.profile_picture,
        skills,
        interests,
        languages,
        availability,
        rating: 4.8,
        reviewCount: Math.floor(Math.random() * 50) + 10
      };
    });
    
    setCache(cacheKey, mentors);
    res.json({ mentors });
  } catch (error) {
    console.error('Get mentors error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Export for Vercel
module.exports = app;