const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const { RtcTokenBuilder, RtcRole } = require('agora-token');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Agora configuration
const AGORA_APP_ID = '1646d8e04dfb4a4b803ce4acea826920';
const AGORA_APP_CERTIFICATE = 'c68f152c0b82444f9a94449682a74b82';

// Simple in-memory cache
const cache = new Map();
const CACHE_TTL = 15 * 60 * 1000; // 15 minutes for better performance

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
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Email transporter
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Test database connection and create tables
pool.connect(async (err, client, release) => {
  if (err) {
    console.error('Database connection error:', err.stack);
  } else {
    console.log('Database connected successfully');
    
    // Create video_calls table if it doesn't exist
    try {
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
      console.log('Video calls table created/verified successfully');
    } catch (tableError) {
      console.error('Error creating video_calls table:', tableError);
    }
    
    release();
  }
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // Increased limit for development
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
// Apply rate limiter only to auth routes
app.use('/api/login', limiter);
app.use('/api/signup', limiter);
app.use('/api/verify-login', limiter);
app.use('/api/verify-signup', limiter);

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({ message: 'PeerSync Backend is running!' });
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

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject,
    html
  });
};

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
    console.log('Signup request received:', req.body);
    const { username, email, phone, password, role } = req.body;

    if (!username || !email || !phone || !password || !role) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user already exists with same email and role
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
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    console.log('Inserting OTP for email:', email);
    await pool.query(
      'INSERT INTO otp_codes (email, otp_code, purpose, expires_at) VALUES ($1, $2, $3, $4)',
      [email, otp, 'signup', expiresAt]
    );

    console.log('Sending OTP email to:', email);
    try {
      await sendOTPEmail(email, otp, 'signup');
      console.log('OTP email sent successfully');
    } catch (emailError) {
      console.error('Email sending failed:', emailError);
      // Continue without failing - for development
    }

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
      process.env.JWT_SECRET,
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
      process.env.JWT_SECRET,
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

// Forgot password
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.status(400).json({ error: 'Email not found' });
    }

    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query(
      'INSERT INTO otp_codes (email, otp_code, purpose, expires_at) VALUES ($1, $2, $3, $4)',
      [email, otp, 'reset', expiresAt]
    );

    await sendOTPEmail(email, otp, 'reset');

    res.json({ message: 'Password reset OTP sent to email' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Reset password
app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    const otpResult = await pool.query(
      'SELECT * FROM otp_codes WHERE email = $1 AND otp_code = $2 AND purpose = $3 AND expires_at > NOW() AND is_used = FALSE',
      [email, otp, 'reset']
    );

    if (otpResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    await pool.query('UPDATE users SET password_hash = $1 WHERE email = $2', [hashedPassword, email]);
    await pool.query('UPDATE otp_codes SET is_used = TRUE WHERE id = $1', [otpResult.rows[0].id]);

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Mentor Profile endpoints
app.get('/api/mentor/profile/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Use a single optimized query
    const result = await pool.query(
      'SELECT * FROM mentor_profiles WHERE user_id = $1',
      [userId]
    );
    
    if (result.rows.length === 0) {
      return res.json({ profile: null });
    }
    
    const profile = result.rows[0];
    
    // Parse interests data quickly
    let interestsData = { selectedCategories: [], interests: [] };
    if (profile.interests) {
      try {
        const parsed = typeof profile.interests === 'string' ? JSON.parse(profile.interests) : profile.interests;
        interestsData = Array.isArray(parsed) ? { interests: parsed, selectedCategories: [] } : parsed;
      } catch (e) {
        console.error('Error parsing interests:', e);
      }
    }
    
    // Return structured data immediately
    const profileData = {
      basicInfo: {
        name: profile.name || '',
        profilePicture: profile.profile_picture || '',
        bio: profile.bio || ''
      },
      education: profile.education || [],
      skills: profile.skills || [],
      background: profile.background || [],
      interests: interestsData.interests || [],
      selectedCategories: interestsData.selectedCategories || [],
      languages: profile.languages || [],
      availability: profile.availability || {}
    };
    
    res.json({ profile: profileData });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/mentor/profile/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { basicInfo, education, skills, background, interests, languages, availability } = req.body;
    
    // Check if profile exists
    const existing = await pool.query(
      'SELECT id FROM mentor_profiles WHERE user_id = $1',
      [userId]
    );
    
    let profileId;
    
    if (existing.rows.length === 0) {
      // Create new profile
      const result = await pool.query(
        'INSERT INTO mentor_profiles (user_id, name, profile_picture, bio, education, skills, background, languages, availability, interests) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id',
        [userId, basicInfo.name, basicInfo.profilePicture, basicInfo.bio, JSON.stringify(education), JSON.stringify(skills), JSON.stringify(background), JSON.stringify(languages), JSON.stringify(availability), JSON.stringify(interests)]
      );
      profileId = result.rows[0].id;
    } else {
      // Update existing profile
      await pool.query(
        'UPDATE mentor_profiles SET name = $1, profile_picture = $2, bio = $3, education = $4, skills = $5, background = $6, languages = $7, availability = $8, interests = $9, updated_at = NOW() WHERE user_id = $10',
        [basicInfo.name, basicInfo.profilePicture, basicInfo.bio, JSON.stringify(education), JSON.stringify(skills), JSON.stringify(background), JSON.stringify(languages), JSON.stringify(availability), JSON.stringify(interests), userId]
      );
      profileId = existing.rows[0].id;
    }
    
    // Handle tags
    if (interests && interests.length > 0) {
      // Delete existing tags
      await pool.query('DELETE FROM mentor_profile_tags WHERE mentor_profile_id = $1', [profileId]);
      
      // Insert new tags
      for (const interest of interests) {
        const tagResult = await pool.query('SELECT id FROM tags WHERE name = $1', [interest]);
        if (tagResult.rows.length > 0) {
          await pool.query(
            'INSERT INTO mentor_profile_tags (mentor_profile_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [profileId, tagResult.rows[0].id]
          );
        }
      }
    }
    
    res.json({ message: 'Profile saved successfully' });
  } catch (error) {
    console.error('Save profile error:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Update specific section of mentor profile
app.patch('/api/mentor/profile/:userId/section', async (req, res) => {
  try {
    console.log('Section update request:', req.body);
    const { userId } = req.params;
    const { section, data } = req.body;
    
    // Check if profile exists, create if not
    let existing = await pool.query(
      'SELECT * FROM mentor_profiles WHERE user_id = $1',
      [userId]
    );
    
    let profileId;
    if (existing.rows.length === 0) {
      // Create new profile with default values
      const result = await pool.query(
        'INSERT INTO mentor_profiles (user_id, name, profile_picture, bio, education, skills, background, languages, availability, interests) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id',
        [userId, '', '', '', '[]', '[]', '[]', '[]', '{}', '[]']
      );
      profileId = result.rows[0].id;
    } else {
      profileId = existing.rows[0].id;
    }
    
    // Update specific section
    switch (section) {
      case 'basic':
        await pool.query(
          'UPDATE mentor_profiles SET name = $1, profile_picture = $2, bio = $3, updated_at = NOW() WHERE user_id = $4',
          [data.name || '', data.profilePicture || '', data.bio || '', userId]
        );
        break;
      case 'education':
        await pool.query(
          'UPDATE mentor_profiles SET education = $1, updated_at = NOW() WHERE user_id = $2',
          [JSON.stringify(data || []), userId]
        );
        break;
      case 'skills':
        await pool.query(
          'UPDATE mentor_profiles SET skills = $1, updated_at = NOW() WHERE user_id = $2',
          [JSON.stringify(data || []), userId]
        );
        break;
      case 'background':
        await pool.query(
          'UPDATE mentor_profiles SET background = $1, updated_at = NOW() WHERE user_id = $2',
          [JSON.stringify(data || []), userId]
        );
        break;
      case 'interests':
        // Save both selected categories and interests in the interests column
        const interestData = {
          selectedCategories: data.selectedCategories || [],
          interests: data.interests || []
        };
        await pool.query(
          'UPDATE mentor_profiles SET interests = $1, updated_at = NOW() WHERE user_id = $2',
          [JSON.stringify(interestData), userId]
        );
        break;
      case 'languages':
        await pool.query(
          'UPDATE mentor_profiles SET languages = $1, updated_at = NOW() WHERE user_id = $2',
          [JSON.stringify(data || []), userId]
        );
        break;
      case 'availability':
        await pool.query(
          'UPDATE mentor_profiles SET availability = $1, updated_at = NOW() WHERE user_id = $2',
          [JSON.stringify(data || {}), userId]
        );
        break;
      default:
        return res.status(400).json({ error: 'Invalid section' });
    }
    
    res.json({ message: 'Section saved successfully' });
  } catch (error) {
    console.error('Save section error:', error);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Get all mentors for mentee dashboard
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
      // Parse JSON fields safely
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
        rating: 4.8, // Default rating
        reviewCount: Math.floor(Math.random() * 50) + 10 // Random review count for demo
      };
    });
    
    setCache(cacheKey, mentors);
    res.json({ mentors });
  } catch (error) {
    console.error('Get mentors error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add mentee-specific endpoints
app.post('/api/mentee/favorite', async (req, res) => {
  try {
    const { menteeId, mentorId } = req.body;
    
    // Check if already favorited
    const existing = await pool.query(
      'SELECT id FROM mentee_favorites WHERE mentee_id = $1 AND mentor_id = $2',
      [menteeId, mentorId]
    );
    
    if (existing.rows.length > 0) {
      // Remove from favorites
      await pool.query(
        'DELETE FROM mentee_favorites WHERE mentee_id = $1 AND mentor_id = $2',
        [menteeId, mentorId]
      );
      res.json({ message: 'Removed from favorites', favorited: false });
    } else {
      // Add to favorites
      await pool.query(
        'INSERT INTO mentee_favorites (mentee_id, mentor_id) VALUES ($1, $2)',
        [menteeId, mentorId]
      );
      res.json({ message: 'Added to favorites', favorited: true });
    }
  } catch (error) {
    console.error('Favorite error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/mentee/:menteeId/favorites', async (req, res) => {
  try {
    const { menteeId } = req.params;
    
    const result = await pool.query(
      'SELECT mentor_id FROM mentee_favorites WHERE mentee_id = $1',
      [menteeId]
    );
    
    const favoriteIds = result.rows.map(row => row.mentor_id);
    res.json({ favorites: favoriteIds });
  } catch (error) {
    console.error('Get favorites error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/mentee/:menteeId/liked-blogs', async (req, res) => {
  try {
    const { menteeId } = req.params;
    
    const result = await pool.query(
      'SELECT blog_id FROM blog_likes WHERE mentee_id = $1',
      [menteeId]
    );
    
    const likedBlogs = result.rows.map(row => row.blog_id);
    res.json({ likedBlogs });
  } catch (error) {
    console.error('Get liked blogs error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Blog endpoints
app.get('/api/blogs', async (req, res) => {
  try {
    const cacheKey = 'all_blogs';
    const cached = getFromCache(cacheKey);
    if (cached) {
      return res.json({ blogs: cached });
    }
    
    const result = await pool.query(`
      SELECT b.*, u.username as mentor_name, mp.name as mentor_display_name, mp.profile_picture as mentor_avatar
      FROM blogs b 
      JOIN users u ON b.mentor_id = u.id 
      LEFT JOIN mentor_profiles mp ON b.mentor_id = mp.user_id
      WHERE b.is_published = true 
      ORDER BY b.created_at DESC
    `);
    
    const blogs = result.rows.map(blog => ({
      ...blog,
      mentor_name: blog.mentor_display_name || blog.mentor_name,
      images: blog.images || [],
      tags: blog.tags || []
    }));
    
    setCache(cacheKey, blogs);
    res.json({ blogs });
  } catch (error) {
    console.error('Get blogs error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/blogs/mentor/:mentorId', async (req, res) => {
  try {
    const { mentorId } = req.params;
    const result = await pool.query(
      'SELECT * FROM blogs WHERE mentor_id = $1 ORDER BY created_at DESC',
      [mentorId]
    );
    
    const blogs = result.rows.map(blog => ({
      ...blog,
      images: blog.images || [],
      tags: blog.tags || []
    }));
    
    res.json({ blogs });
  } catch (error) {
    console.error('Get mentor blogs error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/blogs', async (req, res) => {
  try {
    const { mentorId, title, description, content, category, tags, images } = req.body;
    
    const result = await pool.query(
      'INSERT INTO blogs (mentor_id, title, description, content, category, tags, images) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [mentorId, title, description, content, category, tags || [], images || []]
    );
    
    // Clear relevant caches
    clearCachePattern('blogs');
    clearCachePattern(`mentor_${mentorId}`);
    
    res.json({ message: 'Blog created successfully', blog: result.rows[0] });
  } catch (error) {
    console.error('Create blog error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/blogs/:blogId', async (req, res) => {
  try {
    const { blogId } = req.params;
    const { mentorId } = req.body;
    
    await pool.query(
      'DELETE FROM blogs WHERE id = $1 AND mentor_id = $2',
      [blogId, mentorId]
    );
    
    res.json({ message: 'Blog deleted successfully' });
  } catch (error) {
    console.error('Delete blog error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Blog likes
app.post('/api/blogs/:blogId/like', async (req, res) => {
  try {
    const { blogId } = req.params;
    const { menteeId } = req.body;
    
    const existing = await pool.query(
      'SELECT id FROM blog_likes WHERE blog_id = $1 AND mentee_id = $2',
      [blogId, menteeId]
    );
    
    if (existing.rows.length > 0) {
      await pool.query(
        'DELETE FROM blog_likes WHERE blog_id = $1 AND mentee_id = $2',
        [blogId, menteeId]
      );
      await pool.query(
        'UPDATE blogs SET likes_count = likes_count - 1 WHERE id = $1',
        [blogId]
      );
      res.json({ liked: false });
    } else {
      await pool.query(
        'INSERT INTO blog_likes (blog_id, mentee_id) VALUES ($1, $2)',
        [blogId, menteeId]
      );
      await pool.query(
        'UPDATE blogs SET likes_count = likes_count + 1 WHERE id = $1',
        [blogId]
      );
      
      // Create notification for mentor
      const blog = await pool.query('SELECT mentor_id, title FROM blogs WHERE id = $1', [blogId]);
      const mentee = await pool.query('SELECT username FROM users WHERE id = $1', [menteeId]);
      
      if (blog.rows.length > 0 && mentee.rows.length > 0 && blog.rows[0].mentor_id !== menteeId) {
        await pool.query(
          'INSERT INTO notifications (user_id, type, title, message, related_id, related_type) VALUES ($1, $2, $3, $4, $5, $6)',
          [blog.rows[0].mentor_id, 'blog_like', 'New Like', `${mentee.rows[0].username} liked your blog "${blog.rows[0].title}"`, blogId, 'blog']
        );
        // Clear notification cache
        clearCachePattern(`notifications_${blog.rows[0].mentor_id}`);
      }
      
      res.json({ liked: true });
    }
  } catch (error) {
    console.error('Like blog error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Blog comments
app.get('/api/blogs/:blogId/comments', async (req, res) => {
  try {
    const { blogId } = req.params;
    const result = await pool.query(`
      SELECT bc.*, u.username, u.role, mp.name as display_name, mp.profile_picture
      FROM blog_comments bc
      JOIN users u ON bc.user_id = u.id
      LEFT JOIN mentor_profiles mp ON bc.user_id = mp.user_id
      WHERE bc.blog_id = $1
      ORDER BY bc.created_at ASC
    `, [blogId]);
    
    const comments = result.rows.map(comment => ({
      ...comment,
      author_name: comment.display_name || comment.username,
      author_avatar: comment.profile_picture
    }));
    
    res.json({ comments });
  } catch (error) {
    console.error('Get comments error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/blogs/:blogId/comments', async (req, res) => {
  try {
    const { blogId } = req.params;
    const { userId, content, parentCommentId } = req.body;
    
    const result = await pool.query(
      'INSERT INTO blog_comments (blog_id, user_id, content, parent_comment_id) VALUES ($1, $2, $3, $4) RETURNING *',
      [blogId, userId, content, parentCommentId || null]
    );
    
    await pool.query(
      'UPDATE blogs SET comments_count = comments_count + 1 WHERE id = $1',
      [blogId]
    );
    
    // Create notification for blog owner
    const blog = await pool.query('SELECT mentor_id, title FROM blogs WHERE id = $1', [blogId]);
    const user = await pool.query('SELECT username FROM users WHERE id = $1', [userId]);
    
    if (blog.rows.length > 0 && user.rows.length > 0 && blog.rows[0].mentor_id !== userId) {
      const commentPreview = content.length > 50 ? content.substring(0, 50) + '...' : content;
      await pool.query(
        'INSERT INTO notifications (user_id, type, title, message, related_id, related_type) VALUES ($1, $2, $3, $4, $5, $6)',
        [blog.rows[0].mentor_id, 'blog_comment', 'New Comment', `${user.rows[0].username} commented on "${blog.rows[0].title}": "${commentPreview}"`, blogId, 'blog']
      );
      // Clear notification cache
      clearCachePattern(`notifications_${blog.rows[0].mentor_id}`);
    }
    
    // Create notification for parent comment author if it's a reply
    if (parentCommentId) {
      const parentComment = await pool.query(
        'SELECT bc.user_id, bc.content FROM blog_comments bc WHERE bc.id = $1', 
        [parentCommentId]
      );
      if (parentComment.rows.length > 0 && parentComment.rows[0].user_id !== userId && blog.rows.length > 0) {
        const replyPreview = content.length > 50 ? content.substring(0, 50) + '...' : content;
        const originalComment = parentComment.rows[0].content.length > 30 ? 
          parentComment.rows[0].content.substring(0, 30) + '...' : parentComment.rows[0].content;
        
        await pool.query(
          'INSERT INTO notifications (user_id, type, title, message, related_id, related_type) VALUES ($1, $2, $3, $4, $5, $6)',
          [parentComment.rows[0].user_id, 'blog_reply', 'New Reply', `${user.rows[0].username} replied to your comment on "${blog.rows[0].title}": "${replyPreview}" (Original: "${originalComment}")`, blogId, 'blog']
        );
        // Clear notification cache
        clearCachePattern(`notifications_${parentComment.rows[0].user_id}`);
      }
    }
    
    res.json({ message: 'Comment added successfully', comment: result.rows[0] });
  } catch (error) {
    console.error('Add comment error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/comments/:commentId', async (req, res) => {
  try {
    const { commentId } = req.params;
    const { userId, userRole } = req.body;
    
    const comment = await pool.query('SELECT * FROM blog_comments WHERE id = $1', [commentId]);
    
    if (comment.rows.length === 0) {
      return res.status(404).json({ error: 'Comment not found' });
    }
    
    const blog = await pool.query('SELECT mentor_id FROM blogs WHERE id = $1', [comment.rows[0].blog_id]);
    
    // Allow deletion if user owns comment or is the blog's mentor
    if (comment.rows[0].user_id === userId || (userRole === 'mentor' && blog.rows[0].mentor_id === userId)) {
      await pool.query('DELETE FROM blog_comments WHERE id = $1', [commentId]);
      await pool.query(
        'UPDATE blogs SET comments_count = comments_count - 1 WHERE id = $1',
        [comment.rows[0].blog_id]
      );
      res.json({ message: 'Comment deleted successfully' });
    } else {
      res.status(403).json({ error: 'Not authorized to delete this comment' });
    }
  } catch (error) {
    console.error('Delete comment error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Notifications
app.get('/api/notifications/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const result = await pool.query(
      'SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50',
      [userId]
    );
    
    res.json({ notifications: result.rows });
  } catch (error) {
    console.error('Get notifications error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/notifications/:userId/read', async (req, res) => {
  try {
    const { userId } = req.params;
    await pool.query(
      'UPDATE notifications SET is_read = true WHERE user_id = $1',
      [userId]
    );
    
    res.json({ message: 'All notifications marked as read' });
  } catch (error) {
    console.error('Mark notifications read error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/notifications/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    await pool.query(
      'DELETE FROM notifications WHERE user_id = $1',
      [userId]
    );
    
    res.json({ message: 'All notifications cleared' });
  } catch (error) {
    console.error('Clear notifications error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Community endpoints
app.get('/api/communities', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.*, u.username as mentor_name, mp.name as mentor_display_name
      FROM communities c
      JOIN users u ON c.mentor_id = u.id
      LEFT JOIN mentor_profiles mp ON c.mentor_id = mp.user_id
      WHERE c.is_active = true
      ORDER BY c.created_at DESC
    `);
    
    const communities = result.rows.map(community => ({
      ...community,
      mentor_name: community.mentor_display_name || community.mentor_name
    }));
    
    res.json({ communities });
  } catch (error) {
    console.error('Get communities error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/communities/mentor/:mentorId', async (req, res) => {
  try {
    const { mentorId } = req.params;
    const result = await pool.query(
      'SELECT * FROM communities WHERE mentor_id = $1 AND is_active = true ORDER BY created_at DESC',
      [mentorId]
    );
    
    res.json({ communities: result.rows });
  } catch (error) {
    console.error('Get mentor communities error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/communities', async (req, res) => {
  try {
    const { mentorId, name, description, interestCategory } = req.body;
    
    const result = await pool.query(
      'INSERT INTO communities (mentor_id, name, description, interest_category) VALUES ($1, $2, $3, $4) RETURNING *',
      [mentorId, name, description, interestCategory]
    );
    
    res.json({ message: 'Community created successfully', community: result.rows[0] });
  } catch (error) {
    console.error('Create community error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/communities/:communityId/join', async (req, res) => {
  try {
    const { communityId } = req.params;
    const { menteeId } = req.body;
    
    // Check if already joined
    const existing = await pool.query(
      'SELECT id FROM community_members WHERE community_id = $1 AND mentee_id = $2',
      [communityId, menteeId]
    );
    
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Already joined this community' });
    }
    
    // Add member
    await pool.query(
      'INSERT INTO community_members (community_id, mentee_id) VALUES ($1, $2)',
      [communityId, menteeId]
    );
    
    // Update member count
    await pool.query(
      'UPDATE communities SET member_count = member_count + 1 WHERE id = $1',
      [communityId]
    );
    
    // Create notification for mentor
    const community = await pool.query('SELECT mentor_id, name FROM communities WHERE id = $1', [communityId]);
    const mentee = await pool.query('SELECT username FROM users WHERE id = $1', [menteeId]);
    
    if (community.rows.length > 0 && mentee.rows.length > 0) {
      await pool.query(
        'INSERT INTO notifications (user_id, type, title, message, related_id, related_type) VALUES ($1, $2, $3, $4, $5, $6)',
        [community.rows[0].mentor_id, 'community_join', 'New Member', `${mentee.rows[0].username} joined your community "${community.rows[0].name}"`, communityId, 'community']
      );
    }
    
    res.json({ message: 'Joined community successfully' });
  } catch (error) {
    console.error('Join community error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/communities/:communityId/posts', async (req, res) => {
  try {
    const { communityId } = req.params;
    const result = await pool.query(`
      SELECT cp.*, u.username as mentor_name, mp.name as mentor_display_name
      FROM community_posts cp
      JOIN users u ON cp.mentor_id = u.id
      LEFT JOIN mentor_profiles mp ON cp.mentor_id = mp.user_id
      WHERE cp.community_id = $1
      ORDER BY cp.created_at DESC
    `, [communityId]);
    
    const posts = result.rows.map(post => ({
      ...post,
      mentor_name: post.mentor_display_name || post.mentor_name
    }));
    
    res.json({ posts });
  } catch (error) {
    console.error('Get community posts error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/communities/:communityId/posts', async (req, res) => {
  try {
    const { communityId } = req.params;
    const { mentorId, content, fileUrl, fileName, fileType, fileSize, postType } = req.body;
    
    console.log('Creating community post:', {
      communityId,
      mentorId,
      content: content?.substring(0, 50),
      fileName,
      fileType,
      fileSize,
      postType,
      fileUrlLength: fileUrl?.length
    });
    
    const result = await pool.query(
      'INSERT INTO community_posts (community_id, mentor_id, content, file_url, file_name, file_type, file_size, post_type) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [communityId, mentorId, content || null, fileUrl || null, fileName || null, fileType?.substring(0, 50) || null, fileSize || null, postType || 'text']
    );
    
    console.log('Post created successfully:', result.rows[0].id);
    
    // Notify all community members
    const members = await pool.query(
      'SELECT mentee_id FROM community_members WHERE community_id = $1',
      [communityId]
    );
    
    const community = await pool.query('SELECT name FROM communities WHERE id = $1', [communityId]);
    const mentor = await pool.query('SELECT username FROM users WHERE id = $1', [mentorId]);
    
    if (community.rows.length > 0 && mentor.rows.length > 0) {
      for (const member of members.rows) {
        await pool.query(
          'INSERT INTO notifications (user_id, type, title, message, related_id, related_type) VALUES ($1, $2, $3, $4, $5, $6)',
          [member.mentee_id, 'community_post', 'New Post', `${mentor.rows[0].username} posted in "${community.rows[0].name}"`, communityId, 'community']
        );
      }
    }
    
    res.json({ message: 'Post created successfully', post: result.rows[0] });
  } catch (error) {
    console.error('Create community post error:', error);
    console.error('Error details:', error.message);
    console.error('Error stack:', error.stack);
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

app.post('/api/communities/posts/:postId/react', async (req, res) => {
  try {
    const { postId } = req.params;
    const { userId, reactionType } = req.body;
    
    const existing = await pool.query(
      'SELECT id FROM community_post_reactions WHERE post_id = $1 AND user_id = $2',
      [postId, userId]
    );
    
    if (existing.rows.length > 0) {
      await pool.query(
        'UPDATE community_post_reactions SET reaction_type = $1 WHERE post_id = $2 AND user_id = $3',
        [reactionType, postId, userId]
      );
    } else {
      await pool.query(
        'INSERT INTO community_post_reactions (post_id, user_id, reaction_type) VALUES ($1, $2, $3)',
        [postId, userId, reactionType]
      );
    }
    
    res.json({ message: 'Reaction added successfully' });
  } catch (error) {
    console.error('React to post error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/communities/posts/:postId/reactions', async (req, res) => {
  try {
    const { postId } = req.params;
    const result = await pool.query(
      'SELECT reaction_type, COUNT(*) as count FROM community_post_reactions WHERE post_id = $1 GROUP BY reaction_type',
      [postId]
    );
    
    const reactions = {};
    result.rows.forEach(row => {
      reactions[row.reaction_type] = parseInt(row.count);
    });
    
    res.json({ reactions });
  } catch (error) {
    console.error('Get reactions error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/mentee/:menteeId/communities', async (req, res) => {
  try {
    const { menteeId } = req.params;
    const result = await pool.query(`
      SELECT c.*, cm.joined_at, u.username as mentor_name, mp.name as mentor_display_name
      FROM communities c
      JOIN community_members cm ON c.id = cm.community_id
      JOIN users u ON c.mentor_id = u.id
      LEFT JOIN mentor_profiles mp ON c.mentor_id = mp.user_id
      WHERE cm.mentee_id = $1 AND c.is_active = true
      ORDER BY cm.joined_at DESC
    `, [menteeId]);
    
    const communities = result.rows.map(community => ({
      ...community,
      mentor_name: community.mentor_display_name || community.mentor_name
    }));
    
    res.json({ communities });
  } catch (error) {
    console.error('Get mentee communities error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Video call endpoints
app.post('/api/video-call/token', async (req, res) => {
  try {
    const { channelName, uid, role } = req.body;
    
    if (!channelName || !uid) {
      return res.status(400).json({ error: 'Channel name and UID are required' });
    }
    
    const roleType = role === 'publisher' ? RtcRole.PUBLISHER : RtcRole.SUBSCRIBER;
    const expirationTimeInSeconds = 3600; // 1 hour
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

app.post('/api/video-call/request', async (req, res) => {
  try {
    const { menteeId, mentorId, channelName } = req.body;
    
    // Create call session with current server time
    const result = await pool.query(
      'INSERT INTO video_calls (mentee_id, mentor_id, channel_name, status, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [menteeId, mentorId, channelName, 'pending', new Date().toISOString()]
    );
    
    const callSession = result.rows[0];
    
    // Get mentor and mentee details
    const mentee = await pool.query('SELECT username FROM users WHERE id = $1', [menteeId]);
    const mentor = await pool.query('SELECT username FROM users WHERE id = $1', [mentorId]);
    
    // Create notification for mentor
    await pool.query(
      'INSERT INTO notifications (user_id, type, title, message, related_id, related_type) VALUES ($1, $2, $3, $4, $5, $6)',
      [mentorId, 'call_request', 'Video Call Request', `${mentee.rows[0].username} wants to start a video call with you`, callSession.id, 'video_call']
    );
    
    // Real-time notification removed for Vercel compatibility
    
    res.json({ callId: callSession.id, message: 'Call request sent' });
  } catch (error) {
    console.error('Call request error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/video-call/:callId/accept', async (req, res) => {
  try {
    const { callId } = req.params;
    const { mentorId } = req.body;
    
    // Update call status
    await pool.query(
      'UPDATE video_calls SET status = $1, accepted_at = $2 WHERE id = $3 AND mentor_id = $4',
      ['accepted', new Date().toISOString(), callId, mentorId]
    );
    
    // Get call details
    const call = await pool.query(
      'SELECT * FROM video_calls WHERE id = $1',
      [callId]
    );
    
    if (call.rows.length === 0) {
      return res.status(404).json({ error: 'Call not found' });
    }
    
    const callData = call.rows[0];
    
    // Real-time notification removed for Vercel compatibility
    
    res.json({ message: 'Call accepted', channelName: callData.channel_name });
  } catch (error) {
    console.error('Accept call error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/video-call/:callId/reject', async (req, res) => {
  try {
    const { callId } = req.params;
    const { mentorId } = req.body;
    
    // Update call status
    await pool.query(
      'UPDATE video_calls SET status = $1, ended_at = $2 WHERE id = $3 AND mentor_id = $4',
      ['rejected', new Date().toISOString(), callId, mentorId]
    );
    
    // Get call details
    const call = await pool.query(
      'SELECT mentee_id FROM video_calls WHERE id = $1',
      [callId]
    );
    
    if (call.rows.length > 0) {
      // Real-time notification removed for Vercel compatibility
    }
    
    res.json({ message: 'Call rejected' });
  } catch (error) {
    console.error('Reject call error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/video-call/:callId/start', async (req, res) => {
  try {
    const { callId } = req.params;
    const { userId, startTime } = req.body;
    
    // Check if session was already started
    const existingCall = await pool.query(
      'SELECT started_at FROM video_calls WHERE id = $1',
      [callId]
    );
    
    if (existingCall.rows.length > 0 && existingCall.rows[0].started_at) {
      // Session already started, return existing start time
      console.log(`[${new Date().toLocaleTimeString()}] Session ${callId} already started at ${existingCall.rows[0].started_at}`);
      return res.json({ 
        message: 'Session already started', 
        startTime: existingCall.rows[0].started_at 
      });
    }
    
    // Update call status to active with start time
    const startTimestamp = startTime ? new Date(startTime) : new Date();
    await pool.query(
      'UPDATE video_calls SET status = $1, started_at = $2 WHERE id = $3 AND started_at IS NULL',
      ['active', startTimestamp.toISOString(), callId]
    );
    
    // Get call participants
    const call = await pool.query(
      'SELECT mentee_id, mentor_id FROM video_calls WHERE id = $1',
      [callId]
    );
    
    if (call.rows.length > 0) {
      // Real-time notification removed for Vercel compatibility
    }
    
    // Schedule auto-end after 10 minutes
    const timeoutId = setTimeout(async () => {
      try {
        const endTime = new Date().toISOString();
        const result = await pool.query(
          'UPDATE video_calls SET status = $1, ended_at = $2 WHERE id = $3 AND status = $4 RETURNING *',
          ['completed', endTime, callId, 'active']
        );
        
        if (result.rows.length > 0) {
          console.log(`[${new Date().toLocaleTimeString()}] Auto-ended call ${callId} - Session completed after 10 minutes`);
          
          // Real-time notification removed for Vercel compatibility
        } else {
          console.log(`[${new Date().toLocaleTimeString()}] Call ${callId} was already ended`);
        }
      } catch (error) {
        console.error('Auto-end call error:', error);
      }
    }, 10 * 60 * 1000); // 10 minutes
    
    console.log(`[${new Date().toLocaleTimeString()}] Session ${callId} started - will auto-end in 10 minutes`);
    
    res.json({ message: 'Call started', startTime: startTimestamp.toISOString() });
  } catch (error) {
    console.error('Start call error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/video-call/:callId/end', async (req, res) => {
  try {
    const { callId } = req.params;
    const { userId } = req.body;
    
    // Update call status
    await pool.query(
      'UPDATE video_calls SET status = $1, ended_at = $2 WHERE id = $3',
      ['completed', new Date().toISOString(), callId]
    );
    
    // Get call participants
    const call = await pool.query(
      'SELECT mentee_id, mentor_id FROM video_calls WHERE id = $1',
      [callId]
    );
    
    if (call.rows.length > 0) {
      const otherUserId = userId === call.rows[0].mentee_id ? call.rows[0].mentor_id : call.rows[0].mentee_id;
      // Real-time notification removed for Vercel compatibility
    }
    
    res.json({ message: 'Call ended' });
  } catch (error) {
    console.error('End call error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/video-call/:callId/status', async (req, res) => {
  try {
    const { callId } = req.params;
    
    const result = await pool.query(
      'SELECT * FROM video_calls WHERE id = $1',
      [callId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Call not found' });
    }
    
    res.json({ call: result.rows[0] });
  } catch (error) {
    console.error('Get call status error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/video-calls/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    const result = await pool.query(`
      SELECT vc.*, 
             mentee.username as mentee_name,
             mentor.username as mentor_name
      FROM video_calls vc
      JOIN users mentee ON vc.mentee_id = mentee.id
      JOIN users mentor ON vc.mentor_id = mentor.id
      WHERE vc.mentee_id = $1 OR vc.mentor_id = $1
      ORDER BY vc.created_at DESC
      LIMIT 20
    `, [userId]);
    
    res.json({ calls: result.rows });
  } catch (error) {
    console.error('Get user calls error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/video-call/:callId', async (req, res) => {
  try {
    const { callId } = req.params;
    
    await pool.query(
      'DELETE FROM video_calls WHERE id = $1',
      [callId]
    );
    
    res.json({ message: 'Session deleted successfully' });
  } catch (error) {
    console.error('Delete session error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log(`[${new Date().toLocaleTimeString()}] Socket connected: ${socket.id}`);
  
  socket.on('join_user_room', (userId) => {
    socket.join(`user_${userId}`);
    console.log(`User ${userId} joined their room`);
  });
  
  socket.on('join_call', (callId) => {
    socket.join(`call_${callId}`);
    console.log(`User joined call room: ${callId}`);
  });
  
  socket.on('call_message', (data) => {
    // Broadcast to all users in the call room including sender
    io.to(`call_${data.callId}`).emit('call_message', data);
  });
  
  socket.on('timer_sync', (data) => {
    socket.to(`call_${data.callId}`).emit('timer_sync', data);
  });
  
  socket.on('session_started', (data) => {
    socket.to(`call_${data.callId}`).emit('session_started', data);
  });
  
  socket.on('user_joined', (data) => {
    socket.to(`call_${data.callId}`).emit('user_joined', data);
  });
  
  socket.on('user_left', (data) => {
    socket.to(`call_${data.callId}`).emit('user_left', data);
  });
  
  socket.on('force_end_call', (data) => {
    socket.to(`call_${data.callId}`).emit('force_end_call', data);
  });
  
  socket.on('disconnect', () => {
    console.log(`[${new Date().toLocaleTimeString()}] Socket disconnected: ${socket.id}`);
  });
  
  socket.on('join_user_room', (userId) => {
    console.log(`[${new Date().toLocaleTimeString()}] User ${userId} joined room: user_${userId}`);
  });
  
  socket.on('join_call', (callId) => {
    console.log(`[${new Date().toLocaleTimeString()}] User joined call room: call_${callId}`);
  });
});

// For Vercel serverless functions
if (process.env.VERCEL !== '1') {
  server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

// Export the Express app for Vercel
module.exports = (req, res) => {
  return app(req, res);
};