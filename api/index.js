const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();

// Environment variables with fallbacks
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key';

app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'PeerSync Backend is running on Vercel!',
    timestamp: new Date().toISOString()
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', service: 'PeerSync API' });
});

// Basic auth endpoints (simplified for deployment)
app.post('/api/signup', (req, res) => {
  const { username, email, role } = req.body;
  
  if (!username || !email || !role) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  res.json({ 
    message: 'Signup successful - Database setup pending',
    tempUserId: 'temp123'
  });
});

app.post('/api/verify-signup', (req, res) => {
  const token = jwt.sign(
    { userId: 1, role: 'mentee' },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  res.json({
    message: 'Verification successful',
    token,
    user: { id: 1, username: 'demo', email: 'demo@example.com', role: 'mentee' }
  });
});

app.post('/api/login', (req, res) => {
  const { email, role } = req.body;
  
  if (!email || !role) {
    return res.status(400).json({ error: 'Email and role required' });
  }
  
  res.json({
    message: 'Login initiated - Database setup pending',
    userId: 1
  });
});

app.post('/api/verify-login', (req, res) => {
  const token = jwt.sign(
    { userId: 1, role: 'mentee' },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  res.json({
    message: 'Login successful',
    token,
    user: { id: 1, username: 'demo', email: 'demo@example.com', role: 'mentee' }
  });
});

// Basic endpoints
app.get('/api/mentors', (req, res) => {
  res.json({ mentors: [] });
});

app.post('/api/check-username', (req, res) => {
  res.json({ available: true });
});

// Catch all
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

module.exports = app;