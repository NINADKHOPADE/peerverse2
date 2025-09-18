import React, { useState } from 'react';
import axios from 'axios';
import './Auth.css';

const Login = ({ onLogin, onSwitchToSignup, onForgotPassword }) => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    role: ''
  });
  const [otp, setOtp] = useState('');
  const [showOtpInput, setShowOtpInput] = useState(false);
  const [userId, setUserId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleInputChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
    setError('');
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const apiBase = process.env.NODE_ENV === 'production' ? '' : 'http://localhost:5000';
      const response = await axios.post(`${apiBase}/api/login`, formData);
      setUserId(response.data.userId);
      setShowOtpInput(true);
      setError('');
    } catch (error) {
      setError(error.response?.data?.error || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleOtpVerification = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const apiBase = process.env.NODE_ENV === 'production' ? '' : 'http://localhost:5000';
      const response = await axios.post(`${apiBase}/api/verify-login`, {
        otp,
        userId
      });
      
      localStorage.setItem('token', response.data.token);
      localStorage.setItem('user', JSON.stringify(response.data.user));
      onLogin(response.data.user);
    } catch (error) {
      setError(error.response?.data?.error || 'OTP verification failed');
    } finally {
      setLoading(false);
    }
  };

  if (showOtpInput) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <h2>Email Verification</h2>
          <p>We've sent an OTP to your registered email</p>
          <form onSubmit={handleOtpVerification}>
            <input
              type="text"
              placeholder="Enter 6-digit OTP"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
              maxLength="6"
              required
            />
            {error && <div className="error">{error}</div>}
            <button type="submit" disabled={loading}>
              {loading ? 'Verifying...' : 'Verify OTP'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-container">
      <div className="auth-card">
        <h1>PeerSync</h1>
        <h2>Sign In</h2>
        <form onSubmit={handleLogin}>
          <select
            name="role"
            value={formData.role}
            onChange={handleInputChange}
            required
          >
            <option value="">Select Role</option>
            <option value="mentor">👨🏫 Mentor</option>
            <option value="mentee">👨🎓 Mentee</option>
          </select>
          <input
            type="email"
            name="email"
            placeholder="Email"
            value={formData.email}
            onChange={handleInputChange}
            required
          />
          <input
            type="password"
            name="password"
            placeholder="Password"
            value={formData.password}
            onChange={handleInputChange}
            required
          />
          {error && <div className="error">{error}</div>}
          <button type="submit" disabled={loading} className="primary-btn">
            {loading ? 'Signing In...' : 'Sign In'}
          </button>
        </form>
        
        <div className="auth-links">
          <button onClick={onForgotPassword} className="link-btn">
            Forgot Password?
          </button>
          <button onClick={onSwitchToSignup} className="link-btn">
            Sign Up
          </button>
        </div>
      </div>
    </div>
  );
};

export default Login;