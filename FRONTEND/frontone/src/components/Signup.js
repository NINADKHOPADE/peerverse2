import React, { useState } from 'react';
import axios from 'axios';
import './Auth.css';

const Signup = ({ onSignup, onSwitchToLogin }) => {
  const [step, setStep] = useState(1); // 1: role selection, 2: form, 3: OTP
  const [formData, setFormData] = useState({
    role: '',
    username: '',
    email: '',
    phone: '',
    password: ''
  });
  const [otp, setOtp] = useState('');
  const [tempUserId, setTempUserId] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [usernameAvailable, setUsernameAvailable] = useState(null);

  const handleRoleSelect = (role) => {
    setFormData({ ...formData, role });
    setStep(2);
  };

  const handleInputChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
    setError('');
    
    if (e.target.name === 'username') {
      setUsernameAvailable(null);
    }
  };

  const checkUsername = async () => {
    if (formData.username.length < 3) return;
    
    try {
      const response = await axios.post('http://localhost:5000/api/check-username', {
        username: formData.username
      });
      setUsernameAvailable(response.data.available);
    } catch (error) {
      console.error('Username check failed');
    }
  };

  const handleSignup = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await axios.post('http://localhost:5000/api/signup', formData);
      setTempUserId(response.data.tempUserId);
      setStep(3);
    } catch (error) {
      setError(error.response?.data?.error || 'Signup failed');
    } finally {
      setLoading(false);
    }
  };

  const handleOtpVerification = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await axios.post('http://localhost:5000/api/verify-signup', {
        otp,
        tempUserId
      });
      
      localStorage.setItem('token', response.data.token);
      localStorage.setItem('user', JSON.stringify(response.data.user));
      onSignup(response.data.user);
    } catch (error) {
      setError(error.response?.data?.error || 'OTP verification failed');
    } finally {
      setLoading(false);
    }
  };

  // Step 1: Role Selection
  if (step === 1) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <h1>PeerSync</h1>
          <h2>Choose Your Role</h2>
          <div className="role-selection">
            <div className="role-card" onClick={() => handleRoleSelect('mentor')}>
              <div className="role-emoji">👨‍🏫</div>
              <h3>Mentor</h3>
              <p>Share your knowledge and guide others</p>
            </div>
            <div className="role-card" onClick={() => handleRoleSelect('mentee')}>
              <div className="role-emoji">👨‍🎓</div>
              <h3>Mentee</h3>
              <p>Learn from experienced mentors</p>
            </div>
          </div>
          <button onClick={onSwitchToLogin} className="link-btn">
            Already have an account? Sign In
          </button>
        </div>
      </div>
    );
  }

  // Step 3: OTP Verification
  if (step === 3) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <h2>Email Verification</h2>
          <p>We've sent an OTP to {formData.email}</p>
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
              {loading ? 'Verifying...' : 'Verify & Complete Signup'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  // Step 2: Signup Form
  return (
    <div className="auth-container">
      <div className="auth-card">
        <h1>PeerSync</h1>
        <h2>Sign Up as {formData.role === 'mentor' ? '👨‍🏫 Mentor' : '👨‍🎓 Mentee'}</h2>
        <form onSubmit={handleSignup}>
          <div className="username-field">
            <input
              type="text"
              name="username"
              placeholder="Username (unique)"
              value={formData.username}
              onChange={handleInputChange}
              onBlur={checkUsername}
              required
            />
            {usernameAvailable === false && (
              <div className="error">Username not available</div>
            )}
            {usernameAvailable === true && (
              <div className="success">Username available</div>
            )}
          </div>
          <input
            type="email"
            name="email"
            placeholder="Email"
            value={formData.email}
            onChange={handleInputChange}
            required
          />
          <input
            type="tel"
            name="phone"
            placeholder="Phone Number"
            value={formData.phone}
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
          <button 
            type="submit" 
            disabled={loading || usernameAvailable === false} 
            className="primary-btn"
          >
            {loading ? 'Creating Account...' : 'Sign Up'}
          </button>
        </form>
        
        <div className="auth-links">
          <button onClick={() => setStep(1)} className="link-btn">
            Back to Role Selection
          </button>
          <button onClick={onSwitchToLogin} className="link-btn">
            Already have an account? Sign In
          </button>
        </div>
      </div>
    </div>
  );
};

export default Signup;