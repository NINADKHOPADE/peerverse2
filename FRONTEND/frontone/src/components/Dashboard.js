
import React, { useState } from 'react';
import MentorProfileEditor from './MentorProfileEditor';
import './Auth.css';

const Dashboard = ({ user, onLogout }) => {
  const [showProfileEditor, setShowProfileEditor] = useState(false);

  const handleProfileSave = (profileData) => {
    console.log('Profile saved:', profileData);
    setShowProfileEditor(false);
  };
  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <h1>PeerSync Dashboard</h1>
        <button onClick={onLogout} className="logout-btn">
          Logout
        </button>
      </div>
      
      <div className="dashboard-content">
        <div className="welcome-card">
          <div className="user-info">
            <div className="user-avatar">
              {user.role === 'mentor' ? '👨🏫' : '👨🎓'}
            </div>
            <div className="user-details">
              <h2>Welcome, {user.username}!</h2>
              <p className="user-role">
                Role: <span className="role-badge">{user.role}</span>
              </p>
              <p className="user-email">Email: {user.email}</p>
            </div>
          </div>
        </div>

        <div className="dashboard-features">
          <div className="feature-grid">
            {user.role === 'mentor' ? (
              <>
                <div className="feature-card" onClick={() => setShowProfileEditor(true)}>
                  <h4>👤 Edit Profile</h4>
                  <p>Update your mentor profile</p>
                </div>
                <div className="feature-card">
                  <h4>👥 My Mentees</h4>
                  <p>View and interact with your mentees</p>
                </div>
                <div className="feature-card">
                  <h4>📊 Analytics</h4>
                  <p>Track your mentoring progress</p>
                </div>
              </>
            ) : (
              <>
                <div className="feature-card">
                  <h4>🔍 Find Mentors</h4>
                  <p>Discover mentors in your field</p>
                </div>
                <div className="feature-card">
                  <h4>📖 My Learning</h4>
                  <p>Track your learning journey</p>
                </div>
                <div className="feature-card">
                  <h4>💬 Messages</h4>
                  <p>Chat with your mentors</p>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
      
      {showProfileEditor && (
        <MentorProfileEditor
          user={user}
          onClose={() => setShowProfileEditor(false)}
          onSave={handleProfileSave}
        />
      )}
    </div>
  );
};

export default Dashboard;