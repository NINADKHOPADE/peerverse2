
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import MentorProfileEditor from './MentorProfileEditor';
import BlogSection from './BlogSection';
import CreateBlog from './CreateBlog';
import NotificationPanel from './NotificationPanel';
import CommunitySection from './CommunitySection';
import SessionsPanel from './SessionsPanel';
import './MentorDashboard.css';

const MentorDashboard = ({ user, onLogout, onJoinSession }) => {
  const [activeTab, setActiveTab] = useState('home');
  const [showProfileEditor, setShowProfileEditor] = useState(false);
  const [profileCompletion, setProfileCompletion] = useState(25);
  const [profilePicture, setProfilePicture] = useState('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGNpcmNsZSBjeD0iMzAiIGN5PSIzMCIgcj0iMzAiIGZpbGw9IiNFMUU1RTkiLz4KPHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeD0iMTgiIHk9IjE4Ij4KPHBhdGggZD0iTTEyIDEyQzE0LjIwOTEgMTIgMTYgMTAuMjA5MSAxNiA4QzE2IDUuNzkwODYgMTQuMjA5MSA0IDEyIDRDOS43OTA4NiA0IDggNS43OTA4NiA4IDhDOCAxMC4yMDkxIDkuNzkwODYgMTIgMTIgMTJaIiBmaWxsPSIjNjY3RUVBIi8+CjxwYXRoIGQ9Ik0xMiAxNEM5LjMzIDEzLjk5IDcuMDEgMTUuNjIgNiAxOEMxMC4wMSAyMCAxMy45OSAyMCAxOCAxOEMxNi45OSAxNS42MiAxNC42NyAxMy45OSAxMiAxNFoiIGZpbGw9IiM2NjdFRUEiLz4KPHN2Zz4KPHN2Zz4=');
  const [stats, setStats] = useState({
    totalSessions: 12,
    totalBlogs: 5,
    walletBalance: 2500
  });
  const [upcomingSessions, setUpcomingSessions] = useState([
    { id: 1, mentee: 'John Doe', date: '2024-01-15', time: '10:00 AM', topic: 'React Development' }
  ]);
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [showCreateBlog, setShowCreateBlog] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);

  const handleProfileSave = (profileData) => {
    setShowProfileEditor(false);
    // Update profile completion based on filled fields
    calculateProfileCompletion(profileData);
  };
  
  useEffect(() => {
    // Load profile data on mount
    loadProfileData();
    if (user?.id) {
      loadNotifications();
      
      // Set up periodic notification refresh
      const interval = setInterval(() => {
        loadNotifications();
      }, 30000); // Check every 30 seconds
      
      return () => clearInterval(interval);
    }
  }, [user]);

  const loadNotifications = async () => {
    if (!user?.id) return;
    
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`http://localhost:5000/api/notifications/${user.id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      const notifs = response.data.notifications || [];
      console.log('Loaded notifications for mentor:', notifs);
      setNotifications(notifs);
      setUnreadCount(notifs.filter(n => !n.is_read).length);
    } catch (error) {
      console.error('Failed to load notifications:', error);
    }
  };
  
  const loadProfileData = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`http://localhost:5000/api/mentor/profile/${user.id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.data.profile) {
        calculateProfileCompletion(response.data.profile);
      }
    } catch (error) {
      console.error('Failed to load profile:', error);
    }
  };

  const calculateProfileCompletion = (profile) => {
    let completed = 0;
    let total = 0;
    
    // Basic Info (3 fields)
    if (profile.basicInfo) {
      if (profile.basicInfo.name) completed++;
      if (profile.basicInfo.profilePicture) {
        completed++;
        setProfilePicture(profile.basicInfo.profilePicture);
      }
      if (profile.basicInfo.bio) completed++;
      total += 3;
    }
    
    // Education (at least 1 entry with degree and institution)
    if (profile.education && profile.education.length > 0) {
      const validEducation = profile.education.filter(edu => edu.degree && edu.institution);
      if (validEducation.length > 0) completed++;
    }
    total += 1;
    
    // Skills (at least 3 skills)
    if (profile.skills && profile.skills.length >= 3) {
      const validSkills = profile.skills.filter(skill => skill.name && skill.experience);
      if (validSkills.length >= 3) completed++;
    }
    total += 1;
    
    // Background (at least 1 job)
    if (profile.background && profile.background.length > 0) {
      const validJobs = profile.background.filter(job => job.company && job.position);
      if (validJobs.length > 0) completed++;
    }
    total += 1;
    
    // Interests (at least 5 interests)
    if (profile.interests && Array.isArray(profile.interests) && profile.interests.length >= 5) {
      completed++;
    }
    total += 1;
    
    // Languages (at least 2 languages)
    if (profile.languages && profile.languages.length >= 2) {
      const validLanguages = profile.languages.filter(lang => lang.name && lang.proficiency);
      if (validLanguages.length >= 2) completed++;
    }
    total += 1;
    
    // Availability
    if (profile.availability && profile.availability.timezone && profile.availability.preferredHours) {
      completed++;
    }
    total += 1;
    
    setProfileCompletion(Math.round((completed / total) * 100));
  };

  const renderHome = () => (
    <div className="home-content">
      <div className="welcome-header">
        <h2>Welcome, {user.username}!</h2>
        <p>Ready to mentor and inspire others today?</p>
      </div>

      <div className="profile-completion">
        <h3>Profile Completion: {profileCompletion}%</h3>
        <div className="progress-bar">
          <div className="progress-fill" style={{ width: `${profileCompletion}%` }}></div>
        </div>
        <button onClick={() => setActiveTab('profile')} className="complete-profile-btn">
          Complete Profile
        </button>
      </div>

      <div className="stats-section">
        <div className="stat-card">
          <h4>Total Sessions</h4>
          <span className="stat-number">{stats.totalSessions}</span>
        </div>
        <div className="stat-card">
          <h4>Total Blogs</h4>
          <span className="stat-number">{stats.totalBlogs}</span>
        </div>
        <div className="stat-card">
          <h4>Wallet Balance</h4>
          <span className="stat-number">₹{stats.walletBalance}</span>
        </div>
      </div>

      <div className="upcoming-sessions">
        <h3>Upcoming Sessions</h3>
        {upcomingSessions.length > 0 ? (
          upcomingSessions.map(session => (
            <div key={session.id} className="session-card">
              <div className="session-info">
                <h4>{session.mentee}</h4>
                <p>{session.date} at {session.time}</p>
                <p>{session.topic}</p>
              </div>
              <div className="session-actions">
                <button className="start-btn">Start Session</button>
                <button className="complete-btn">Mark Completed</button>
              </div>
            </div>
          ))
        ) : (
          <p>No upcoming sessions</p>
        )}
      </div>

      <div className="recent-notifications">
        <h3>Recent Notifications</h3>
        {notifications.length > 0 ? (
          <ul>
            {notifications.slice(0, 3).map((notification, index) => (
              <li key={notification.id || index}>
                {typeof notification === 'string' ? notification : notification.message || notification.title}
              </li>
            ))}
          </ul>
        ) : (
          <p>No new notifications</p>
        )}
      </div>
    </div>
  );

  const renderSessions = () => (
    <SessionsPanel 
      user={user} 
      onJoinSession={onJoinSession}
    />
  );

  const renderBlogs = () => {
    if (showCreateBlog) {
      return (
        <CreateBlog 
          user={user} 
          onBack={() => setShowCreateBlog(false)}
        />
      );
    }
    
    return (
      <div className="blogs-content">
        <div className="blogs-header">
          <h3>My Blogs</h3>
          <button 
            className="create-blog-btn"
            onClick={() => setShowCreateBlog(true)}
          >
            ➕ Create Blog
          </button>
        </div>
        <BlogSection user={user} userRole="mentor" />
      </div>
    );
  };

  const renderCommunity = () => (
    <div className="community-content">
      <CommunitySection user={user} userRole="mentor" />
    </div>
  );

  const renderWallet = () => (
    <div className="wallet-content">
      <div className="wallet-balance">
        <h3>Current Wallet Balance: ₹{stats.walletBalance}</h3>
      </div>
      <div className="transaction-history">
        <h4>Recent Transactions</h4>
        <div className="transaction-item">
          <span>Session with John Doe</span>
          <span>+₹500</span>
        </div>
      </div>
    </div>
  );

  const renderNotifications = () => (
    <div className="notifications-content">
      <div className="notifications-header">
        <h3>Notifications</h3>
        <button 
          className="clear-all-btn"
          onClick={async () => {
            try {
              const token = localStorage.getItem('token');
              await axios.delete(`http://localhost:5000/api/notifications/${user.id}`, {
                headers: { Authorization: `Bearer ${token}` }
              });
              setNotifications([]);
              setUnreadCount(0);
              // Clear cache
              localStorage.removeItem(`notifications_${user.id}`);
              localStorage.removeItem(`notifications_${user.id}_time`);
            } catch (error) {
              console.error('Failed to clear notifications:', error);
            }
          }}
        >
          Clear All
        </button>
      </div>
      
      <div className="notification-list">
        {notifications.length > 0 ? (
          notifications.map((notification, index) => (
            <div key={notification.id || index} className={`notification-item ${!notification.is_read ? 'unread' : ''}`}>
              <div className="notification-title">{notification.title || 'Notification'}</div>
              <div className="notification-message">
                {typeof notification === 'string' ? notification : (notification.message || 'No message')}
              </div>
              <div className="notification-time">
                {notification.created_at ? new Date(notification.created_at).toLocaleString('en-US', { 
                  month: 'short', 
                  day: 'numeric',
                  hour: '2-digit', 
                  minute: '2-digit',
                  hour12: true 
                }) : ''}
              </div>
            </div>
          ))
        ) : (
          <p>No notifications</p>
        )}
      </div>
    </div>
  );

  const renderSettings = () => (
    <div className="settings-content">
      <h3>Settings</h3>
      <div className="settings-section">
        <h4>Profile Settings</h4>
        <button onClick={() => setActiveTab('profile')} className="edit-profile-btn">
          Edit Profile
        </button>
      </div>
    </div>
  );

  const renderProfile = () => (
    <div className="profile-content">
      <div className="profile-header-section">
        <h2>Edit Profile</h2>
        <p>Complete your mentor profile to attract more mentees</p>
      </div>
      <MentorProfileEditor
        user={user}
        onClose={() => setActiveTab('home')}
        onSave={handleProfileSave}
        embedded={true}
      />
    </div>
  );

  const renderContent = () => {
    switch (activeTab) {
      case 'home': return renderHome();
      case 'profile': return renderProfile();
      case 'sessions': return renderSessions();
      case 'blogs': return renderBlogs();
      case 'community': return renderCommunity();
      case 'wallet': return renderWallet();
      case 'notifications': return renderNotifications();
      case 'settings': return renderSettings();
      default: return renderHome();
    }
  };

  return (
    <div className="mentor-dashboard">
      <div className="sidebar">
        <div className="sidebar-header">
          <h2>PeerSync</h2>
        </div>
        
        <div className="mentor-profile-section">
          <div className="mentor-avatar">
            <img src={profilePicture} alt="Profile" />
          </div>
          <div className="mentor-info">
            <h4>{user.username}</h4>
            <p>Mentor</p>
          </div>
        </div>
        
        <nav className="sidebar-nav">
          <button 
            className={`nav-btn ${activeTab === 'home' ? 'active' : ''}`}
            onClick={() => setActiveTab('home')}
          >
            🏠 Home
          </button>
          <button 
            className={`nav-btn ${activeTab === 'profile' ? 'active' : ''}`}
            onClick={() => setActiveTab('profile')}
          >
            👤 Edit Profile
          </button>
          <button 
            className={`nav-btn ${activeTab === 'sessions' ? 'active' : ''}`}
            onClick={() => setActiveTab('sessions')}
          >
            📅 Sessions
          </button>
          <button 
            className={`nav-btn ${activeTab === 'blogs' ? 'active' : ''}`}
            onClick={() => setActiveTab('blogs')}
          >
            📝 Blogs
          </button>
          <button 
            className={`nav-btn ${activeTab === 'community' ? 'active' : ''}`}
            onClick={() => setActiveTab('community')}
          >
            👥 Community
          </button>
          <button 
            className={`nav-btn ${activeTab === 'wallet' ? 'active' : ''}`}
            onClick={() => setActiveTab('wallet')}
          >
            💰 Wallet
          </button>
          <button 
            className={`nav-btn ${activeTab === 'notifications' ? 'active' : ''}`}
            onClick={() => {
              setActiveTab('notifications');
              loadNotifications();
            }}
          >
            🔔 Notifications
            {unreadCount > 0 && (
              <span className="notification-badge">{unreadCount}</span>
            )}
          </button>
          <button 
            className={`nav-btn ${activeTab === 'settings' ? 'active' : ''}`}
            onClick={() => setActiveTab('settings')}
          >
            ⚙ Settings
          </button>
          <button className="nav-btn logout-btn" onClick={onLogout}>
            🚪 Logout
          </button>
        </nav>
      </div>

      <div className="main-content">
        {renderContent()}
      </div>

      <NotificationPanel 
        user={user}
        isOpen={showNotifications}
        onClose={() => {
          setShowNotifications(false);
          loadNotifications();
        }}
      />
    </div>
  );
};

export default MentorDashboard;