import React, { useState, useEffect } from 'react';
import axios from 'axios';
import CommunitySection from './CommunitySection';
import './CommunityBrowser.css';

const CommunityBrowser = ({ user }) => {
  const [availableCommunities, setAvailableCommunities] = useState([]);
  const [joinedCommunities, setJoinedCommunities] = useState([]);
  const [selectedCommunity, setSelectedCommunity] = useState(null);
  const [activeTab, setActiveTab] = useState('browse');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadAvailableCommunities();
    loadJoinedCommunities();
  }, []);

  const loadAvailableCommunities = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:5000/api/communities', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setAvailableCommunities(response.data.communities || []);
    } catch (error) {
      console.error('Failed to load communities:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadJoinedCommunities = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`http://localhost:5000/api/mentee/${user.id}/communities`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setJoinedCommunities(response.data.communities || []);
    } catch (error) {
      console.error('Failed to load joined communities:', error);
    }
  };

  const handleJoinCommunity = async (communityId) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post(`http://localhost:5000/api/communities/${communityId}/join`, {
        menteeId: user.id
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      alert('Successfully joined the community!');
      loadAvailableCommunities();
      loadJoinedCommunities();
    } catch (error) {
      console.error('Failed to join community:', error);
      alert('Failed to join community. You may have already joined.');
    }
  };

  const isAlreadyJoined = (communityId) => {
    return joinedCommunities.some(c => c.id === communityId);
  };

  if (selectedCommunity) {
    return (
      <div className="community-viewer">
        <div className="community-viewer-header">
          <button onClick={() => setSelectedCommunity(null)} className="back-btn">
            ← Back to Communities
          </button>
        </div>
        <CommunitySection 
          user={user} 
          userRole="mentee"
          selectedCommunity={selectedCommunity}
          onBack={() => setSelectedCommunity(null)}
        />
      </div>
    );
  }

  return (
    <div className="community-browser">
      <div className="community-tabs">
        <button 
          className={`tab-btn ${activeTab === 'browse' ? 'active' : ''}`}
          onClick={() => setActiveTab('browse')}
        >
          Browse Communities
        </button>
        <button 
          className={`tab-btn ${activeTab === 'joined' ? 'active' : ''}`}
          onClick={() => setActiveTab('joined')}
        >
          My Communities ({joinedCommunities.length})
        </button>
      </div>

      {activeTab === 'browse' && (
        <div className="browse-communities">
          <h2>Available Communities</h2>
          {loading ? (
            <div className="loading">Loading communities...</div>
          ) : (
            <div className="communities-grid">
              {availableCommunities.map(community => (
                <div key={community.id} className="community-card">
                  <div className="community-header">
                    <h3>{community.name}</h3>
                    <span className="community-category">{community.interest_category}</span>
                  </div>
                  
                  <p className="community-description">{community.description}</p>
                  
                  <div className="community-meta">
                    <div className="community-owner">
                      <span className="owner-label">Owner:</span>
                      <span className="owner-name">{community.mentor_name}</span>
                    </div>
                    <div className="member-count">
                      👥 {community.member_count} members
                    </div>
                  </div>
                  
                  <div className="community-actions">
                    {isAlreadyJoined(community.id) ? (
                      <button 
                        className="joined-btn"
                        onClick={() => setSelectedCommunity(community)}
                      >
                        ✓ Joined - View
                      </button>
                    ) : (
                      <button 
                        className="join-btn"
                        onClick={() => handleJoinCommunity(community.id)}
                      >
                        Join Community
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'joined' && (
        <div className="joined-communities">
          <h2>My Communities</h2>
          {joinedCommunities.length === 0 ? (
            <div className="no-communities">
              <div className="no-communities-icon">👥</div>
              <p>You haven't joined any communities yet.</p>
              <button 
                className="browse-btn"
                onClick={() => setActiveTab('browse')}
              >
                Browse Communities
              </button>
            </div>
          ) : (
            <div className="communities-grid">
              {joinedCommunities.map(community => (
                <div 
                  key={community.id} 
                  className="community-card joined"
                  onClick={() => setSelectedCommunity(community)}
                >
                  <div className="community-header">
                    <h3>{community.name}</h3>
                    <span className="community-category">{community.interest_category}</span>
                  </div>
                  
                  <p className="community-description">{community.description}</p>
                  
                  <div className="community-meta">
                    <div className="community-owner">
                      <span className="owner-label">Owner:</span>
                      <span className="owner-name">{community.mentor_name}</span>
                    </div>
                    <div className="member-count">
                      👥 {community.member_count} members
                    </div>
                  </div>
                  
                  <div className="join-date">
                    Joined {community.joined_at ? new Date(community.joined_at).toLocaleDateString() : 'Recently'}
  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default CommunityBrowser;