import React, { useState, useEffect } from 'react';
import axios from 'axios';
import BlogSection from './BlogSection';
import NotificationPanel from './NotificationPanel';
import CommunityBrowser from './CommunityBrowser';
import VideoCall from './VideoCall';
import CallRequestModal from './CallRequestModal';

import SessionsPanel from './SessionsPanel';
import './MenteeDashboard.css';

const MenteeDashboard = ({ user, onLogout, onJoinSession }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedInterest, setSelectedInterest] = useState('');
  const [mentors, setMentors] = useState([]);
  const [filteredMentors, setFilteredMentors] = useState([]);
  const [loading, setLoading] = useState(false);

  const interestCategories = {
    placement: ['DSA', 'Frontend Development', 'Backend Development', 'Full Stack', 'Mobile Development'],
    skills_learning: ['JavaScript', 'Python', 'Java', 'React', 'Node.js'],
    projects: ['Web Development', 'Mobile Apps', 'AI/ML Projects', 'Blockchain'],
    study_help: ['Mathematics', 'Computer Science', 'GATE Preparation']
  };

  useEffect(() => {
    loadMentors();
  }, []);

  const loadMentors = async () => {
    setLoading(true);
    try {
      // Check cache first
      const cacheKey = 'mentors_list';
      const cached = localStorage.getItem(cacheKey);
      const cacheTime = localStorage.getItem(`${cacheKey}_time`);
      
      if (cached && cacheTime && Date.now() - parseInt(cacheTime) < 15 * 60 * 1000) {
        const mentorsData = JSON.parse(cached);
        setMentors(mentorsData);
        setFilteredMentors(mentorsData);
        setLoading(false);
        return;
      }
      
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:5000/api/mentors', {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      const mentorsData = response.data.mentors || [];
      setMentors(mentorsData);
      setFilteredMentors(mentorsData);
      
      // Cache the result
      localStorage.setItem(cacheKey, JSON.stringify(mentorsData));
      localStorage.setItem(`${cacheKey}_time`, Date.now().toString());
    } catch (error) {
      console.error('Failed to load mentors:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = () => {
    let filtered = mentors;
    
    // Text search
    if (searchQuery) {
      filtered = filtered.filter(mentor => 
        mentor.name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        mentor.bio?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        mentor.skills?.some(skill => {
          const skillName = typeof skill === 'object' ? skill.name : skill;
          return skillName?.toLowerCase().includes(searchQuery.toLowerCase());
        })
      );
    }
    
    // College filter
    if (selectedFilters.college) {
      filtered = filtered.filter(mentor => {
        if (mentor.education && mentor.education.length > 0) {
          const college = mentor.education[0].institution || mentor.education[0].school;
          return college?.trim() === selectedFilters.college;
        }
        return false;
      });
    }
    
    // Skill filter
    if (selectedFilters.skill) {
      filtered = filtered.filter(mentor => 
        mentor.skills?.some(skill => {
          const skillName = typeof skill === 'object' ? skill.name : skill;
          return skillName?.toLowerCase().trim() === selectedFilters.skill;
        })
      );
    }
    
    // Language filter
    if (selectedFilters.language) {
      filtered = filtered.filter(mentor => 
        mentor.languages?.some(language => {
          const langName = typeof language === 'object' ? language.name : language;
          return langName?.toLowerCase().trim() === selectedFilters.language;
        })
      );
    }
    
    // Interest filter
    if (selectedFilters.interest) {
      filtered = filtered.filter(mentor => {
        if (Array.isArray(mentor.interests)) {
          return mentor.interests.includes(selectedFilters.interest);
        }
        return false;
      });
    }
    
    // Company filter
    if (selectedFilters.company) {
      filtered = filtered.filter(mentor => 
        mentor.background?.some(bg => {
          const company = bg.company || bg.organization;
          return company?.trim() === selectedFilters.company;
        })
      );
    }
    

    
    // Legacy interest filter
    if (selectedInterest) {
      filtered = filtered.filter(mentor => 
        mentor.interests?.some(interest => {
          const interestName = typeof interest === 'object' ? interest.name : interest;
          return interestName?.toLowerCase().includes(selectedInterest.toLowerCase());
        })
      );
    }
    
    setFilteredMentors(filtered);
  };

  const [favorites, setFavorites] = useState([]);
  const [currentSection, setCurrentSection] = useState('home');
  const [showNotifications, setShowNotifications] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const [selectedMentor, setSelectedMentor] = useState(null);
  const [showFilters, setShowFilters] = useState(false);
  const [filters, setFilters] = useState({
    colleges: [],
    skills: [],
    languages: [],
    interests: [],
    companies: []
  });
  const [selectedFilters, setSelectedFilters] = useState({
    college: '',
    skill: '',
    language: '',
    interest: '',
    company: ''
  });
  const [activeCall, setActiveCall] = useState(null);
  const [showCallModal, setShowCallModal] = useState(false);


  const mainInterests = [
    'PLACEMENT', 'COLLEGE REVIEWS', 'SKILLS LEARNING', 
    'PROJECTS', 'HACKATHONS', 'STUDY HELP'
  ];

  useEffect(() => {
    if (user?.id) {
      loadFavorites();
      loadUnreadCount();
    }
  }, [user]);

  useEffect(() => {
    if (mentors.length > 0) {
      generateFilters();
    }
  }, [mentors]);

  const generateFilters = () => {
    const colleges = new Set();
    const skills = new Set();
    const languages = new Set();
    const companies = new Set();

    mentors.forEach(mentor => {
      // Extract college from education (original names)
      if (mentor.education && mentor.education.length > 0) {
        const college = mentor.education[0].institution || mentor.education[0].school;
        if (college) colleges.add(college.trim());
      }
      
      // Extract skills (original names)
      mentor.skills?.forEach(skill => {
        const skillName = typeof skill === 'object' ? skill.name : skill;
        if (skillName) skills.add(skillName.trim());
      });
      
      // Extract languages (original names)
      mentor.languages?.forEach(language => {
        const langName = typeof language === 'object' ? language.name : language;
        if (langName) languages.add(langName.trim());
      });
      
      // Extract companies from background (original names)
      mentor.background?.forEach(bg => {
        const company = bg.company || bg.organization;
        if (company) companies.add(company.trim());
      });
    });

    setFilters({
      colleges: Array.from(colleges).sort(),
      skills: Array.from(skills).sort(),
      languages: Array.from(languages).sort(),
      interests: mainInterests,
      companies: Array.from(companies).sort()
    });
  };

  const clearFilters = () => {
    setSelectedFilters({
      college: '',
      skill: '',
      language: '',
      interest: '',
      company: ''
    });
    setSelectedInterest('');
    setSearchQuery('');
    setFilteredMentors(mentors);
  };

  const handleFilterChange = (filterType, value) => {
    setSelectedFilters(prev => ({
      ...prev,
      [filterType]: value
    }));
    setTimeout(() => handleSearch(), 100);
  };

  const loadFavorites = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`http://localhost:5000/api/mentee/${user.id}/favorites`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setFavorites(response.data.favorites || []);
    } catch (error) {
      console.error('Failed to load favorites:', error);
    }
  };

  const handleCall = async (mentorId) => {
    try {
      console.log('Initiating call to mentor:', mentorId);
      const channelName = `call_${Date.now()}_${user.id}_${mentorId}`;
      
      const response = await axios.post('http://localhost:5000/api/video-call/request', {
        menteeId: user.id,
        mentorId,
        channelName
      });
      
      console.log('Call request response:', response.data);
      alert('Call request sent to mentor. Check Sessions tab to join when accepted.');
    } catch (error) {
      console.error('Failed to initiate call:', error);
      alert('Failed to initiate call. Please try again.');
    }
  };

  const handleMessage = (mentorId) => {
    // Simulate messaging
    alert(`Opening chat with mentor. This feature will be implemented with real-time messaging.`);
  };

  const handleFavorite = async (mentorId) => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.post('http://localhost:5000/api/mentee/favorite', {
        menteeId: user.id,
        mentorId
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.data.favorited) {
        setFavorites([...favorites, mentorId]);
      } else {
        setFavorites(favorites.filter(id => id !== mentorId));
      }
    } catch (error) {
      console.error('Failed to update favorite:', error);
    }
  };

  const loadUnreadCount = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`http://localhost:5000/api/notifications/${user.id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const unread = response.data.notifications?.filter(n => !n.is_read).length || 0;
      setUnreadCount(unread);
    } catch (error) {
      console.error('Failed to load notification count:', error);
    }
  };

  const renderMentorCard = (mentor) => {
    const college = mentor.education && mentor.education.length > 0 
      ? mentor.education[0].institution || mentor.education[0].school || 'Not specified'
      : 'Not specified';
    
    return (
      <div key={mentor.id} className="mentor-card" onClick={() => setSelectedMentor(mentor)}>
        <div className="mentor-header">
          <div className="mentor-avatar">
            <img src={mentor.profilePicture || 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iODAiIGhlaWdodD0iODAiIHZpZXdCb3g9IjAgMCA4MCA4MCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGNpcmNsZSBjeD0iNDAiIGN5PSI0MCIgcj0iNDAiIGZpbGw9IiNFMUU1RTkiLz4KPHN2ZyB3aWR0aD0iMzIiIGhlaWdodD0iMzIiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeD0iMjQiIHk9IjI0Ij4KPHBhdGggZD0iTTEyIDEyQzE0LjIwOTEgMTIgMTYgMTAuMjA5MSAxNiA4QzE2IDUuNzkwODYgMTQuMjA5MSA0IDEyIDRDOS43OTA4NiA0IDggNS43OTA4NiA4IDhDOCAxMC4yMDkxIDkuNzkwODYgMTIgMTIgMTJaIiBmaWxsPSIjNjY3RUVBIi8+CjxwYXRoIGQ9Ik0xMiAxNEM5LjMzIDEzLjk5IDcuMDEgMTUuNjIgNiAxOEMxMC4wMSAyMCAxMy45OSAyMCAxOCAxOEMxNi45OSAxNS42MiAxNC42NyAxMy45OSAxMiAxNFoiIGZpbGw9IiM2NjdFRUEiLz4KPHN2Zz4KPHN2Zz4='} alt={mentor.name} />
          </div>
          <div className="mentor-basic-info">
            <h3>{mentor.name}</h3>
            <p className="mentor-college">{college}</p>
            <div className="mentor-rating">
              <span>⭐ {mentor.rating || 4.8} ({mentor.reviewCount || 25} reviews)</span>
            </div>
          </div>
          <button 
            onClick={(e) => { e.stopPropagation(); handleFavorite(mentor.id); }} 
            className={`favorite-icon ${favorites.includes(mentor.id) ? 'favorited' : ''}`}
          >
            {favorites.includes(mentor.id) ? '💖' : '🤍'}
          </button>
        </div>
        
        <div className="mentor-skills-section">
          <h4>Skills:</h4>
          <div className="skills-list">
            {mentor.skills?.slice(0, 4).map((skill, index) => (
              <span key={index} className="skill-tag">{typeof skill === 'object' ? skill.name : skill}</span>
            ))}
            {mentor.skills?.length > 4 && (
              <span className="more-skills">+{mentor.skills.length - 4} more</span>
            )}
          </div>
        </div>
        
        <div className="mentor-interests-section">
          <h4>Interests:</h4>
          <div className="interests-list">
            {Array.isArray(mentor.interests) && mentor.interests.length > 0 ? (
              mentor.interests.slice(0, 3).map((interest, index) => (
                <span key={index} className="category-tag">{interest}</span>
              ))
            ) : (
              <span className="no-interests">No interests listed</span>
            )}
            {mentor.interests?.length > 3 && (
              <span className="more-interests">+{mentor.interests.length - 3} more</span>
            )}
          </div>
        </div>
        
        <div className="mentor-actions">
          <button onClick={(e) => { e.stopPropagation(); handleCall(mentor.id); }} className="action-btn call">
            📞 Call
          </button>
          <button onClick={(e) => { e.stopPropagation(); handleMessage(mentor.id); }} className="action-btn message">
            💬 Message
          </button>
          <button onClick={(e) => { e.stopPropagation(); setSelectedMentor(mentor); }} className="action-btn view">
            👁️ View Profile
          </button>
        </div>
      </div>
    );
  };

  const handleCallStart = (callId, channelName) => {
    setActiveCall({ callId, channelName });
    setShowCallModal(false);
  };

  const handleCallEnd = () => {
    setActiveCall(null);
  };

  if (activeCall) {
    return (
      <VideoCall 
        callId={activeCall.callId}
        user={user}
        onEndCall={handleCallEnd}
      />
    );
  }

  return (
    <div className="mentee-dashboard">
      {/* Header */}
      <header className="dashboard-header">
        <div className="header-left">
          <h1 className="app-name">PeerSync</h1>
          <nav className="main-nav">
            <button 
              className={`nav-link ${currentSection === 'home' ? 'active' : ''}`}
              onClick={() => setCurrentSection('home')}
            >
              Home
            </button>
            <button 
              className={`nav-link ${currentSection === 'mentors' ? 'active' : ''}`}
              onClick={() => setCurrentSection('mentors')}
            >
              Mentors
            </button>
            <button 
              className={`nav-link ${currentSection === 'blogs' ? 'active' : ''}`}
              onClick={() => setCurrentSection('blogs')}
            >
              Blogs
            </button>
            <button 
              className={`nav-link ${currentSection === 'community' ? 'active' : ''}`}
              onClick={() => setCurrentSection('community')}
            >
              Community
            </button>
            <button 
              className={`nav-link ${currentSection === 'sessions' ? 'active' : ''}`}
              onClick={() => setCurrentSection('sessions')}
            >
              Sessions
            </button>
            <button className="nav-link">Wallet</button>
          </nav>
        </div>
        <div className="header-right">
          <button 
            className="notification-btn"
            onClick={() => setShowNotifications(true)}
          >
            🔔
            {unreadCount > 0 && <span className="notification-badge">{unreadCount}</span>}
          </button>
          <div className="user-profile">
            <img src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHZpZXdCb3g9IjAgMCA0MCA0MCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGNpcmNsZSBjeD0iMjAiIGN5PSIyMCIgcj0iMjAiIGZpbGw9IiNFMUU1RTkiLz4KPHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeD0iMTIiIHk9IjEyIj4KPHBhdGggZD0iTTEyIDEyQzE0LjIwOTEgMTIgMTYgMTAuMjA5MSAxNiA4QzE2IDUuNzkwODYgMTQuMjA5MSA0IDEyIDRDOS43OTA4NiA0IDggNS43OTA4NiA4IDhDOCAxMC4yMDkxIDkuNzkwODYgMTIgMTIgMTJaIiBmaWxsPSIjNjY3RUVBIi8+CjxwYXRoIGQ9Ik0xMiAxNEM5LjMzIDEzLjk5IDcuMDEgMTUuNjIgNiAxOEMxMC4wMSAyMCAxMy45OSAyMCAxOCAxOEMxNi45OSAxNS42MiAxNC42NyAxMy45OSAxMiAxNFoiIGZpbGw9IiM2NjdFRUEiLz4KPHN2Zz4KPHN2Zz4=" alt="Profile" />
            <span>{user.username}</span>
            <button onClick={onLogout} className="logout-btn">Logout</button>
          </div>
        </div>
      </header>

      {currentSection === 'home' && (
        <>

          
          {/* Stats Section */}
          <div className="stats-section">
            <div className="stats-container">
              <div className="stat-item">
                <div className="stat-number">{filteredMentors.length}</div>
                <div className="stat-label">Available Mentors</div>
              </div>
              <div className="stat-item">
                <div className="stat-number">{favorites.length}</div>
                <div className="stat-label">Favorite Mentors</div>
              </div>
              <div className="stat-item">
                <div className="stat-number">0</div>
                <div className="stat-label">Completed Sessions</div>
              </div>
              <div className="stat-item">
                <div className="stat-number">0</div>
                <div className="stat-label">Hours Learned</div>
              </div>
            </div>
          </div>

          {/* Search Section */}
          <div className="search-section">
            <div className="search-container">
              <div className="search-bar">
                <input
                  type="text"
                  placeholder="Search mentors by name, skills, interests..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
                />
                <button onClick={handleSearch} className="search-btn">
                  🔍 Search
                </button>
              </div>
              <div className="browse-dropdown">
                <select
                  value={selectedInterest}
                  onChange={(e) => {
                    setSelectedInterest(e.target.value);
                    setTimeout(handleSearch, 100);
                  }}
                >
                  <option value="">Browse by Interest</option>
                  {Object.entries(interestCategories).map(([category, interests]) => (
                    <optgroup key={category} label={category.replace('_', ' ').toUpperCase()}>
                      {interests.map(interest => (
                        <option key={interest} value={interest}>{interest}</option>
                      ))}
                    </optgroup>
                  ))}
                </select>
              </div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="quick-actions">
            <div className="quick-actions-container">
              <button className="quick-action-btn" onClick={() => {
                setSelectedInterest('');
                setSearchQuery('');
                setTimeout(handleSearch, 100);
              }}>
                🔍 All Mentors
              </button>
              <button className="quick-action-btn" onClick={() => {
                setSelectedInterest('JavaScript');
                setTimeout(handleSearch, 100);
              }}>
                💻 JavaScript
              </button>
              <button className="quick-action-btn" onClick={() => {
                setSelectedInterest('Python');
                setTimeout(handleSearch, 100);
              }}>
                🐍 Python
              </button>
              <button className="quick-action-btn" onClick={() => {
                setSelectedInterest('React');
                setTimeout(handleSearch, 100);
              }}>
                ⚛️ React
              </button>
            </div>
          </div>

          {/* Mentors Grid */}
          <div className="mentors-section">
            <div className="section-header">
              <h2>Available Mentors</h2>
              <span className="results-count">
                {filteredMentors.length} mentors found
              </span>
            </div>
            
            {loading ? (
              <div className="loading-container">
                <div className="loading-spinner"></div>
                <p>Loading mentors...</p>
              </div>
            ) : (
              <div className="mentors-grid">
                {filteredMentors.length > 0 ? (
                  filteredMentors.map(renderMentorCard)
                ) : (
                  <div className="no-mentors">
                    <h3>No mentors found</h3>
                    <p>Try adjusting your search criteria</p>
                  </div>
                )}
              </div>
            )}
          </div>
        </>
      )}

      {currentSection === 'mentors' && (
        <div className="mentors-page">
          {/* Advanced Filters */}
          <div className="filters-section">
            <div className="filters-header">
              <h2>Find Mentors</h2>
              <button 
                onClick={() => setShowFilters(!showFilters)} 
                className="filter-toggle-btn"
              >
                🔍 Filters {showFilters ? '▲' : '▼'}
              </button>
            </div>
            
            {showFilters && (
              <div className="filters-grid">
                <div className="filter-group">
                  <label>College/University</label>
                  <select 
                    value={selectedFilters.college} 
                    onChange={(e) => handleFilterChange('college', e.target.value)}
                  >
                    <option value="">All Colleges</option>
                    {filters.colleges.map(college => (
                      <option key={college} value={college}>
                        {college}
                      </option>
                    ))}
                  </select>
                </div>
                
                <div className="filter-group">
                  <label>Skills</label>
                  <select 
                    value={selectedFilters.skill} 
                    onChange={(e) => handleFilterChange('skill', e.target.value)}
                  >
                    <option value="">All Skills</option>
                    {filters.skills.map(skill => (
                      <option key={skill} value={skill}>
                        {skill}
                      </option>
                    ))}
                  </select>
                </div>
                
                <div className="filter-group">
                  <label>Languages</label>
                  <select 
                    value={selectedFilters.language} 
                    onChange={(e) => handleFilterChange('language', e.target.value)}
                  >
                    <option value="">All Languages</option>
                    {filters.languages.map(language => (
                      <option key={language} value={language}>
                        {language}
                      </option>
                    ))}
                  </select>
                </div>
                
                <div className="filter-group">
                  <label>Interests</label>
                  <select 
                    value={selectedFilters.interest} 
                    onChange={(e) => handleFilterChange('interest', e.target.value)}
                  >
                    <option value="">All Interests</option>
                    {filters.interests.map(interest => (
                      <option key={interest} value={interest}>
                        {interest}
                      </option>
                    ))}
                  </select>
                </div>
                
                <div className="filter-group">
                  <label>Company</label>
                  <select 
                    value={selectedFilters.company} 
                    onChange={(e) => handleFilterChange('company', e.target.value)}
                  >
                    <option value="">All Companies</option>
                    {filters.companies.map(company => (
                      <option key={company} value={company}>
                        {company}
                      </option>
                    ))}
                  </select>
                </div>
                

                
                <div className="filter-actions">
                  <button onClick={clearFilters} className="clear-filters-btn">
                    Clear All
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Mentors Grid */}
          <div className="mentors-section">
            <div className="section-header">
              <h2>All Mentors</h2>
              <span className="results-count">
                {filteredMentors.length} mentors found
              </span>
            </div>
            
            {loading ? (
              <div className="loading-container">
                <div className="loading-spinner"></div>
                <p>Loading mentors...</p>
              </div>
            ) : (
              <div className="mentors-grid">
                {filteredMentors.length > 0 ? (
                  filteredMentors.map(renderMentorCard)
                ) : (
                  <div className="no-mentors">
                    <h3>No mentors found</h3>
                    <p>Try adjusting your search criteria or filters</p>
                    <button onClick={clearFilters} className="clear-filters-btn">
                      Clear Filters
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {currentSection === 'blogs' && (
        <BlogSection user={user} userRole="mentee" />
      )}

      {currentSection === 'community' && (
        <CommunityBrowser user={user} />
      )}

      {currentSection === 'sessions' && (
        <SessionsPanel 
          user={user} 
          onJoinSession={onJoinSession || ((callId, channelName) => {
            setActiveCall({ callId, channelName });
          })}
        />
      )}

      <NotificationPanel 
        user={user}
        isOpen={showNotifications}
        onClose={() => {
          setShowNotifications(false);
          loadUnreadCount();
        }}
      />

      {/* Mentor Detail Modal */}
      {selectedMentor && (
        <div className="mentor-modal-overlay" onClick={() => setSelectedMentor(null)}>
          <div className="mentor-modal" onClick={(e) => e.stopPropagation()}>
            <button className="close-modal" onClick={() => setSelectedMentor(null)}>✕</button>
            <div className="mentor-detail">
              <div className="mentor-profile-header">
                <img src={selectedMentor.profilePicture || 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIgdmlld0JveD0iMCAwIDEwMCAxMDAiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxjaXJjbGUgY3g9IjUwIiBjeT0iNTAiIHI9IjUwIiBmaWxsPSIjRTFFNUU5Ii8+Cjxzdmcgd2lkdGg9IjQwIiBoZWlnaHQ9IjQwIiB2aWV3Qm94PSIwIDAgMjQgMjQiIGZpbGw9Im5vbmUiIHg9IjMwIiB5PSIzMCI+CjxwYXRoIGQ9Ik0xMiAxMkMxNC4yMDkxIDEyIDE2IDEwLjIwOTEgMTYgOEMxNiA1Ljc5MDg2IDE0LjIwOTEgNCAxMiA0QzkuNzkwODYgNCA4IDUuNzkwODYgOCA4QzggMTAuMjA5MSA5Ljc5MDg2IDEyIDEyIDEyWiIgZmlsbD0iIzY2N0VFQSIvPgo8cGF0aCBkPSJNMTIgMTRDOS4zMyAxMy45OSA3LjAxIDE1LjYyIDYgMThDMTAuMDEgMjAgMTMuOTkgMjAgMTggMThDMTYuOTkgMTUuNjIgMTQuNjcgMTMuOTkgMTIgMTRaIiBmaWxsPSIjNjY3RUVBIi8+Cjwvc3ZnPgo8L3N2Zz4='} alt={selectedMentor.name} />
                <div className="mentor-info">
                  <h2>{selectedMentor.name}</h2>
                  <div className="mentor-rating">
                    <span>⭐ {selectedMentor.rating || 4.8} ({selectedMentor.reviewCount || 25} reviews)</span>
                  </div>
                  <p className="mentor-bio">{selectedMentor.bio}</p>
                </div>
              </div>
              
              <div className="mentor-details-grid">
                <div className="detail-section">
                  <h3>Education</h3>
                  <div className="education-list">
                    {selectedMentor.education?.map((edu, index) => (
                      <div key={index} className="education-item">
                        <h4>{edu.degree || edu.qualification}</h4>
                        <p>{edu.institution || edu.school}</p>
                        <span>{edu.year || edu.duration}</span>
                      </div>
                    )) || <p>No education information available</p>}
                  </div>
                </div>
                
                <div className="detail-section">
                  <h3>Skills</h3>
                  <div className="skills-list">
                    {selectedMentor.skills?.map((skill, index) => (
                      <span key={index} className="skill-tag">{typeof skill === 'object' ? skill.name : skill}</span>
                    )) || <p>No skills listed</p>}
                  </div>
                </div>
                
                <div className="detail-section">
                  <h3>Background</h3>
                  <div className="background-list">
                    {selectedMentor.background?.map((bg, index) => (
                      <div key={index} className="background-item">
                        <h4>{bg.position || bg.title}</h4>
                        <p>{bg.company || bg.organization}</p>
                        <span>{bg.duration || bg.year}</span>
                      </div>
                    )) || <p>No background information available</p>}
                  </div>
                </div>
                
                <div className="detail-section">
                  <h3>Interests</h3>
                  <div className="interests-detailed">
                    {Array.isArray(selectedMentor.interests) && selectedMentor.interests.length > 0 ? (
                      <div className="interests-grid">
                        {selectedMentor.interests.map((interest, index) => (
                          <span key={index} className="category-tag">{interest}</span>
                        ))}
                      </div>
                    ) : (
                      <p>No interests listed</p>
                    )}
                  </div>
                </div>
                
                <div className="detail-section">
                  <h3>Languages</h3>
                  <div className="languages-list">
                    {selectedMentor.languages?.map((language, index) => (
                      <span key={index} className="language-tag">{typeof language === 'object' ? language.name : language}</span>
                    )) || <p>No languages listed</p>}
                  </div>
                </div>
                
                {selectedMentor.availability && Object.keys(selectedMentor.availability).length > 0 && (
                  <div className="detail-section">
                    <h3>Availability</h3>
                    <div className="availability-info">
                      {Object.entries(selectedMentor.availability).map(([day, times]) => (
                        <div key={day} className="availability-day">
                          <strong>{day}:</strong> {times || 'Not available'}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              
              <div className="mentor-actions-modal">
                <button onClick={() => handleCall(selectedMentor.id)} className="action-btn-modal call">
                  📞 Schedule Call
                </button>
                <button onClick={() => handleMessage(selectedMentor.id)} className="action-btn-modal message">
                  💬 Send Message
                </button>
                <button onClick={() => handleFavorite(selectedMentor.id)} className={`action-btn-modal favorite ${favorites.includes(selectedMentor.id) ? 'favorited' : ''}`}>
                  {favorites.includes(selectedMentor.id) ? '💖 Favorited' : '🤍 Add to Favorites'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
      
      {showCallModal && (
        <CallRequestModal 
          user={user}
          onCallStart={handleCallStart}
          onClose={() => setShowCallModal(false)}
        />
      )}
    </div>
  );
};

export default MenteeDashboard;