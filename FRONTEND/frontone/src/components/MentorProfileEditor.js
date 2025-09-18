import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './MentorProfile.css';

const MentorProfileEditor = ({ user, onClose, onSave, embedded = false }) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [loadingProfile, setLoadingProfile] = useState(true);
  const [profileCache, setProfileCache] = useState(null);
  const [profileData, setProfileData] = useState({
    basicInfo: { name: '', profilePicture: '', bio: '' },
    education: [{ degree: '', field: '', institution: '', startYear: '', endYear: '', grade: '' }],
    skills: [{ name: '', experience: '', proficiency: 'Beginner' }],
    background: [{ company: '', position: '', startDate: '', endDate: '', location: '', description: '', projects: [] }],
    interests: {},
    languages: [{ name: '', proficiency: 'Basic' }],
    availability: { available: true, timezone: '', preferredHours: '', sessionDuration: '60', maxMentees: 5 }
  });
  
  const [selectedCategories, setSelectedCategories] = useState([]);
  const [selectedCategory, setSelectedCategory] = useState('');

  useEffect(() => {
    if (user && !profileCache) {
      loadProfileData();
    } else if (profileCache) {
      setLoadingProfile(false);
    }
  }, [user, profileCache]);

  const loadProfileData = async () => {
    // Use cached data if available
    if (profileCache) {
      setProfileData(profileCache);
      if (profileCache.selectedCategories) {
        setSelectedCategories(profileCache.selectedCategories);
      }
      setLoadingProfile(false);
      return;
    }

    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`http://localhost:5000/api/mentor/profile/${user.id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.data.profile) {
        setProfileData(response.data.profile);
        setProfileCache(response.data.profile);
        if (response.data.profile.selectedCategories) {
          setSelectedCategories(response.data.profile.selectedCategories);
        }
      }
    } catch (error) {
      console.error('Failed to load profile:', error);
    } finally {
      setLoadingProfile(false);
    }
  };

  const steps = [
    { id: 'basic', label: 'Basic Info', icon: '👨🏻‍💼' },
    { id: 'education', label: 'Education', icon: '🎓' },
    { id: 'skills', label: 'Skills', icon: '💡' },
    { id: 'background', label: 'Background', icon: '💼' },
    { id: 'interests', label: 'Interests', icon: '❤️' },
    { id: 'languages', label: 'Languages', icon: '🌍' },
    { id: 'availability', label: 'Availability', icon: '📅' }
  ];

  const interestTags = {
    placement: [
      'DSA', 'Frontend Development', 'Backend Development', 'Full Stack', 'Mobile Development',
      'DevOps', 'Cloud Computing', 'Machine Learning', 'Data Science', 'Cybersecurity',
      'System Design', 'Database Management', 'API Development', 'Testing', 'UI/UX Design',
      'Product Management', 'Aptitude', 'Resume Building', 'Interview Preparation', 'Coding Practice'
    ],
    college_reviews: [
      'Andhra Pradesh', 'Arunachal Pradesh', 'Assam', 'Bihar', 'Chhattisgarh', 'Goa', 'Gujarat',
      'Haryana', 'Himachal Pradesh', 'Jharkhand', 'Karnataka', 'Kerala', 'Madhya Pradesh',
      'Maharashtra', 'Manipur', 'Meghalaya', 'Mizoram', 'Nagaland', 'Odisha', 'Punjab',
      'Rajasthan', 'Sikkim', 'Tamil Nadu', 'Telangana', 'Tripura', 'Uttar Pradesh',
      'Uttarakhand', 'West Bengal', 'Delhi', 'Mumbai'
    ],
    skills_learning: [
      'JavaScript', 'Python', 'Java', 'C++', 'React', 'Angular', 'Vue.js', 'Node.js',
      'Spring Boot', 'Django', 'Flask', 'MongoDB', 'MySQL', 'PostgreSQL', 'AWS',
      'Azure', 'Docker', 'Kubernetes', 'Git', 'Linux'
    ],
    projects: [
      'Web Development', 'Mobile Apps', 'Desktop Applications', 'Game Development',
      'AI/ML Projects', 'Data Analytics', 'Blockchain', 'IoT', 'AR/VR', 'E-commerce',
      'Social Media', 'Healthcare', 'Education', 'Finance', 'Entertainment',
      'Open Source', 'Startup Ideas', 'Research Projects', 'Hackathon Projects', 'Portfolio Projects'
    ],
    hackathons: [
      'Problem Solving', 'Team Formation', 'Idea Generation', 'Prototype Development',
      'Presentation Skills', 'Time Management', 'Technology Selection', 'UI/UX Design',
      'Backend Development', 'Frontend Development', 'Database Design', 'API Integration',
      'Deployment', 'Testing', 'Documentation', 'Pitch Preparation', 'Demo Creation',
      'Judging Criteria', 'Networking', 'Post-Hackathon Steps'
    ],
    study_help: [
      'Mathematics', 'Physics', 'Chemistry', 'Computer Science', 'Electronics', 'Mechanical',
      'Civil Engineering', 'Electrical Engineering', 'GATE Preparation', 'JEE Preparation',
      'NEET Preparation', 'CAT Preparation', 'GRE Preparation', 'TOEFL Preparation',
      'IELTS Preparation', 'Semester Exams', 'Assignment Help', 'Project Reports',
      'Research Papers', 'Thesis Writing'
    ]
  };

  const handleInputChange = (section, field, value, index = null) => {
    setProfileData(prev => {
      if (index !== null) {
        const newArray = [...prev[section]];
        newArray[index] = { ...newArray[index], [field]: value };
        return { ...prev, [section]: newArray };
      }
      return { ...prev, [section]: { ...prev[section], [field]: value } };
    });
  };

  const addArrayItem = (section, defaultItem) => {
    setProfileData(prev => ({
      ...prev,
      [section]: [...prev[section], defaultItem]
    }));
  };

  const removeArrayItem = (section, index) => {
    setProfileData(prev => ({
      ...prev,
      [section]: prev[section].filter((_, i) => i !== index)
    }));
  };

  const handleInterestToggle = (interest) => {
    setProfileData(prev => ({
      ...prev,
      interests: prev.interests.includes(interest)
        ? prev.interests.filter(i => i !== interest)
        : [...prev.interests, interest]
    }));
  };

  const saveSection = async () => {
    setLoading(true);
    setError('');
    try {
      const token = localStorage.getItem('token');
      const currentSection = steps[currentStep].id;
      let sectionData;
      
      // Map section IDs to profile data keys
      switch (currentSection) {
        case 'basic':
          sectionData = profileData.basicInfo;
          break;
        case 'education':
          sectionData = profileData.education;
          break;
        case 'skills':
          sectionData = profileData.skills;
          break;
        case 'background':
          sectionData = profileData.background;
          break;
        case 'interests':
          // Group interests by category
          const interestsByCategory = {};
          selectedCategories.forEach(category => {
            interestsByCategory[category] = profileData.interests.filter(interest => 
              interestTags[category] && interestTags[category].includes(interest)
            );
          });
          
          sectionData = {
            selectedCategories: selectedCategories,
            interests: interestsByCategory
          };
          break;
        case 'languages':
          sectionData = profileData.languages;
          break;
        case 'availability':
          sectionData = profileData.availability;
          break;
        default:
          sectionData = profileData[currentSection];
      }
      
      await axios.patch(`http://localhost:5000/api/mentor/profile/${user.id}/section`, {
        section: currentSection,
        data: sectionData
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      // Update cache after successful save
      setProfileCache(prev => ({
        ...prev,
        [currentSection === 'basic' ? 'basicInfo' : currentSection]: sectionData
      }));
    } catch (error) {
      console.error('Save section error:', error);
      setError(error.response?.data?.error || 'Failed to save section');
    } finally {
      setLoading(false);
    }
  };

  const saveProfile = async () => {
    setLoading(true);
    setError('');
    try {
      const token = localStorage.getItem('token');
      await axios.put(`http://localhost:5000/api/mentor/profile/${user.id}`, profileData, {
        headers: { Authorization: `Bearer ${token}` }
      });
      onSave(profileData);
    } catch (error) {
      console.error('Save profile error:', error);
      setError(error.response?.data?.error || 'Failed to save profile');
    } finally {
      setLoading(false);
    }
  };

  const renderBasicInfo = () => (
    <div className="step-content">
      <h3>Basic Information</h3>
      <input
        type="text"
        placeholder="Full Name"
        value={profileData.basicInfo.name}
        onChange={(e) => handleInputChange('basicInfo', 'name', e.target.value)}
      />
      <input
        type="file"
        accept="image/*"
        onChange={(e) => {
          const file = e.target.files[0];
          if (file) {
            const reader = new FileReader();
            reader.onload = (e) => handleInputChange('basicInfo', 'profilePicture', e.target.result);
            reader.readAsDataURL(file);
          }
        }}
      />
      {profileData.basicInfo.profilePicture && (
        <img src={profileData.basicInfo.profilePicture} alt="Preview" className="profile-preview" />
      )}
      <textarea
        placeholder="Bio (Tell mentees about yourself)"
        value={profileData.basicInfo.bio}
        onChange={(e) => handleInputChange('basicInfo', 'bio', e.target.value)}
        rows="4"
      />
    </div>
  );

  const renderEducation = () => (
    <div className="step-content">
      <h3>Education</h3>
      {profileData.education.map((edu, index) => (
        <div key={index} className="array-item">
          <input
            type="text"
            placeholder="Degree"
            value={edu.degree}
            onChange={(e) => handleInputChange('education', 'degree', e.target.value, index)}
          />
          <input
            type="text"
            placeholder="Field of Study"
            value={edu.field}
            onChange={(e) => handleInputChange('education', 'field', e.target.value, index)}
          />
          <input
            type="text"
            placeholder="Institution"
            value={edu.institution}
            onChange={(e) => handleInputChange('education', 'institution', e.target.value, index)}
          />
          <div className="date-row">
            <input
              type="number"
              placeholder="Start Year"
              value={edu.startYear}
              onChange={(e) => handleInputChange('education', 'startYear', e.target.value, index)}
            />
            <input
              type="number"
              placeholder="End Year"
              value={edu.endYear}
              onChange={(e) => handleInputChange('education', 'endYear', e.target.value, index)}
            />
          </div>
          <input
            type="text"
            placeholder="Grade/GPA"
            value={edu.grade}
            onChange={(e) => handleInputChange('education', 'grade', e.target.value, index)}
          />
          <button type="button" onClick={() => removeArrayItem('education', index)} className="remove-btn">Remove</button>
        </div>
      ))}
      <button type="button" onClick={() => addArrayItem('education', { degree: '', field: '', institution: '', startYear: '', endYear: '', grade: '' })} className="add-btn">
        Add Education
      </button>
    </div>
  );

  const renderSkills = () => (
    <div className="step-content">
      <h3>Skills</h3>
      {profileData.skills.map((skill, index) => (
        <div key={index} className="array-item">
          <input
            type="text"
            placeholder="Skill Name"
            value={skill.name}
            onChange={(e) => handleInputChange('skills', 'name', e.target.value, index)}
          />
          <input
            type="number"
            placeholder="Years of Experience"
            value={skill.experience}
            onChange={(e) => handleInputChange('skills', 'experience', e.target.value, index)}
          />
          <select
            value={skill.proficiency}
            onChange={(e) => handleInputChange('skills', 'proficiency', e.target.value, index)}
          >
            <option value="Beginner">Beginner</option>
            <option value="Intermediate">Intermediate</option>
            <option value="Advanced">Advanced</option>
            <option value="Expert">Expert</option>
          </select>
          <button type="button" onClick={() => removeArrayItem('skills', index)} className="remove-btn">Remove</button>
        </div>
      ))}
      <button type="button" onClick={() => addArrayItem('skills', { name: '', experience: '', proficiency: 'Beginner' })} className="add-btn">
        Add Skill
      </button>
    </div>
  );

  const renderBackground = () => (
    <div className="step-content">
      <h3>Professional Background</h3>
      {profileData.background.map((job, index) => (
        <div key={index} className="array-item">
          <input
            type="text"
            placeholder="Company Name"
            value={job.company}
            onChange={(e) => handleInputChange('background', 'company', e.target.value, index)}
          />
          <input
            type="text"
            placeholder="Position"
            value={job.position}
            onChange={(e) => handleInputChange('background', 'position', e.target.value, index)}
          />
          <div className="date-row">
            <input
              type="date"
              placeholder="Start Date"
              value={job.startDate}
              onChange={(e) => handleInputChange('background', 'startDate', e.target.value, index)}
            />
            <input
              type="date"
              placeholder="End Date"
              value={job.endDate}
              onChange={(e) => handleInputChange('background', 'endDate', e.target.value, index)}
            />
          </div>
          <input
            type="text"
            placeholder="Location"
            value={job.location}
            onChange={(e) => handleInputChange('background', 'location', e.target.value, index)}
          />
          <textarea
            placeholder="Job Description"
            value={job.description}
            onChange={(e) => handleInputChange('background', 'description', e.target.value, index)}
            rows="3"
          />
          <button type="button" onClick={() => removeArrayItem('background', index)} className="remove-btn">Remove</button>
        </div>
      ))}
      <button type="button" onClick={() => addArrayItem('background', { company: '', position: '', startDate: '', endDate: '', location: '', description: '', projects: [] })} className="add-btn">
        Add Experience
      </button>
    </div>
  );

  const handleCategoryToggle = (category) => {
    setSelectedCategories(prev => 
      prev.includes(category) 
        ? prev.filter(c => c !== category)
        : prev.length < 6 ? [...prev, category] : prev
    );
  };

  const addTagFromCategory = () => {
    if (selectedCategory && profileData.interests.length < 20) {
      const availableTags = interestTags[selectedCategory].filter(
        tag => !profileData.interests.includes(tag)
      );
      if (availableTags.length > 0) {
        setProfileData(prev => ({
          ...prev,
          interests: [...prev.interests, availableTags[0]]
        }));
      }
    }
  };

  const removeInterest = (interest) => {
    setProfileData(prev => ({
      ...prev,
      interests: prev.interests.filter(i => i !== interest)
    }));
  };

  const renderInterests = () => (
    <div className="step-content">
      <h3>Mentorship Interests</h3>
      
      <div className="category-selection">
        <h4>Select Interest Categories (Max 6)</h4>
        <div className="category-grid">
          {Object.keys(interestTags).map(category => (
            <div
              key={category}
              className={`category-card ${selectedCategories.includes(category) ? 'selected' : ''}`}
              onClick={() => handleCategoryToggle(category)}
            >
              {category.replace('_', ' ').toUpperCase()}
            </div>
          ))}
        </div>
      </div>

      {selectedCategories.length > 0 && (
        <div className="tag-selection">
          <h4>Add Tags from Selected Categories</h4>
          <div className="tag-dropdown">
            <select 
              value={selectedCategory} 
              onChange={(e) => setSelectedCategory(e.target.value)}
            >
              <option value="">Select Category</option>
              {selectedCategories.map(category => (
                <option key={category} value={category}>
                  {category.replace('_', ' ').toUpperCase()}
                </option>
              ))}
            </select>
            
            {selectedCategory && (
              <select 
                value=""
                onChange={(e) => {
                  if (e.target.value && !profileData.interests.includes(e.target.value)) {
                    setProfileData(prev => ({
                      ...prev,
                      interests: [...prev.interests, e.target.value]
                    }));
                  }
                }}
              >
                <option value="">Select Tag</option>
                {interestTags[selectedCategory]
                  .filter(tag => !profileData.interests.includes(tag))
                  .map((tag, index) => (
                    <option key={`${selectedCategory}-${tag}-${index}`} value={tag}>{tag}</option>
                  ))
                }
              </select>
            )}
          </div>
        </div>
      )}

      <div className="selected-interests">
        <h4>Selected Tags ({profileData.interests.filter(i => i && i.trim()).length}/20)</h4>
        <div className="interests-list">
          {profileData.interests
            .filter(interest => interest && interest.trim() !== '')
            .map((interest, index) => (
              <div key={`tag-${interest}-${index}`} className="interest-tag">
                <span>{interest}</span>
                <button 
                  type="button" 
                  onClick={() => removeInterest(interest)}
                  className="remove-tag"
                >
                  ×
                </button>
              </div>
            ))
          }
        </div>
        {profileData.interests.filter(i => i && i.trim()).length === 0 && (
          <p style={{color: '#666', fontStyle: 'italic'}}>No tags selected yet</p>
        )}
      </div>
    </div>
  );

  const renderLanguages = () => (
    <div className="step-content">
      <h3>Languages</h3>
      {profileData.languages.map((lang, index) => (
        <div key={index} className="array-item">
          <input
            type="text"
            placeholder="Language"
            value={lang.name}
            onChange={(e) => handleInputChange('languages', 'name', e.target.value, index)}
          />
          <select
            value={lang.proficiency}
            onChange={(e) => handleInputChange('languages', 'proficiency', e.target.value, index)}
          >
            <option value="Basic">Basic</option>
            <option value="Conversational">Conversational</option>
            <option value="Fluent">Fluent</option>
            <option value="Native">Native</option>
          </select>
          <button type="button" onClick={() => removeArrayItem('languages', index)} className="remove-btn">Remove</button>
        </div>
      ))}
      <button type="button" onClick={() => addArrayItem('languages', { name: '', proficiency: 'Basic' })} className="add-btn">
        Add Language
      </button>
    </div>
  );

  const renderAvailability = () => (
    <div className="step-content">
      <h3>Availability</h3>
      <label className="checkbox-label">
        <input
          type="checkbox"
          checked={profileData.availability.available}
          onChange={(e) => handleInputChange('availability', 'available', e.target.checked)}
        />
        Available for mentoring
      </label>
      <select
        value={profileData.availability.timezone}
        onChange={(e) => handleInputChange('availability', 'timezone', e.target.value)}
      >
        <option value="">Select Timezone</option>
        <option value="UTC">UTC</option>
        <option value="EST">EST</option>
        <option value="PST">PST</option>
        <option value="IST">IST</option>
      </select>
      <input
        type="text"
        placeholder="Preferred Hours (e.g., 9 AM - 5 PM)"
        value={profileData.availability.preferredHours}
        onChange={(e) => handleInputChange('availability', 'preferredHours', e.target.value)}
      />
      <select
        value={profileData.availability.sessionDuration}
        onChange={(e) => handleInputChange('availability', 'sessionDuration', e.target.value)}
      >
        <option value="30">30 minutes</option>
        <option value="60">60 minutes</option>
        <option value="90">90 minutes</option>
        <option value="120">120 minutes</option>
      </select>
      <input
        type="number"
        placeholder="Maximum Mentees"
        value={profileData.availability.maxMentees}
        onChange={(e) => handleInputChange('availability', 'maxMentees', parseInt(e.target.value))}
        min="1"
        max="50"
      />
    </div>
  );

  const renderStepContent = () => {
    switch (currentStep) {
      case 0: return renderBasicInfo();
      case 1: return renderEducation();
      case 2: return renderSkills();
      case 3: return renderBackground();
      case 4: return renderInterests();
      case 5: return renderLanguages();
      case 6: return renderAvailability();
      default: return null;
    }
  };

  if (loadingProfile) {
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <p>Loading your profile...</p>
      </div>
    );
  }

  return (
    <div className={`profile-editor ${embedded ? 'embedded' : ''}`}>
      <div className="editor-header">
        <h2>Edit Mentor Profile</h2>
        {!embedded && <button onClick={onClose} className="close-btn">×</button>}
      </div>

      <div className="step-navigation">
        {steps.map((step, index) => (
          <button
            key={step.id}
            className={`step-btn ${index === currentStep ? 'active' : ''} ${index < currentStep ? 'completed' : ''}`}
            onClick={() => setCurrentStep(index)}
          >
            <span className="step-icon">{step.icon}</span>
            <span className="step-label">{step.label}</span>
          </button>
        ))}
      </div>

      <div className="editor-content">
        {renderStepContent()}
        
        {error && <div className="error">{error}</div>}
        
        <div className="editor-actions">
          <button onClick={saveSection} disabled={loading} className="save-section-btn">
            {loading ? 'Saving...' : 'Save Section'}
          </button>
          
          <div className="navigation-buttons">
            {currentStep > 0 && (
              <button onClick={() => setCurrentStep(currentStep - 1)} className="back-btn">
                Back
              </button>
            )}
            
            {currentStep < steps.length - 1 ? (
              <button onClick={() => setCurrentStep(currentStep + 1)} className="next-btn">
                Next
              </button>
            ) : (
              <div className="final-actions">
                <button onClick={saveProfile} disabled={loading} className="save-profile-btn">
                  {loading ? 'Saving Profile...' : 'Save Profile'}
                </button>
                <button onClick={onClose} className="cancel-btn">
                  Cancel
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default MentorProfileEditor;