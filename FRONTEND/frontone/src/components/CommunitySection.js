import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './CommunitySection.css';

const CommunitySection = ({ user, userRole }) => {
  const [communities, setCommunities] = useState([]);
  const [selectedCommunity, setSelectedCommunity] = useState(null);
  const [posts, setPosts] = useState([]);
  const [showCreateCommunity, setShowCreateCommunity] = useState(false);
  const [newPost, setNewPost] = useState({ content: '', file: null });
  const [loading, setLoading] = useState(false);
  const [postReactions, setPostReactions] = useState({});
  const [showMediaGallery, setShowMediaGallery] = useState(false);
  const [mediaFiles, setMediaFiles] = useState([]);
  const [uploading, setUploading] = useState(false);

  useEffect(() => {
    loadCommunities();
  }, [userRole]);

  const loadCommunities = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const url = userRole === 'mentor' 
        ? `http://localhost:5000/api/communities/mentor/${user.id}`
        : `http://localhost:5000/api/mentee/${user.id}/communities`;
      
      const response = await axios.get(url, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setCommunities(response.data.communities || []);
    } catch (error) {
      console.error('Failed to load communities:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadPosts = async (communityId) => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`http://localhost:5000/api/communities/${communityId}/posts`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const sortedPosts = (response.data.posts || []).sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
      setPosts(sortedPosts);
      loadPostReactions(sortedPosts);
      
      // Extract all files for gallery
      const allFiles = sortedPosts.filter(post => post.file_url);
      console.log('All posts:', sortedPosts);
      console.log('Posts with files:', allFiles);
      setMediaFiles(allFiles);
    } catch (error) {
      console.error('Failed to load posts:', error);
    }
  };

  const loadPostReactions = async (posts) => {
    try {
      const token = localStorage.getItem('token');
      const reactions = {};
      
      for (const post of posts) {
        const response = await axios.get(`http://localhost:5000/api/communities/posts/${post.id}/reactions`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        reactions[post.id] = response.data.reactions || {};
      }
      
      setPostReactions(reactions);
    } catch (error) {
      console.error('Failed to load reactions:', error);
    }
  };

  const handleCreatePost = async () => {
    if (!newPost.content.trim() && !newPost.file) return;
    if (uploading) return;
    
    try {
      setUploading(true);
      const token = localStorage.getItem('token');
      let fileData = {};
      
      if (newPost.file) {
        if (newPost.file.size > 10 * 1024 * 1024) {
          alert('File size must be less than 10MB');
          setUploading(false);
          return;
        }
        
        const reader = new FileReader();
        reader.onload = async (e) => {
          try {
            fileData = {
              fileUrl: e.target.result,
              fileName: newPost.file.name,
              fileType: newPost.file.type,
              fileSize: newPost.file.size,
              postType: 'file'
            };
            
            await axios.post(`http://localhost:5000/api/communities/${selectedCommunity.id}/posts`, {
              mentorId: user.id,
              content: newPost.content,
              fileUrl: fileData.fileUrl,
              fileName: fileData.fileName,
              fileType: fileData.fileType,
              fileSize: fileData.fileSize,
              postType: fileData.postType
            }, {
              headers: { Authorization: `Bearer ${token}` }
            });
            
            setNewPost({ content: '', file: null });
            loadPosts(selectedCommunity.id);
          } catch (error) {
            console.error('File upload error:', error.response?.data || error.message);
            alert('Failed to upload file: ' + (error.response?.data?.error || error.message));
          } finally {
            setUploading(false);
          }
        };
        reader.readAsDataURL(newPost.file);
      } else {
        try {
          await axios.post(`http://localhost:5000/api/communities/${selectedCommunity.id}/posts`, {
            mentorId: user.id,
            content: newPost.content,
            postType: 'text'
          }, {
            headers: { Authorization: `Bearer ${token}` }
          });
          
          setNewPost({ content: '', file: null });
          loadPosts(selectedCommunity.id);
        } catch (error) {
          console.error('Text post error:', error.response?.data || error.message);
          alert('Failed to create post: ' + (error.response?.data?.error || error.message));
        } finally {
          setUploading(false);
        }
      }
    } catch (error) {
      console.error('Failed to create post:', error);
      setUploading(false);
    }
  };

  const handleReact = async (postId, reactionType) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post(`http://localhost:5000/api/communities/posts/${postId}/react`, {
        userId: user.id,
        reactionType
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      loadPosts(selectedCommunity.id);
    } catch (error) {
      console.error('Failed to react:', error);
    }
  };

  const openCommunity = (community) => {
    setSelectedCommunity(community);
    loadPosts(community.id);
  };

  const downloadFile = (fileUrl, fileName) => {
    const link = document.createElement('a');
    link.href = fileUrl;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const openMediaGallery = () => {
    setShowMediaGallery(true);
  };

  const MediaGallery = () => (
    <div className="media-gallery-overlay">
      <div className="media-gallery">
        <div className="gallery-header">
          <h3>Shared Files</h3>
          <button onClick={() => setShowMediaGallery(false)} className="close-btn">✕</button>
        </div>
        <div className="files-list">
          {mediaFiles.length === 0 ? (
            <div className="no-files">No files shared yet</div>
          ) : (
            mediaFiles.map(file => (
            <div key={file.id} className="file-item">
              <div className="file-icon-container">
                {file.file_type?.startsWith('image/') ? (
                  <img src={file.file_url} alt={file.file_name} className="file-thumbnail" />
                ) : (
                  <div className="file-icon-wrapper">
                    <span className="file-icon">
                      {file.file_type?.includes('pdf') ? '📄' :
                       file.file_type?.includes('doc') ? '📝' :
                       file.file_type?.includes('txt') ? '📃' : '📎'}
                    </span>
                  </div>
                )}
              </div>
              <div className="file-details">
                <div className="file-name">{file.file_name}</div>
                <div className="file-meta">
                  <span className="file-type">{file.file_type?.split('/')[1]?.toUpperCase() || 'FILE'}</span>
                  <span className="file-date">{new Date(file.created_at).toLocaleDateString()}</span>
                </div>
              </div>
              <button 
                onClick={() => downloadFile(file.file_url, file.file_name)}
                className="download-btn"
              >
                ⬇️
              </button>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );

  if (showCreateCommunity && userRole === 'mentor') {
    return <CreateCommunityForm 
      user={user} 
      onBack={() => setShowCreateCommunity(false)}
      onSuccess={() => {
        setShowCreateCommunity(false);
        loadCommunities();
      }}
    />;
  }

  if (selectedCommunity) {
    return (
      <div className="community-chat">
        {showMediaGallery && <MediaGallery />}
        <div className="chat-header">
          <button onClick={() => setSelectedCommunity(null)} className="back-btn">← Back</button>
          <div className="community-info">
            <h3>{selectedCommunity.name}</h3>
            <p>{selectedCommunity.member_count} members</p>
          </div>
          <button onClick={openMediaGallery} className="media-gallery-btn">
            📁 Files ({mediaFiles.length})
          </button>
        </div>

        <div className="chat-messages">
          {posts.map(post => (
            <div key={post.id} className="message">
              <div className="message-header">
                <span className="sender">{post.mentor_name}</span>
                <span className="time">{new Date(post.created_at).toLocaleString()}</span>
              </div>
              
              {post.content && <div className="message-content">{post.content}</div>}
              
              {post.file_url && (
                <div className="message-file">
                  {post.file_type?.startsWith('image/') ? (
                    <div className="image-container">
                      <img src={post.file_url} alt={post.file_name} className="message-image" />
                      <button onClick={() => downloadFile(post.file_url, post.file_name)} className="download-overlay">
                        ⬇️
                      </button>
                    </div>
                  ) : (
                    <div className="file-attachment">
                      <span>📎 {post.file_name}</span>
                      <button onClick={() => downloadFile(post.file_url, post.file_name)}>
                        Download
                      </button>
                    </div>
                  )}
                </div>
              )}
              
              <div className="reactions-section">
                {userRole === 'mentee' && (
                  <div className="reaction-buttons">
                    <button onClick={() => handleReact(post.id, 'like')} className="react-btn">
                      👍
                    </button>
                    <button onClick={() => handleReact(post.id, 'love')} className="react-btn">
                      ❤️
                    </button>
                    <button onClick={() => handleReact(post.id, 'celebrate')} className="react-btn">
                      🎉
                    </button>
                    <button onClick={() => handleReact(post.id, 'clap')} className="react-btn">
                      👏
                    </button>
                  </div>
                )}
                
                {postReactions[post.id] && (
                  <div className="reaction-counts">
                    {Object.entries(postReactions[post.id]).map(([type, count]) => (
                      count > 0 && (
                        <span key={type} className="reaction-count">
                          {type === 'like' && '👍'}
                          {type === 'love' && '❤️'}
                          {type === 'celebrate' && '🎉'}
                          {type === 'clap' && '👏'}
                          {count}
                        </span>
                      )
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        {userRole === 'mentor' && (
          <div className="message-input">
            <textarea
              value={newPost.content}
              onChange={(e) => setNewPost({...newPost, content: e.target.value})}
              placeholder="Type a message..."
              rows="2"
            />
            <input
              type="file"
              onChange={(e) => setNewPost({...newPost, file: e.target.files[0]})}
              accept=".pdf,.doc,.docx,.txt,.jpg,.jpeg,.png,.gif"
            />
            <button onClick={handleCreatePost} disabled={uploading}>
              {uploading ? (
                <span className="uploading">
                  <span className="dots">Uploading</span>
                  <span className="loading-dots"></span>
                </span>
              ) : (
                'Send'
              )}
            </button>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="community-section">
      <div className="community-header">
        <h2>{userRole === 'mentor' ? 'My Communities' : 'Joined Communities'}</h2>
        {userRole === 'mentor' && (
          <button onClick={() => setShowCreateCommunity(true)} className="create-community-btn">
            ➕ Create Community
          </button>
        )}
      </div>

      {loading ? (
        <div className="loading">Loading communities...</div>
      ) : (
        <div className="communities-grid">
          {communities.map(community => (
            <div key={community.id} className="community-card" onClick={() => openCommunity(community)}>
              <h3>{community.name}</h3>
              <p>{community.description}</p>
              <div className="community-meta">
                <span>👥 {community.member_count} members</span>
                <span>📚 {community.interest_category}</span>
              </div>
              {userRole === 'mentee' && (
                <div className="community-owner">By {community.mentor_name}</div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const CreateCommunityForm = ({ user, onBack, onSuccess }) => {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    interestCategory: ''
  });

  const categories = [
    'Programming', 'Web Development', 'Mobile Development', 'Data Science',
    'AI/ML', 'Cybersecurity', 'DevOps', 'UI/UX Design', 'Career Guidance', 'Interview Prep'
  ];

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    try {
      const token = localStorage.getItem('token');
      await axios.post('http://localhost:5000/api/communities', {
        mentorId: user.id,
        ...formData
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      onSuccess();
    } catch (error) {
      console.error('Failed to create community:', error);
    }
  };

  return (
    <div className="create-community-form">
      <div className="form-header">
        <button onClick={onBack} className="back-btn">← Back</button>
        <h2>Create New Community</h2>
      </div>

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>Community Name *</label>
          <input
            type="text"
            value={formData.name}
            onChange={(e) => setFormData({...formData, name: e.target.value})}
            required
          />
        </div>

        <div className="form-group">
          <label>Description</label>
          <textarea
            value={formData.description}
            onChange={(e) => setFormData({...formData, description: e.target.value})}
            rows="3"
          />
        </div>

        <div className="form-group">
          <label>Interest Category</label>
          <select
            value={formData.interestCategory}
            onChange={(e) => setFormData({...formData, interestCategory: e.target.value})}
          >
            <option value="">Select category</option>
            {categories.map(cat => (
              <option key={cat} value={cat}>{cat}</option>
            ))}
          </select>
        </div>

        <div className="form-actions">
          <button type="button" onClick={onBack}>Cancel</button>
          <button type="submit">Create Community</button>
        </div>
      </form>
    </div>
  );
};

export default CommunitySection;