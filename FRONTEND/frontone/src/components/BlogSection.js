import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './BlogSection.css';

const BlogSection = ({ user, userRole }) => {
  const [blogs, setBlogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedBlog, setSelectedBlog] = useState(null);
  const [comments, setComments] = useState([]);
  const [newComment, setNewComment] = useState('');
  const [likedBlogs, setLikedBlogs] = useState([]);
  const [replyingTo, setReplyingTo] = useState(null);
  const [replyText, setReplyText] = useState('');
  const [lastFetch, setLastFetch] = useState(null);

  useEffect(() => {
    // Only fetch if we haven't fetched recently (cache for 10 minutes)
    const now = Date.now();
    if (!lastFetch || now - lastFetch > 10 * 60 * 1000) {
      loadBlogs();
      if (userRole === 'mentee') {
        loadLikedBlogs();
      }
      setLastFetch(now);
    }
  }, [userRole, lastFetch]);

  const loadBlogs = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const apiBase = process.env.NODE_ENV === 'production' ? '/api' : 'http://localhost:5000/api';
      const url = userRole === 'mentor' 
        ? `${apiBase}/blogs/mentor/${user.id}`
        : `${apiBase}/blogs`;
      
      // Check localStorage cache first
      const cacheKey = `blogs_${userRole}_${user.id}`;
      const cached = localStorage.getItem(cacheKey);
      const cacheTime = localStorage.getItem(`${cacheKey}_time`);
      
      if (cached && cacheTime && Date.now() - parseInt(cacheTime) < 10 * 60 * 1000) {
        setBlogs(JSON.parse(cached));
        setLoading(false);
        return;
      }
      
      const response = await axios.get(url, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      const blogsData = response.data.blogs || [];
      setBlogs(blogsData);
      
      // Cache the result
      localStorage.setItem(cacheKey, JSON.stringify(blogsData));
      localStorage.setItem(`${cacheKey}_time`, Date.now().toString());
    } catch (error) {
      console.error('Failed to load blogs:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadLikedBlogs = async () => {
    try {
      const token = localStorage.getItem('token');
      const apiBase = process.env.NODE_ENV === 'production' ? 'https://dream-nodejs-production.up.railway.app' : 'http://localhost:5000';
      const response = await axios.get(`${apiBase}/api/mentee/${user.id}/liked-blogs`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setLikedBlogs(response.data.likedBlogs || []);
    } catch (error) {
      console.error('Failed to load liked blogs:', error);
    }
  };

  const handleLike = async (blogId) => {
    if (userRole !== 'mentee') return;
    
    try {
      const token = localStorage.getItem('token');
      const apiBase = process.env.NODE_ENV === 'production' ? '' : 'http://localhost:5000';
      const response = await axios.post(`${apiBase}/api/blogs/${blogId}/like`, {
        menteeId: user.id
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.data.liked) {
        setLikedBlogs([...likedBlogs, blogId]);
        setBlogs(blogs.map(blog => 
          blog.id === blogId ? { ...blog, likes_count: blog.likes_count + 1 } : blog
        ));
      } else {
        setLikedBlogs(likedBlogs.filter(id => id !== blogId));
        setBlogs(blogs.map(blog => 
          blog.id === blogId ? { ...blog, likes_count: blog.likes_count - 1 } : blog
        ));
      }
    } catch (error) {
      console.error('Failed to like blog:', error);
    }
  };

  const loadComments = async (blogId) => {
    try {
      const token = localStorage.getItem('token');
      const apiBase = process.env.NODE_ENV === 'production' ? '' : 'http://localhost:5000';
      const response = await axios.get(`${apiBase}/api/blogs/${blogId}/comments`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setComments(response.data.comments || []);
    } catch (error) {
      console.error('Failed to load comments:', error);
    }
  };

  const handleAddComment = async () => {
    if (!newComment.trim()) return;
    
    try {
      const token = localStorage.getItem('token');
      const apiBase = process.env.NODE_ENV === 'production' ? '' : 'http://localhost:5000';
      await axios.post(`${apiBase}/api/blogs/${selectedBlog.id}/comments`, {
        userId: user.id,
        content: newComment
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      setNewComment('');
      loadComments(selectedBlog.id);
      setBlogs(blogs.map(blog => 
        blog.id === selectedBlog.id ? { ...blog, comments_count: blog.comments_count + 1 } : blog
      ));
      
      // Clear cache to force refresh
      const cacheKey = `blogs_${userRole}_${user.id}`;
      localStorage.removeItem(cacheKey);
      localStorage.removeItem(`${cacheKey}_time`);
    } catch (error) {
      console.error('Failed to add comment:', error);
    }
  };

  const handleAddReply = async (parentCommentId) => {
    if (!replyText.trim()) return;
    
    try {
      const token = localStorage.getItem('token');
      const apiBase = process.env.NODE_ENV === 'production' ? '' : 'http://localhost:5000';
      await axios.post(`${apiBase}/api/blogs/${selectedBlog.id}/comments`, {
        userId: user.id,
        content: replyText,
        parentCommentId
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      setReplyText('');
      setReplyingTo(null);
      loadComments(selectedBlog.id);
      setBlogs(blogs.map(blog => 
        blog.id === selectedBlog.id ? { ...blog, comments_count: blog.comments_count + 1 } : blog
      ));
      
      // Clear cache to force refresh
      const cacheKey = `blogs_${userRole}_${user.id}`;
      localStorage.removeItem(cacheKey);
      localStorage.removeItem(`${cacheKey}_time`);
    } catch (error) {
      console.error('Failed to add reply:', error);
    }
  };

  const handleDeleteComment = async (commentId) => {
    try {
      const token = localStorage.getItem('token');
      const apiBase = process.env.NODE_ENV === 'production' ? '' : 'http://localhost:5000';
      await axios.delete(`${apiBase}/api/comments/${commentId}`, {
        data: { userId: user.id, userRole },
        headers: { Authorization: `Bearer ${token}` }
      });
      
      loadComments(selectedBlog.id);
      setBlogs(blogs.map(blog => 
        blog.id === selectedBlog.id ? { ...blog, comments_count: blog.comments_count - 1 } : blog
      ));
    } catch (error) {
      console.error('Failed to delete comment:', error);
    }
  };

  const openBlogModal = (blog) => {
    setSelectedBlog(blog);
    loadComments(blog.id);
  };

  const closeBlogModal = () => {
    setSelectedBlog(null);
    setComments([]);
    setNewComment('');
  };

  return (
    <div className="blog-section">
      <div className="blog-header">
        <h2>{userRole === 'mentor' ? 'My Blogs' : 'Latest Blogs'}</h2>
      </div>

      {loading ? (
        <div className="loading">Loading blogs...</div>
      ) : (
        <div className="blogs-grid">
          {blogs.map(blog => (
            <div key={blog.id} className="blog-card" onClick={() => openBlogModal(blog)}>
              {blog.images && blog.images.length > 0 && (
                <div className="blog-image">
                  <img src={blog.images[0]} alt={blog.title} />
                </div>
              )}
              <div className="blog-content">
                <h3>{blog.title}</h3>
                <p className="blog-description">{blog.description}</p>
                <div className="blog-meta">
                  <span className="blog-author">By {blog.mentor_name}</span>
                  <span className="blog-date">{new Date(blog.created_at).toLocaleDateString()}</span>
                </div>
                <div className="blog-stats">
                  <span>❤️ {blog.likes_count}</span>
                  <span>💬 {blog.comments_count}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {selectedBlog && (
        <div className="blog-modal" onClick={closeBlogModal}>
          <div className="blog-modal-content" onClick={e => e.stopPropagation()}>
            <button className="close-btn" onClick={closeBlogModal}>×</button>
            
            <div className="blog-header-modal">
              <h2>{selectedBlog.title}</h2>
              <div className="blog-meta">
                <span>By {selectedBlog.mentor_name}</span>
                <span>{new Date(selectedBlog.created_at).toLocaleDateString()}</span>
              </div>
            </div>

            {selectedBlog.images && selectedBlog.images.length > 0 && (
              <div className="blog-images">
                {selectedBlog.images.map((img, index) => (
                  <img key={index} src={img} alt={`Blog image ${index + 1}`} />
                ))}
              </div>
            )}

            <div className="blog-content-modal">
              <p>{selectedBlog.content}</p>
            </div>

            <div className="blog-actions">
              {userRole === 'mentee' && (
                <button 
                  className={`like-btn ${likedBlogs.includes(selectedBlog.id) ? 'liked' : ''}`}
                  onClick={() => handleLike(selectedBlog.id)}
                >
                  {likedBlogs.includes(selectedBlog.id) ? '❤️ Liked' : '🤍 Like'}
                </button>
              )}
              <span className="stats">❤️ {selectedBlog.likes_count} 💬 {selectedBlog.comments_count}</span>
            </div>

            <div className="comments-section">
              <h3>Comments</h3>
              
              <div className="add-comment">
                <textarea
                  value={newComment}
                  onChange={(e) => setNewComment(e.target.value)}
                  placeholder="Write a comment..."
                  rows="3"
                />
                <button onClick={handleAddComment}>Post Comment</button>
              </div>

              <div className="comments-list">
                {comments.filter(comment => !comment.parent_comment_id).map(comment => (
                  <div key={comment.id} className="comment">
                    <div className="comment-header">
                      <img 
                        src={comment.author_avatar || 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzIiIGhlaWdodD0iMzIiIHZpZXdCb3g9IjAgMCAzMiAzMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGNpcmNsZSBjeD0iMTYiIGN5PSIxNiIgcj0iMTYiIGZpbGw9IiNFMUU1RTkiLz4KPHN2ZyB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeD0iMTAiIHk9IjEwIj4KPHBhdGggZD0iTTEyIDEyQzE0LjIwOTEgMTIgMTYgMTAuMjA5MSAxNiA4QzE2IDUuNzkwODYgMTQuMjA5MSA0IDEyIDRDOS43OTA4NiA0IDggNS43OTA4NiA4IDhDOCAxMC4yMDkxIDkuNzkwODYgMTIgMTIgMTJaIiBmaWxsPSIjNjY3RUVBIi8+CjxwYXRoIGQ9Ik0xMiAxNEM5LjMzIDEzLjk5IDcuMDEgMTUuNjIgNiAxOEMxMC4wMSAyMCAxMy45OSAyMCAxOCAxOEMxNi45OSAxNS42MiAxNC42NyAxMy45OSAxMiAxNFoiIGZpbGw9IiM2NjdFRUEiLz4KPHN2Zz4KPHN2Zz4='} 
                        alt={comment.author_name} 
                        className="comment-avatar"
                      />
                      <div className="comment-info">
                        <span className="comment-author">{comment.author_name}</span>
                        <span className="comment-date">{new Date(comment.created_at).toLocaleDateString()}</span>
                      </div>
                      {(comment.user_id === user.id || (userRole === 'mentor' && selectedBlog.mentor_id === user.id)) && (
                        <button 
                          className="delete-comment-btn"
                          onClick={() => handleDeleteComment(comment.id)}
                        >
                          🗑️
                        </button>
                      )}
                    </div>
                    <p className="comment-content">{comment.content}</p>
                    
                    {userRole === 'mentor' && selectedBlog.mentor_id === user.id && (
                      <button 
                        className="reply-btn"
                        onClick={() => setReplyingTo(comment.id)}
                      >
                        💬 Reply
                      </button>
                    )}
                    
                    {replyingTo === comment.id && (
                      <div className="reply-form">
                        <textarea
                          value={replyText}
                          onChange={(e) => setReplyText(e.target.value)}
                          placeholder="Write a reply..."
                          rows="2"
                        />
                        <div className="reply-actions">
                          <button onClick={() => handleAddReply(comment.id)}>Reply</button>
                          <button onClick={() => { setReplyingTo(null); setReplyText(''); }}>Cancel</button>
                        </div>
                      </div>
                    )}
                    
                    {/* Show replies */}
                    <div className="replies">
                      {comments.filter(reply => reply.parent_comment_id === comment.id).map(reply => (
                        <div key={reply.id} className="reply">
                          <div className="comment-header">
                            <img 
                              src={reply.author_avatar || 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGNpcmNsZSBjeD0iMTIiIGN5PSIxMiIgcj0iMTIiIGZpbGw9IiNFMUU1RTkiLz4KPHN2ZyB3aWR0aD0iOCIgaGVpZ2h0PSI4IiB2aWV3Qm94PSIwIDAgMjQgMjQiIGZpbGw9Im5vbmUiIHg9IjgiIHk9IjgiPgo8cGF0aCBkPSJNMTIgMTJDMTQuMjA5MSAxMiAxNiAxMC4yMDkxIDE2IDhDMTYgNS43OTA4NiAxNC4yMDkxIDQgMTIgNEM5Ljc5MDg2IDQgOCA1Ljc5MDg2IDggOEM4IDEwLjIwOTEgOS43OTA4NiAxMiAxMiAxMloiIGZpbGw9IiM2NjdFRUEiLz4KPHBhdGggZD0iTTEyIDE0QzkuMzMgMTMuOTkgNy4wMSAxNS42MiA2IDE4QzEwLjAxIDIwIDEzLjk5IDIwIDE4IDE4QzE2Ljk5IDE1LjYyIDE0LjY3IDEzLjk5IDEyIDE0WiIgZmlsbD0iIzY2N0VFQSIvPgo8L3N2Zz4KPHN2Zz4='} 
                              alt={reply.author_name} 
                              className="reply-avatar"
                            />
                            <div className="comment-info">
                              <span className="comment-author">{reply.author_name}</span>
                              <span className="comment-date">{new Date(reply.created_at).toLocaleDateString()}</span>
                            </div>
                            {(reply.user_id === user.id || (userRole === 'mentor' && selectedBlog.mentor_id === user.id)) && (
                              <button 
                                className="delete-comment-btn"
                                onClick={() => handleDeleteComment(reply.id)}
                              >
                                🗑️
                              </button>
                            )}
                          </div>
                          <p className="comment-content">{reply.content}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default BlogSection;