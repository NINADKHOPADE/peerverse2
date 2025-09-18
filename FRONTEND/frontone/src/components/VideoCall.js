import React, { useState, useEffect, useRef } from 'react';
import AgoraRTC from 'agora-rtc-sdk-ng';
import axios from 'axios';
import io from 'socket.io-client';
import './VideoCall.css';

const VideoCall = ({ callId, user, onEndCall }) => {
  const [client] = useState(AgoraRTC.createClient({ mode: 'rtc', codec: 'vp8' }));
  const [localVideoTrack, setLocalVideoTrack] = useState(null);
  const [localAudioTrack, setLocalAudioTrack] = useState(null);
  const [remoteUsers, setRemoteUsers] = useState([]);
  const [isJoined, setIsJoined] = useState(false);
  const [isMuted, setIsMuted] = useState(true);
  const [isVideoOff, setIsVideoOff] = useState(true);
  const [isScreenSharing, setIsScreenSharing] = useState(false);
  const [screenShareTrack, setScreenShareTrack] = useState(null);
  const [isLocalVideoMinimized, setIsLocalVideoMinimized] = useState(false);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [showChat, setShowChat] = useState(false);
  const [joinNotifications, setJoinNotifications] = useState([]);
  const [remoteAudioMuted, setRemoteAudioMuted] = useState({});
  const [speakingUsers, setSpeakingUsers] = useState({});
  const [callDuration, setCallDuration] = useState(0);
  const [socket, setSocket] = useState(null);
  const [sessionStartTime, setSessionStartTime] = useState(null);
  const [showTimeWarning, setShowTimeWarning] = useState(false);

  
  const localVideoRef = useRef(null);
  const remoteVideoRefs = useRef({});
  const timerRef = useRef(null);

  useEffect(() => {
    const socketConnection = io('http://localhost:5000');
    setSocket(socketConnection);
    
    socketConnection.emit('join_call', callId);
    
    socketConnection.on('call_message', (data) => {
      // Only add message if it's not from current user (to avoid duplicates)
      if (data.userId !== user.id) {
        setMessages(prev => [...prev, data]);
      }
    });
    
    socketConnection.on('call_ended', (data) => {
      handleEndCall();
    });
    
    socketConnection.on('session_started', (data) => {
      setSessionStartTime(new Date(data.startTime));
    });
    
    socketConnection.on('timer_sync', (data) => {
      setCallDuration(data.duration);
    });
    
    socketConnection.on('user_joined', (data) => {
      const notification = `${data.username} joined the meeting`;
      setJoinNotifications(prev => [...prev, { id: Date.now(), message: notification }]);
      setTimeout(() => {
        setJoinNotifications(prev => prev.filter(n => n.id !== data.id));
      }, 3000);
    });
    
    socketConnection.on('user_left', (data) => {
      const notification = `${data.username} left the meeting`;
      setJoinNotifications(prev => [...prev, { id: Date.now(), message: notification }]);
      setTimeout(() => {
        setJoinNotifications(prev => prev.filter(n => n.id !== data.id));
      }, 3000);
    });
    
    socketConnection.on('force_end_call', async () => {
      await forceCleanup();
      // Close window after cleanup
      setTimeout(() => {
        window.close();
      }, 1000);
    });
    
    return () => {
      socketConnection.disconnect();
    };
  }, [callId]);

  useEffect(() => {
    initializeCall();
    
    // Cleanup on component unmount or page unload
    const handleBeforeUnload = () => {
      cleanup();
    };
    
    window.addEventListener('beforeunload', handleBeforeUnload);
    
    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
      cleanup();
    };
  }, []);

  useEffect(() => {
    if (sessionStartTime && !timerRef.current) {
      timerRef.current = setInterval(() => {
        const elapsed = Math.floor((Date.now() - sessionStartTime.getTime()) / 1000);
        setCallDuration(elapsed);
        
        // Show warning at 9:30 (570 seconds)
        if (elapsed >= 570 && elapsed < 600) {
          setShowTimeWarning(true);
        } else {
          setShowTimeWarning(false);
        }
        
        // Sync timer with other participant
        if (socket) {
          socket.emit('timer_sync', { callId, duration: elapsed });
        }
        
        // Auto-end call at exactly 10 minutes (600 seconds)
        if (elapsed >= 600) {
          handleAutoEndCall();
        }
      }, 1000);
    }
    
    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [sessionStartTime, socket, callId]);

  const initializeCall = async () => {
    try {
      // Check if already joined
      if (isJoined) {
        console.log('Already joined, skipping initialization');
        return;
      }
      
      console.log('Initializing call for user:', user.id);
      
      // Get Agora token
      const tokenResponse = await axios.post('http://localhost:5000/api/video-call/token', {
        channelName: `call_${callId}`,
        uid: user.id,
        role: 'publisher'
      });
      
      const { token, appId } = tokenResponse.data;
      
      // Remove existing event listeners to prevent duplicates
      client.removeAllListeners();
      
      // Set up client event handlers
      client.on('user-published', handleUserPublished);
      client.on('user-unpublished', handleUserUnpublished);
      client.on('user-left', handleUserLeft);
      
      // Join channel
      await client.join(appId, `call_${callId}`, token, user.id);
      setIsJoined(true);
      console.log('Successfully joined channel');
      
      // Enable volume indicator for speaking detection
      client.enableAudioVolumeIndicator();
      
      // Set up volume indicator event listener
      client.on('volume-indicator', (volumes) => {
        const speakingState = {};
        volumes.forEach((volume) => {
          // Map UID to actual user ID for proper identification
          const actualUserId = volume.uid === user.id ? user.id : volume.uid;
          speakingState[actualUserId] = volume.level > 0.1;
        });
        setSpeakingUsers(speakingState);
      });
      
      // Notify others about joining
      if (socket) {
        socket.emit('user_joined', { callId, userId: user.id, username: user.username });
      }
      
      // Check if session is already started
      try {
        const statusResponse = await axios.get(`http://localhost:5000/api/video-call/${callId}/status`);
        const call = statusResponse.data.call;
        
        if (call.status === 'active' && call.started_at) {
          const startTime = new Date(call.started_at);
          const elapsed = Math.floor((Date.now() - startTime.getTime()) / 1000);
          
          console.log('Session already active:', {
            startTime: startTime.toLocaleString(),
            elapsed,
            remaining: 600 - elapsed
          });
          
          // Only sync if session is still within 10 minutes
          if (elapsed < 600) {
            setSessionStartTime(startTime);
            setCallDuration(elapsed);
          } else {
            // Session expired, mark as completed
            console.log('Session expired, marking as completed');
            await axios.post(`http://localhost:5000/api/video-call/${callId}/end`, {
              userId: user.id,
              reason: 'time_expired'
            });
          }
        } else if (call.status === 'completed') {
          console.log('Session already completed');
          // Close window if session is completed
          setTimeout(() => window.close(), 2000);
        }
      } catch (error) {
        console.log('Could not get call status:', error);
      }
      
    } catch (error) {
      console.error('Failed to initialize call:', error);
      // Silently handle errors during auto-end
    }
  };

  const handleUserPublished = async (remoteUser, mediaType) => {
    await client.subscribe(remoteUser, mediaType);
    
    if (mediaType === 'video') {
      setRemoteUsers(prev => {
        const updated = [...prev];
        const existingIndex = updated.findIndex(u => u.uid === remoteUser.uid);
        const userName = remoteUser.uid === user.id ? 'You' : (user.role === 'mentor' ? 'Mentee' : 'Mentor');
        
        // Simple screen share detection - assume single video stream
        const isScreenShare = false; // Simplified for now
        
        if (existingIndex >= 0) {
          if (isScreenShare) {
            updated[existingIndex] = { ...updated[existingIndex], hasScreenShare: true, name: userName };
          } else {
            updated[existingIndex] = { ...updated[existingIndex], hasVideo: true, name: userName };
          }
        } else {
          updated.push({ 
            uid: remoteUser.uid, 
            hasVideo: !isScreenShare, 
            hasScreenShare: isScreenShare,
            hasAudio: false, 
            name: userName 
          });
        }
        return updated;
      });
      
      // Play remote video - prioritize screen share in main view
      setTimeout(() => {
        const isScreenShare = false; // Simplified for now
        const remoteVideoElement = remoteVideoRefs.current[remoteUser.uid];
        
        if (remoteVideoElement && remoteUser.videoTrack) {
          if (isScreenShare) {
            // Play screen share in main video area
            remoteUser.videoTrack.play(remoteVideoElement);
          } else {
            // Check if user already has screen share
            const userWithScreenShare = remoteUsers.find(u => u.uid === remoteUser.uid && u.hasScreenShare);
            if (userWithScreenShare) {
              // Play camera in PiP area
              const pipElement = remoteVideoRefs.current[`${remoteUser.uid}_camera`];
              if (pipElement) {
                remoteUser.videoTrack.play(pipElement);
              }
            } else {
              // Play camera in main area
              remoteUser.videoTrack.play(remoteVideoElement);
            }
          }
        }
      }, 100);
    }
    
    if (mediaType === 'audio') {
      setRemoteUsers(prev => {
        const updated = [...prev];
        const existingIndex = updated.findIndex(u => u.uid === remoteUser.uid);
        const userName = remoteUser.uid === user.id ? 'You' : (user.role === 'mentor' ? 'Mentee' : 'Mentor');
        if (existingIndex >= 0) {
          updated[existingIndex] = { ...updated[existingIndex], hasAudio: true, name: userName };
        } else {
          updated.push({ uid: remoteUser.uid, hasVideo: false, hasAudio: true, name: userName });
        }
        return updated;
      });
      
      if (!remoteAudioMuted[remoteUser.uid] && remoteUser.audioTrack && typeof remoteUser.audioTrack.play === 'function') {
        try {
          remoteUser.audioTrack.play();
        } catch (error) {
          console.log('Audio play error:', error);
        }
      }
    }
  };

  const handleUserUnpublished = (user, mediaType) => {
    if (mediaType === 'video') {
      setRemoteUsers(prev => 
        prev.map(u => u.uid === user.uid ? { ...u, hasVideo: false } : u)
      );
    }
    if (mediaType === 'audio') {
      setRemoteUsers(prev => 
        prev.map(u => u.uid === user.uid ? { ...u, hasAudio: false } : u)
      );
    }
  };

  const handleUserLeft = (user) => {
    setRemoteUsers(prev => prev.filter(u => u.uid !== user.uid));
  };

  const toggleMute = async () => {
    try {
      if (isMuted) {
        // Turn mic ON - create fresh track
        const audioTrack = await AgoraRTC.createMicrophoneAudioTrack({ echoCancellation: true, noiseSuppression: true });
        setLocalAudioTrack(audioTrack);
        if (client && isJoined) {
          await client.publish([audioTrack]);
        }
        setIsMuted(false);
      } else {
        // Turn mic OFF - completely release microphone
        if (localAudioTrack) {
          localAudioTrack.stop();
          localAudioTrack.close();
          
          if (client && isJoined) {
            await client.unpublish([localAudioTrack]);
          }
          
          setLocalAudioTrack(null);
        }
        setIsMuted(true);
      }
    } catch (error) {
      console.error('Microphone toggle error:', error);
      if (error.message.includes('NotReadableError') || error.message.includes('in use')) {
        // Show red X indicator instead of error
        setIsMuted(true);
      }
    }
  };

  const toggleVideo = async () => {
    try {
      if (isVideoOff) {
        // Turn camera ON
        const videoTrack = await AgoraRTC.createCameraVideoTrack({ encoderConfig: '720p_1' });
        setLocalVideoTrack(videoTrack);
        
        // Play in local video element
        if (localVideoRef.current) {
          videoTrack.play(localVideoRef.current);
        }
        
        // Publish the new track
        if (client && isJoined) {
          await client.publish([videoTrack]);
        }
        setIsVideoOff(false);
      } else {
        // Turn camera OFF
        if (localVideoTrack) {
          await localVideoTrack.setEnabled(false);
          localVideoTrack.stop();
          localVideoTrack.close();
          
          if (client && isJoined) {
            await client.unpublish([localVideoTrack]);
          }
          
          setLocalVideoTrack(null);
        }
        setIsVideoOff(true);
      }
    } catch (error) {
      console.error('Camera toggle error:', error);
      if (error.message.includes('NotReadableError') || error.message.includes('in use')) {
        // Show red X indicator instead of error
        setIsVideoOff(true);
      }
    }
  };

  const toggleScreenShare = async () => {
    try {
      if (!isScreenSharing) {
        // Create screen share track
        const screenTrack = await AgoraRTC.createScreenVideoTrack({
          encoderConfig: '720p_1',
          optimizationMode: 'detail'
        });
        
        setScreenShareTrack(screenTrack);
        
        // Replace camera with screen share
        if (localVideoTrack) {
          await client.unpublish([localVideoTrack]);
        }
        
        await client.publish([screenTrack]);
        setIsScreenSharing(true);
        
        // Show screen share in local view
        if (localVideoRef.current) {
          screenTrack.play(localVideoRef.current);
        }
        
        screenTrack.on('track-ended', async () => {
          await client.unpublish([screenTrack]);
          screenTrack.close();
          setScreenShareTrack(null);
          setIsScreenSharing(false);
          
          // Republish camera
          if (localVideoTrack) {
            await client.publish([localVideoTrack]);
            if (localVideoRef.current) {
              localVideoTrack.play(localVideoRef.current);
            }
          }
        });
      } else {
        // Stop screen sharing
        if (screenShareTrack) {
          await client.unpublish([screenShareTrack]);
          screenShareTrack.close();
          setScreenShareTrack(null);
        }
        setIsScreenSharing(false);
        
        // Republish camera
        if (localVideoTrack) {
          await client.publish([localVideoTrack]);
          if (localVideoRef.current) {
            localVideoTrack.play(localVideoRef.current);
          }
        }
      }
    } catch (error) {
      console.error('Screen sharing error:', error);
      setIsScreenSharing(false);
    }
  };

  const sendMessage = () => {
    if (newMessage.trim() && socket) {
      const messageData = {
        callId,
        userId: user.id,
        username: user.username,
        message: newMessage.trim(),
        timestamp: new Date().toISOString()
      };
      
      socket.emit('call_message', messageData);
      setMessages(prev => [...prev, messageData]);
      setNewMessage('');
    }
  };

  const handleEndCall = async () => {
    try {
      // Notify others about leaving
      if (socket) {
        socket.emit('user_left', { callId, userId: user.id, username: user.username });
      }
      
      await axios.post(`http://localhost:5000/api/video-call/${callId}/end`, {
        userId: user.id
      });
    } catch (error) {
      console.error('Error ending call:', error);
    }
    
    cleanup();
    onEndCall();
  };
  
  const handleAutoEndCall = async () => {
    try {
      // Force end call for all participants
      if (socket) {
        socket.emit('force_end_call', { callId });
      }
      
      await axios.post(`http://localhost:5000/api/video-call/${callId}/end`, {
        userId: user.id,
        reason: 'time_limit'
      });
    } catch (error) {
      console.error('Error auto-ending call:', error);
    }
    
    // Force cleanup and close window
    await forceCleanup();
    setTimeout(() => {
      window.close();
    }, 1000);
  };
  
  const forceCleanup = async () => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    
    try {
      // Force stop all tracks immediately
      if (localAudioTrack) {
        localAudioTrack.stop();
        localAudioTrack.close();
        setLocalAudioTrack(null);
      }
      if (localVideoTrack) {
        localVideoTrack.stop();
        localVideoTrack.close();
        setLocalVideoTrack(null);
      }
      
      // Force leave channel
      if (client && isJoined) {
        await client.unpublish();
        await client.leave();
      }
      
      // Clear video elements
      if (localVideoRef.current) {
        localVideoRef.current.srcObject = null;
      }
      
    } catch (error) {
      console.error('Force cleanup error:', error);
    }
    
    if (socket) {
      socket.disconnect();
    }
    
    setIsJoined(false);
  };
  
  // const handleRejoinCall = async () => {
  //   try {
  //     await cleanup();
  //     setIsJoined(false);
  //     setLocalAudioTrack(null);
  //     setLocalVideoTrack(null);
  //     setRemoteUsers([]);
  //     setIsMuted(true);
  //     setIsVideoOff(true);
  //     setMessages([]);
  //     setTimeout(() => {
  //       initializeCall();
  //     }, 3000);
  //   } catch (error) {
  //     console.error('Rejoin error:', error);
  //   }
  // };
  
  const toggleRemoteAudio = (uid) => {
    setRemoteAudioMuted(prev => {
      const newState = { ...prev, [uid]: !prev[uid] };
      
      // Find and mute/unmute remote audio
      const remoteUser = client.remoteUsers.find(u => u.uid === uid);
      if (remoteUser && remoteUser.audioTrack) {
        if (newState[uid]) {
          remoteUser.audioTrack.stop();
        } else {
          remoteUser.audioTrack.play();
        }
      }
      
      return newState;
    });
  };

  const cleanup = async () => {
    console.log('Starting cleanup...');
    
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    
    try {
      // Stop and close tracks first
      if (localAudioTrack) {
        localAudioTrack.stop();
        localAudioTrack.close();
        setLocalAudioTrack(null);
      }
      if (localVideoTrack) {
        localVideoTrack.stop();
        localVideoTrack.close();
        setLocalVideoTrack(null);
      }
      if (screenShareTrack) {
        screenShareTrack.stop();
        screenShareTrack.close();
        setScreenShareTrack(null);
      }
      
      // Leave channel if joined
      if (client && isJoined) {
        await client.unpublish();
        await client.leave();
        console.log('Left Agora channel');
      }
      
      // Clear video elements
      if (localVideoRef.current) {
        localVideoRef.current.srcObject = null;
      }
      
      // Remove all event listeners
      client.removeAllListeners();
      
    } catch (error) {
      console.error('Cleanup error:', error);
    }
    
    setIsJoined(false);
    setRemoteUsers([]);
    console.log('Cleanup completed');
  };

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <div className="video-call-container">
      <div className="video-call-header">
        <div className="call-info">
          <h3>Video Call</h3>
          {sessionStartTime ? (
            <>
              <span className={`call-duration ${showTimeWarning ? 'warning' : ''}`}>
                {formatTime(callDuration)}
              </span>
              <span className="time-limit">/ 10:00</span>
              {showTimeWarning && (
                <span className="time-warning">⚠️ 30 seconds remaining!</span>
              )}
            </>
          ) : user.role === 'mentee' ? (
            <span className="waiting-timer">Waiting for mentor to start session...</span>
          ) : (
            <span className="mentor-ready">Ready to start session</span>
          )}
        </div>
        <button onClick={() => setShowChat(!showChat)} className="chat-toggle">
          💬 Chat {messages.length > 0 && `(${messages.length})`}
        </button>
      </div>

      {/* Join Notifications */}
      <div className="join-notifications">
        {joinNotifications.map(notification => (
          <div key={notification.id} className="join-notification">
            {notification.message}
          </div>
        ))}
      </div>
      
      <div className="video-call-content">
        <div className="video-area">
          <div className="remote-videos">
            {remoteUsers.map(remoteUser => (
              <div key={remoteUser.uid} className="remote-video-container">
                <div 
                  ref={el => remoteVideoRefs.current[remoteUser.uid] = el}
                  className="remote-video"
                />
                {/* Show camera in picture-in-picture when screen sharing */}
                {remoteUser.hasVideo && remoteUser.hasScreenShare && (
                  <div className="pip-camera">
                    <div 
                      ref={el => remoteVideoRefs.current[`${remoteUser.uid}_camera`] = el}
                      className="pip-video"
                    />
                  </div>
                )}
                <div className={`user-info ${speakingUsers[remoteUser.uid] ? 'speaking' : ''}`}>
                  <span>{remoteUser.name || (user.role === 'mentor' ? 'Mentee' : 'Mentor')}</span>
                  {speakingUsers[remoteUser.uid] && <span className="speaking-indicator">🎤</span>}
                  {!remoteUser.hasAudio && <span className="muted-indicator">🔇</span>}
                  {!remoteUser.hasVideo && <span className="video-off-indicator">📹</span>}
                  {remoteUser.hasScreenShare && <span className="screen-share-indicator">🖥️</span>}
                </div>
                <div className="remote-controls">
                  <button 
                    onClick={() => toggleRemoteAudio(remoteUser.uid)}
                    className={`remote-mute-btn ${remoteAudioMuted[remoteUser.uid] ? 'muted' : ''}`}
                    title={remoteAudioMuted[remoteUser.uid] ? 'Unmute' : 'Mute'}
                  >
                    {remoteAudioMuted[remoteUser.uid] ? '🔇' : '🔊'}
                  </button>
                </div>
              </div>
            ))}
            {remoteUsers.length === 0 && client.remoteUsers.length === 0 && (
              <div className="waiting-message">
                <p>Waiting for other participant to join...</p>
              </div>
            )}
            {client.remoteUsers.length > 0 && remoteUsers.length === 0 && (
              <div className="participant-joined">
                <p>{user.role === 'mentor' ? 'Mentee' : 'Mentor'} joined (camera/mic off)</p>
              </div>
            )}
          </div>

          <div className={`local-video-container ${isLocalVideoMinimized ? 'minimized' : ''}`}>
            <div ref={localVideoRef} className="local-video" />
            {isVideoOff && (
              <div className="camera-off-overlay">
                <div className="camera-off-icon">📷</div>
                <span>Camera Off</span>
              </div>
            )}
            {isScreenSharing && (
              <div className="screen-share-indicator">
                <span>🖥️ You're presenting</span>
              </div>
            )}
            {/* Show camera in PiP when screen sharing */}
            {isScreenSharing && localVideoTrack && !isVideoOff && (
              <div className="local-pip-camera">
                <div 
                  ref={el => {
                    if (el && localVideoTrack) {
                      localVideoTrack.play(el);
                    }
                  }}
                  className="pip-video"
                />
              </div>
            )}
            <div className={`local-user-info ${speakingUsers[user.id] ? 'speaking' : ''}`}>
              <span>You ({user.username})</span>
              {speakingUsers[user.id] && <span className="speaking-indicator">🎤</span>}
              {isMuted && <span className="muted-indicator">🔇</span>}
              {isVideoOff && <span className="video-off-indicator">📹</span>}
            </div>
            <button 
              className="minimize-btn"
              onClick={() => setIsLocalVideoMinimized(!isLocalVideoMinimized)}
              title={isLocalVideoMinimized ? 'Expand' : 'Minimize'}
            >
              {isLocalVideoMinimized ? '⬆️' : '⬇️'}
            </button>
          </div>
        </div>

        {showChat && (
          <div className="chat-panel">
            <div className="chat-header">
              <h4>Chat</h4>
              <button onClick={() => setShowChat(false)}>✕</button>
            </div>
            <div className="chat-messages">
              {messages.map((msg, index) => (
                <div key={index} className={`message ${msg.userId === user.id ? 'own' : 'other'}`}>
                  <span className="username">{msg.username}:</span>
                  <span className="text">{msg.message}</span>
                  <span className="time">{new Date(msg.timestamp).toLocaleTimeString('en-US', { hour12: true, hour: '2-digit', minute: '2-digit' })}</span>
                </div>
              ))}
            </div>
            <div className="chat-input">
              <input
                type="text"
                value={newMessage}
                onChange={(e) => setNewMessage(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
                placeholder="Type a message..."
              />
              <button onClick={sendMessage}>Send</button>
            </div>
          </div>
        )}
      </div>

      <div className="video-call-controls">
        <button 
          onClick={toggleMute} 
          className={`control-btn ${isMuted ? 'muted' : ''}`}
          title={isMuted ? 'Unmute' : 'Mute'}
        >
          {isMuted ? '🔇' : '🎤'}
        </button>
        
        <button 
          onClick={toggleVideo} 
          className={`control-btn ${isVideoOff ? 'video-off' : ''}`}
          title={isVideoOff ? 'Turn on camera' : 'Turn off camera'}
        >
          {isVideoOff ? '📹' : '📷'}
        </button>
        
        <button 
          onClick={toggleScreenShare} 
          className={`control-btn ${isScreenSharing ? 'sharing' : ''}`}
          title={isScreenSharing ? 'Stop sharing' : 'Share screen with audio'}
        >
          {isScreenSharing ? '🛑' : '🖥️'}
        </button>
        
        {user.role === 'mentor' && !sessionStartTime && (
          <button 
            onClick={async () => {
              // Double check if session was already started
              try {
                const statusResponse = await axios.get(`http://localhost:5000/api/video-call/${callId}/status`);
                const call = statusResponse.data.call;
                
                if (call.started_at) {
                  // Session already started, sync the time
                  const startTime = new Date(call.started_at);
                  const elapsed = Math.floor((Date.now() - startTime.getTime()) / 1000);
                  
                  if (elapsed < 600) {
                    setSessionStartTime(startTime);
                    setCallDuration(elapsed);
                    console.log('Synced to existing session');
                  }
                  return;
                }
              } catch (error) {
                console.log('Could not check session status:', error);
              }
              
              // Start new session
              const startTime = new Date();
              setSessionStartTime(startTime);
              
              try {
                const response = await axios.post(`http://localhost:5000/api/video-call/${callId}/start`, {
                  userId: user.id,
                  startTime: startTime.toISOString()
                });
                
                console.log('Started new session:', response.data);
                
                // Broadcast to all participants via socket
                if (socket) {
                  socket.emit('session_started', { callId, startTime: startTime.toISOString() });
                }
              } catch (error) {
                console.error('Failed to start session:', error);
              }
            }}
            className="control-btn start-session"
          >
            ▶️ Start Session
          </button>
        )}
        
        <button onClick={handleEndCall} className="control-btn end-call">
          📞 End Call
        </button>
      </div>
    </div>
  );
};

export default VideoCall;