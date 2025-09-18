import React, { useState, useEffect } from 'react';
import axios from 'axios';
import io from 'socket.io-client';
import './CallRequestModal.css';

const CallRequestModal = ({ user, onCallStart, onClose }) => {
  const [incomingCall, setIncomingCall] = useState(null);
  const [socket, setSocket] = useState(null);

  useEffect(() => {
    if (!user || !user.id || user.role === 'mentor') return;
    
    const socketConnection = io('http://localhost:5000');
    setSocket(socketConnection);
    
    socketConnection.emit('join_user_room', user.id);
    
    socketConnection.on('call_request', (data) => {
      console.log('Incoming call request:', data);
      setIncomingCall(data);
    });
    
    socketConnection.on('call_accepted', (data) => {
      console.log('Call accepted:', data);
      onCallStart(data.callId, data.channelName);
    });
    
    socketConnection.on('call_rejected', () => {
      setIncomingCall(null);
      alert('Call was rejected by the mentor');
    });
    
    return () => {
      socketConnection.disconnect();
    };
  }, [user.id, onCallStart]);

  // Disable for mentors - they should use Sessions tab
  if (user?.role === 'mentor') return null;

  const acceptCall = async () => {
    try {
      await axios.post(`http://localhost:5000/api/video-call/${incomingCall.callId}/accept`, {
        mentorId: user.id
      });
      
      onCallStart(incomingCall.callId, incomingCall.channelName);
      setIncomingCall(null);
    } catch (error) {
      console.error('Error accepting call:', error);
    }
  };

  const rejectCall = async () => {
    try {
      await axios.post(`http://localhost:5000/api/video-call/${incomingCall.callId}/reject`, {
        mentorId: user.id
      });
      
      setIncomingCall(null);
    } catch (error) {
      console.error('Error rejecting call:', error);
    }
  };

  if (!incomingCall) return null;

  return (
    <div className="call-request-overlay">
      <div className="call-request-modal">
        <div className="call-request-header">
          <h3>Incoming Video Call</h3>
        </div>
        
        <div className="call-request-content">
          <div className="caller-info">
            <div className="caller-avatar">
              <span>{incomingCall.menteeName.charAt(0).toUpperCase()}</span>
            </div>
            <h4>{incomingCall.menteeName}</h4>
            <p>wants to start a video call with you</p>
          </div>
          
          <div className="call-animation">
            <div className="pulse-ring"></div>
            <div className="pulse-ring delay-1"></div>
            <div className="pulse-ring delay-2"></div>
            <div className="call-icon">📞</div>
          </div>
        </div>
        
        <div className="call-request-actions">
          <button onClick={rejectCall} className="reject-btn">
            ❌ Decline
          </button>
          <button onClick={acceptCall} className="accept-btn">
            ✅ Accept
          </button>
        </div>
      </div>
    </div>
  );
};

export default CallRequestModal;