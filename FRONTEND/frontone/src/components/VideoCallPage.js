import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import VideoCall from './VideoCall';

const VideoCallPage = () => {
  const { callId } = useParams();
  const [user, setUser] = useState(null);

  useEffect(() => {
    // Get user from localStorage
    const userData = localStorage.getItem('user');
    if (userData) {
      setUser(JSON.parse(userData));
    }
  }, []);

  const handleEndCall = () => {
    window.close();
  };

  if (!user) {
    return <div>Loading...</div>;
  }

  return (
    <VideoCall 
      callId={callId}
      user={user}
      onEndCall={handleEndCall}
    />
  );
};

export default VideoCallPage;