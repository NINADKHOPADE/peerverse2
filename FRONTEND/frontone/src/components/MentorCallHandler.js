import React, { useState, useEffect } from 'react';
import VideoCall from './VideoCall';

const MentorCallHandler = ({ user, children }) => {
  const [activeCall, setActiveCall] = useState(null);
  const [showCallModal, setShowCallModal] = useState(false);

  const handleCallEnd = () => {
    setActiveCall(null);
  };

  const handleJoinSession = (callId, channelName) => {
    setActiveCall({ callId, channelName });
    setShowCallModal(false);
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
    <>
      {React.cloneElement(children, { onJoinSession: handleJoinSession })}
    </>
  );
};

export default MentorCallHandler;