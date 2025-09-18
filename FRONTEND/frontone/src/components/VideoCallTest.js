import React, { useState } from 'react';
import axios from 'axios';

const VideoCallTest = ({ user }) => {
  const [testResult, setTestResult] = useState('');

  const testVideoCallAPI = async () => {
    try {
      setTestResult('Testing video call API...');
      
      // Test token generation
      const tokenResponse = await axios.post('http://localhost:5000/api/video-call/token', {
        channelName: 'test_channel',
        uid: user.id,
        role: 'publisher'
      });
      
      if (tokenResponse.data.token) {
        setTestResult('✅ Video call API is working! Token generated successfully.');
      } else {
        setTestResult('❌ Token generation failed');
      }
    } catch (error) {
      setTestResult(`❌ Error: ${error.message}`);
    }
  };

  return (
    <div style={{ padding: '20px', background: '#f5f5f5', margin: '20px', borderRadius: '8px' }}>
      <h3>Video Call System Test</h3>
      <button onClick={testVideoCallAPI} style={{ 
        padding: '10px 20px', 
        background: '#0066cc', 
        color: 'white', 
        border: 'none', 
        borderRadius: '5px',
        cursor: 'pointer'
      }}>
        Test Video Call API
      </button>
      {testResult && (
        <div style={{ marginTop: '10px', padding: '10px', background: 'white', borderRadius: '5px' }}>
          {testResult}
        </div>
      )}
    </div>
  );
};

export default VideoCallTest;