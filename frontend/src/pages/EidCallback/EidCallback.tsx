import React, { useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { API_BASE_URL } from '../../config/env';
import axios from 'axios';

const EidCallback: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth(); // Assuming login function can handle eID attributes

  useEffect(() => {
    const processEidCallback = async () => {
      try {
        // Extract query parameters or other data from the URL
        const queryParams = new URLSearchParams(location.search);
        const paosId = queryParams.get('paosId'); // Example: parameter from eID client

        if (!paosId) {
          throw new Error('Missing PAOS ID in eID callback.');
        }

        // Send the PAOS ID to your backend for final verification
        const response = await axios.post(`${API_BASE_URL}/eid/callback`, { paosId });

        const { token, user, eIdAttributes } = response.data;

        if (token && user) {
          login(user.username, user.email, token, eIdAttributes);
          navigate('/dashboard'); // Redirect to dashboard on successful login
        } else {
          throw new Error('eID callback processing failed: No user or token received.');
        }
      } catch (error: any) {
        console.error('eID Callback Error:', error);
        // Display an error message or redirect to an error page
        navigate('/login', { state: { eidError: error.message || 'eID authentication failed.' } });
      }
    };

    processEidCallback();
  }, [location, navigate, login]);

  return (
    <div className="eid-callback-page">
      <h1>Processing eID authentication...</h1>
      <p>Please wait while we verify your identity.</p>
      {/* Optionally add a loading spinner */}
    </div>
  );
};

export default EidCallback;