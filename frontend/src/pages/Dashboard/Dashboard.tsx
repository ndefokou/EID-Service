import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import EidProcess from '../../components/eid/EidProcess/EidProcess';
import EidCard from '../../components/eid/EidCard/EidCard';
import * as EidService from '../../services/eidService'; // This import will also cause an error initially
import styles from './Dashboard.module.scss'; // Corrected import for CSS module

const Dashboard: React.FC = () => {
  const { isAuthenticated, user, loading } = useAuth();
  const navigate = useNavigate();
  const [eidFlowState, setEidFlowState] = useState<any>(null); // State for eID flow data
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!loading && !isAuthenticated) {
      navigate('/login');
    }
  }, [isAuthenticated, loading, navigate]);

  const startEidProcess = async () => {
    try {
      setError(null);
      const response = await EidService.startEidAuthentication();
      setEidFlowState(response);
      // In a real scenario, you'd likely redirect to the eID client or open a modal
      // For now, we'll just display the state
      console.log('eID Authentication started:', response);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to start eID authentication.');
      console.error('Error starting eID authentication:', err);
    }
  };

  if (loading) {
    return <div>Loading user data...</div>;
  }

  return (
    <div className={styles['dashboard-page']}>
      <div className="container">
        <h1>Welcome, {user?.username || 'Guest'}!</h1>
        <p>This is your personalized dashboard.</p>

        <section className={styles['eid-section']}>
          <h2>eID Functionality</h2>
          <p>Leverage the German eID to verify your identity or access secure services.</p>
          <button className={`${styles.button} ${styles['button-primary']}`} onClick={startEidProcess}>
            Start eID Authentication
          </button>
          {error && <p className={styles['error-message']}>{error}</p>}

          {eidFlowState && (
            <div className={styles['eid-status-area']}>
              <h3>eID Process Status</h3>
              <EidProcess
                currentStep={1} // Placeholder, will be updated with actual flow logic
                maxSteps={3} // Placeholder, will be updated with actual flow logic
                statusMessage="Please follow the instructions on your eID client."
                onCancel={() => console.log('eID process cancelled')} // Placeholder
              />
              <EidCard status="initial" message="Please follow the instructions on your eID client." />
              <pre>{JSON.stringify(eidFlowState, null, 2)}</pre>
            </div>
          )}
        </section>

        <section className={styles['profile-section']}>
          <h2>Your Profile</h2>
          <div className={styles['profile-info']}>
            <p><strong>Username:</strong> {user?.username}</p>
            <p><strong>Email:</strong> {user?.email}</p>
            {/* Display more user attributes if available from the backend */}
          </div>
          <button className={`${styles.button} ${styles['button-secondary']}`}>Edit Profile</button>
        </section>
      </div>
    </div>
  );
};

export default Dashboard;