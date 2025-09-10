import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { EidFlowContainer } from '../../components/eid/EidFlowContainer/EidFlowContainer';
import './Home.scss'; // Page-specific styling

const Home: React.FC = () => {
  const navigate = useNavigate();
  const [eidFlowActive, setEidFlowActive] = useState(false);
  const [eidError, setEidError] = useState<string | null>(null);

  const handleEidSuccess = (attributes: Record<string, any>) => {
    // In a real application, you would log in the user with these attributes
    // For now, we'll simulate a redirect.
    console.log('eID Authentication Successful. Attributes:', attributes);
    setEidFlowActive(false);
    navigate('/dashboard'); // Redirect to dashboard on success
  };

  const handleEidFailure = (error: string) => {
    console.error('eID Authentication Failed:', error);
    setEidError(error);
    setEidFlowActive(false);
  };

  const startEidFlow = () => {
    setEidFlowActive(true);
    setEidError(null);
  };

  return (
    <div className="home-page">
      <section className="home-page__hero">
        <h1>Welcome to the German eID Service</h1>
        <p>
          Securely identify yourself online using your German eID card. Access digital services
          with confidence and convenience.
        </p>
        <div className="home-page__cta">
          {eidFlowActive ? (
            <EidFlowContainer onEidSuccess={handleEidSuccess} onEidFailure={handleEidFailure} />
          ) : (
            <>
              {eidError && <p className="error-message">{eidError}</p>}
              <button onClick={startEidFlow} className="button button--primary button--large">
                Start eID Verification
              </button>
            </>
          )}
        </div>
      </section>

      <section className="home-page__features">
        <div className="feature-card">
          <h3>Secure Identification</h3>
          <p>Utilize the highest security standards of the German eID card for online authentication.</p>
        </div>
        <div className="feature-card">
          <h3>Data Protection</h3>
          <p>Your personal data is protected in accordance with GDPR and German eID Act.</p>
        </div>
        <div className="feature-card">
          <h3>User-Friendly</h3>
          <p>A streamlined process makes online identification simple and efficient.</p>
        </div>
      </section>
    </div>
  );
};

export default Home;