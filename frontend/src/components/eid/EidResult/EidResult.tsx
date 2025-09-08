import React from 'react';

interface EidResultProps {
  success: boolean;
  message: string;
  attributes?: { [key: string]: string };
}

const EidResult: React.FC<EidResultProps> = ({ success, message, attributes }) => {
  return (
    <div className={`eid-result ${success ? 'eid-result--success' : 'eid-result--failure'}`}>
      <h3>eID Verification {success ? 'Successful' : 'Failed'}</h3>
      <p>{message}</p>
      {attributes && Object.keys(attributes).length > 0 && (
        <div>
          <h4>Received Attributes:</h4>
          <ul>
            {Object.entries(attributes).map(([key, value]) => (
              <li key={key}><strong>{key}:</strong> {value}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default EidResult;