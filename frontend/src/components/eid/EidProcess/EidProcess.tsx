import React from 'react';
import EidCard from '../EidCard/EidCard';
import './EidProcess.scss'; // Component-specific styling

interface EidProcessProps {
  currentStep: number;
  maxSteps: number;
  statusMessage: string;
  error?: string;
  onCancel: () => void;
  onRetry?: () => void;
}

const EidProcess: React.FC<EidProcessProps> = ({
  currentStep,
  maxSteps,
  statusMessage,
  error,
  onCancel,
  onRetry,
}) => {
  const progressPercentage = (currentStep / maxSteps) * 100;

  return (
    <div className="eid-process">
      <div className="eid-process__header">
        <h2>eID Authentication Process</h2>
        {error ? (
          <p className="text-danger">Error: {error}</p>
        ) : (
          <p>Step {currentStep} of {maxSteps}</p>
        )}
      </div>

      <div className="eid-process__progress-bar">
        <div
          className="eid-process__progress-bar-fill"
          style={{ width: `${progressPercentage}%` }}
        ></div>
      </div>

      <div className="eid-process__card-container">
        <EidCard status={error ? 'error' : 'reading'} message={statusMessage} />
      </div>

      <div className="eid-process__actions">
        <button className="button button--secondary" onClick={onCancel}>
          Cancel
        </button>
        {error && onRetry && (
          <button className="button button--primary" onClick={onRetry}>
            Retry
          </button>
        )}
      </div>
    </div>
  );
};

export default EidProcess;