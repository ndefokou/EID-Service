import React from 'react';
import './EidCard.scss'; // Component-specific styling

interface EidCardProps {
  status: 'initial' | 'reading' | 'success' | 'error';
  message: string;
}

const EidCard: React.FC<EidCardProps> = ({ status, message }) => {
  const getStatusClass = () => {
    switch (status) {
      case 'reading':
        return 'eid-card--reading';
      case 'success':
        return 'eid-card--success';
      case 'error':
        return 'eid-card--error';
      default:
        return '';
    }
  };

  return (
    <div className={`eid-card ${getStatusClass()}`}>
      <div className="eid-card__icon">
        {status === 'reading' && <i className="fas fa-spinner fa-spin"></i>}
        {status === 'success' && <i className="fas fa-check-circle"></i>}
        {status === 'error' && <i className="fas fa-exclamation-circle"></i>}
        {status === 'initial' && <i className="fas fa-id-card"></i>}
      </div>
      <p className="eid-card__message">{message}</p>
    </div>
  );
};

export default EidCard;