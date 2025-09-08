import React from 'react';

interface CardReaderStatusProps {
  status: 'connected' | 'disconnected' | 'error' | 'reading';
  message?: string;
}

const CardReaderStatus: React.FC<CardReaderStatusProps> = ({ status, message }) => {
  const statusClasses = {
    connected: 'card-reader-status--connected',
    disconnected: 'card-reader-status--disconnected',
    error: 'card-reader-status--error',
    reading: 'card-reader-status--reading',
  };

  return (
    <div className={`card-reader-status ${statusClasses[status]}`}>
      <p>Status: {status.charAt(0).toUpperCase() + status.slice(1)}</p>
      {message && <p>{message}</p>}
    </div>
  );
};

export default CardReaderStatus;