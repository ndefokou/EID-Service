import React from 'react';
import styles from './UserIdentification.module.scss';
import { Button } from '../../common/Button/Button';

interface UserIdentificationProps {
  onStartEid: () => void;
  isLoading: boolean;
  error: string | null;
}

export const UserIdentification: React.FC<UserIdentificationProps> = ({ onStartEid, isLoading, error }) => {
  return (
    <div className={styles.userIdentification}>
      <h2 className={styles.title}>eID User Identification</h2>
      <p className={styles.description}>
        To proceed, please use your German eID card for identification.
        This process will securely verify your identity and allow you to share selected attributes.
      </p>
      {error && <p className={styles.error}>{error}</p>}
      <Button onClick={onStartEid} disabled={isLoading}>
        {isLoading ? 'Starting eID...' : 'Start eID Identification'}
      </Button>
    </div>
  );
};