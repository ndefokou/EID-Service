import React, { useState, useEffect } from 'react';
import styles from './AttributeConsent.module.scss';
import { Button } from '../../common/Button/Button';

interface AttributeConsentProps {
  requestedAttributes: string[];
  onConsent: (selectedAttributes: string[]) => void;
  onCancel: () => void;
  isLoading: boolean;
  error: string | null;
}

export const AttributeConsent: React.FC<AttributeConsentProps> = ({
  requestedAttributes,
  onConsent,
  onCancel,
  isLoading,
  error,
}) => {
  const [selectedAttributes, setSelectedAttributes] = useState<string[]>([]);

  useEffect(() => {
    // By default, all requested attributes are pre-selected for consent
    setSelectedAttributes(requestedAttributes);
  }, [requestedAttributes]);

  const handleCheckboxChange = (attribute: string) => {
    setSelectedAttributes((prevSelected) =>
      prevSelected.includes(attribute)
        ? prevSelected.filter((attr) => attr !== attribute)
        : [...prevSelected, attribute]
    );
  };

  const handleConsentClick = () => {
    onConsent(selectedAttributes);
  };

  return (
    <div className={styles.attributeConsent}>
      <h2 className={styles.title}>Attribute Consent</h2>
      <p className={styles.description}>
        The service requests access to the following attributes from your eID card.
        Please select the attributes you consent to share.
      </p>
      {error && <p className={styles.error}>{error}</p>}
      <div className={styles.attributeList}>
        {requestedAttributes.map((attribute) => (
          <label key={attribute} className={styles.checkboxLabel}>
            <input
              type="checkbox"
              checked={selectedAttributes.includes(attribute)}
              onChange={() => handleCheckboxChange(attribute)}
              disabled={isLoading}
            />
            {attribute}
          </label>
        ))}
      </div>
      <div className={styles.actions}>
        <Button onClick={onCancel} disabled={isLoading} className={styles.cancelButton}>
          Cancel
        </Button>
        <Button onClick={handleConsentClick} disabled={isLoading || selectedAttributes.length === 0}>
          {isLoading ? 'Consenting...' : 'Consent to Share'}
        </Button>
      </div>
    </div>
  );
};