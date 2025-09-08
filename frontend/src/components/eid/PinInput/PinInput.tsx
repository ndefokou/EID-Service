import React, { useState } from 'react';

interface PinInputProps {
  onPinSubmit: (pin: string) => void;
  isLoading: boolean;
  error?: string;
}

const PinInput: React.FC<PinInputProps> = ({ onPinSubmit, isLoading, error }) => {
  const [pin, setPin] = useState<string>('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (pin.length === 6) { // Assuming a 6-digit PIN
      onPinSubmit(pin);
    } else {
      // Handle invalid PIN length feedback
    }
  };

  return (
    <form onSubmit={handleSubmit} className="pin-input-form">
      <label htmlFor="pin">Enter your eID PIN:</label>
      <input
        type="password"
        id="pin"
        value={pin}
        onChange={(e) => setPin(e.target.value)}
        maxLength={6}
        pattern="\d{6}"
        inputMode="numeric"
        disabled={isLoading}
        required
      />
      {error && <p className="error-message">{error}</p>}
      <button type="submit" disabled={isLoading || pin.length !== 6}>
        {isLoading ? 'Verifying...' : 'Submit PIN'}
      </button>
    </form>
  );
};

export default PinInput;