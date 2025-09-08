import React, { createContext, useState, useContext, ReactNode } from 'react';

// Define the shape of the eID authentication state
interface EidFlowState {
  currentStep: number;
  maxSteps: number;
  statusMessage: string;
  error: string | null;
  transactionId: string | null;
  eIDAttributes: any | null; // Placeholder for actual eID attributes
}

// Define the actions that can be performed
interface EidFlowActions {
  startEidFlow: () => void;
  updateEidStatus: (step: number, message: string, transactionId?: string) => void;
  setEidError: (error: string) => void;
  completeEidFlow: (attributes: any) => void;
  resetEidFlow: () => void;
}

const EidFlowContext = createContext<EidFlowState & EidFlowActions | undefined>(undefined);

interface EidFlowProviderProps {
  children: ReactNode;
}

export const EidFlowProvider: React.FC<EidFlowProviderProps> = ({ children }) => {
  const [state, setState] = useState<EidFlowState>({
    currentStep: 0,
    maxSteps: 5, // Example: Start, Read Card, Authenticate, Get Attributes, Complete
    statusMessage: 'Ready to start eID authentication.',
    error: null,
    transactionId: null,
    eIDAttributes: null,
  });

  const startEidFlow = () => {
    setState({
      ...state,
      currentStep: 1,
      statusMessage: 'Initiating eID authentication...',
      error: null,
      transactionId: null,
      eIDAttributes: null,
    });
  };

  const updateEidStatus = (step: number, message: string, transactionId?: string) => {
    setState((prevState) => ({
      ...prevState,
      currentStep: step,
      statusMessage: message,
      transactionId: transactionId || prevState.transactionId,
      error: null,
    }));
  };

  const setEidError = (error: string) => {
    setState((prevState) => ({
      ...prevState,
      error,
      statusMessage: `Error: ${error}`,
    }));
  };

  const completeEidFlow = (attributes: any) => {
    setState((prevState) => ({
      ...prevState,
      currentStep: prevState.maxSteps,
      statusMessage: 'eID authentication successful!',
      eIDAttributes: attributes,
      error: null,
    }));
  };

  const resetEidFlow = () => {
    setState({
      currentStep: 0,
      maxSteps: 5,
      statusMessage: 'Ready to start eID authentication.',
      error: null,
      transactionId: null,
      eIDAttributes: null,
    });
  };

  return (
    <EidFlowContext.Provider
      value={{
        ...state,
        startEidFlow,
        updateEidStatus,
        setEidError,
        completeEidFlow,
        resetEidFlow,
      }}
    >
      {children}
    </EidFlowContext.Provider>
  );
};

export const useEidFlow = () => {
  const context = useContext(EidFlowContext);
  if (context === undefined) {
    throw new Error('useEidFlow must be used within an EidFlowProvider');
  }
  return context;
};