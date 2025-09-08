import { useState, useCallback } from 'react';
import axios from 'axios';
import { API_BASE_URL } from '../config/env';

interface EidClientState {
  isLoading: boolean;
  error: string | null;
  data: any | null;
}

const useEidClient = () => {
  const [state, setState] = useState<EidClientState>({
    isLoading: false,
    error: null,
    data: null,
  });

  const startEidFlow = useCallback(async () => {
    setState({ isLoading: true, error: null, data: null });
    try {
      // Simulate initiating contact with the eID client or backend endpoint
      const response = await axios.post(`${API_BASE_URL}/eid/start`, {});
      setState((prevState) => ({ ...prevState, isLoading: false, data: response.data }));
      return response.data;
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || 'Failed to start eID flow';
      setState((prevState) => ({ ...prevState, isLoading: false, error: errorMessage }));
      throw new Error(errorMessage);
    }
  }, []);

  // Placeholder for handling eID client callback if needed in the frontend
  const handleEidClientCallback = useCallback(async (callbackData: any) => {
    setState((prevState) => ({ ...prevState, isLoading: true, error: null }));
    try {
      // Simulate handling the callback from the eID client (e.g., sending to backend)
      const response = await axios.post(`${API_BASE_URL}/eid/callback`, callbackData);
      setState((prevState) => ({ ...prevState, isLoading: false, data: response.data }));
      return response.data;
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || 'Failed to process eID callback';
      setState((prevState) => ({ ...prevState, isLoading: false, error: errorMessage }));
      throw new Error(errorMessage);
    }
  }, []);

  return { ...state, startEidFlow, handleEidClientCallback };
};

export default useEidClient;