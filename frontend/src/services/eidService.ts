import axios from 'axios';
import { API_ENDPOINTS } from '../config/api';
import { EID_CONFIG } from '../config/eid';
import { EidAuthResponse, EidStatusResponse } from '../types/eid'; // Import from types

export const startEidAuthentication = async (): Promise<EidAuthResponse> => {
  try {
    const response = await axios.post(API_ENDPOINTS.EID.START_AUTH, {
      relyingPartyId: EID_CONFIG.RP_ID,
      callbackUrl: EID_CONFIG.EID_CALLBACK_URL,
      requiredAttributes: EID_CONFIG.REQUESTED_ATTRIBUTES,
    });
    return response.data;
  } catch (error: any) {
    if (axios.isAxiosError(error) && error.response) {
      throw new Error(error.response.data.message || 'Failed to start eID authentication.');
    }
    throw new Error('An unexpected error occurred during eID authentication initiation.');
  }
};

export const pollEidAuthenticationStatus = async (statusUrl: string): Promise<EidStatusResponse> => {
  try {
    const response = await axios.get(statusUrl);
    return response.data;
  } catch (error: any) {
    if (axios.isAxiosError(error) && error.response) {
      throw new Error(error.response.data.message || 'Failed to poll eID authentication status.');
    }
    throw new Error('An unexpected error occurred while polling eID authentication status.');
  }
};

export const getEidAttributes = async (transactionId: string): Promise<any> => {
  try {
    const response = await axios.get(`${API_ENDPOINTS.EID.GET_ATTRIBUTES}/${transactionId}`);
    return response.data;
  } catch (error: any) {
    if (axios.isAxiosError(error) && error.response) {
      throw new Error(error.response.data.message || 'Failed to retrieve eID attributes.');
    }
    throw new Error('An unexpected error occurred while retrieving eID attributes.');
  }
};