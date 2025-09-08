import axios from 'axios';
import { API_ENDPOINTS } from '../config/api';

export interface UserProfile {
  id: string;
  username: string;
  email: string;
  // Add other user profile fields as needed
}

export const fetchUserProfile = async (): Promise<UserProfile> => {
  try {
    const token = localStorage.getItem('authToken');
    if (!token) {
      throw new Error('No authentication token found.');
    }

    const response = await axios.get(API_ENDPOINTS.USER.PROFILE, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    return response.data;
  } catch (error: any) {
    if (axios.isAxiosError(error) && error.response) {
      throw new Error(error.response.data.message || 'Failed to fetch user profile.');
    }
    throw new Error('An unexpected error occurred while fetching user profile.');
  }
};

export const updateUserProfile = async (profileData: Partial<UserProfile>): Promise<UserProfile> => {
  try {
    const token = localStorage.getItem('authToken');
    if (!token) {
      throw new Error('No authentication token found.');
    }

    const response = await axios.put(API_ENDPOINTS.USER.UPDATE_PROFILE, profileData, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    return response.data;
  } catch (error: any) {
    if (axios.isAxiosError(error) && error.response) {
      throw new Error(error.response.data.message || 'Failed to update user profile.');
    }
    throw new Error('An unexpected error occurred while updating user profile.');
  }
};