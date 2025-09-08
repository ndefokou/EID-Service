// Configuration for API endpoints

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:3001/api/v1';

export const API_ENDPOINTS = {
  AUTH: {
    LOGIN: `${API_BASE_URL}/auth/login`,
    REGISTER: `${API_BASE_URL}/auth/register`,
    LOGOUT: `${API_BASE_URL}/auth/logout`,
    REFRESH_TOKEN: `${API_BASE_URL}/auth/refresh`,
    PASSWORD_RESET_REQUEST: `${API_BASE_URL}/auth/password-reset/request`,
    PASSWORD_RESET_CONFIRM: `${API_BASE_URL}/auth/password-reset/confirm`,
  },
  EID: {
    START_AUTH: `${API_BASE_URL}/eid/start`,
    POLL_AUTH_STATUS: `${API_BASE_URL}/eid/status`,
    GET_ATTRIBUTES: `${API_BASE_URL}/eid/attributes`,
  },
  USER: {
    PROFILE: `${API_BASE_URL}/user/profile`,
    UPDATE_PROFILE: `${API_BASE_URL}/user/profile`,
  },
};

export default API_BASE_URL;