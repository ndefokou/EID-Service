import React, { createContext, useState, useContext, useEffect, ReactNode } from 'react';

interface AuthContextType {
  isAuthenticated: boolean;
  user: { id: string; username: string; email: string; eIdAttributes?: Record<string, any> } | null; // Added eIdAttributes
  login: (username: string, email: string, token: string, eIdAttributes?: Record<string, any>) => void; // Added optional eIdAttributes
  logout: () => void;
  setAuth: (state: { isAuthenticated: boolean; user: { id: string; username: string; email: string; eIdAttributes?: Record<string, any> } | null }) => void;
  loading: boolean; // Add loading state
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<{ id: string; username: string; email: string; eIdAttributes?: Record<string, any> } | null>(null);
  const [loading, setLoading] = useState(true); // Add loading state

  // Simulate an async check for authentication status on component mount
  useEffect(() => {
    const checkAuthStatus = async () => {
      const token = localStorage.getItem('authToken');
      if (token) {
        // In a real app, you'd validate the token with your backend
        // For now, assume it's valid and set a dummy user
        setIsAuthenticated(true);
        // This should come from a decoded token or a user profile API call
        setUser({ id: '123', username: 'demoUser', email: 'user@example.com' });
      }
      setLoading(false);
    };
    checkAuthStatus();
  }, []);

  const login = (username: string, email: string, token: string, eIdAttributes?: Record<string, any>) => {
    // In a real application, you'd store the token securely (e.g., in HttpOnly cookies)
    // For this example, we'll just set authentication status and user info.
    localStorage.setItem('authToken', token);
    setIsAuthenticated(true);
    setUser({ id: '123', username, email, eIdAttributes }); // Dummy user ID with email and optional eIdAttributes
  };

  const logout = () => {
    localStorage.removeItem('authToken');
    setIsAuthenticated(false);
    setUser(null);
  };

  const setAuth = (state: { isAuthenticated: boolean; user: { id: string; username: string; email: string; eIdAttributes?: Record<string, any> } | null }) => {
    setIsAuthenticated(state.isAuthenticated);
    setUser(state.user);
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, user, login, logout, setAuth, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};