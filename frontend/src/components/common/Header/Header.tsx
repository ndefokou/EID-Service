import React from 'react';
import { Link, NavLink } from 'react-router-dom';
import './Header.scss'; // Assuming you'll create a Header.scss

const Header: React.FC = () => {
  const isAuthenticated = false; // Placeholder for authentication status

  return (
    <header className="header">
      <div className="header__container">
        <Link to="/" className="header__logo">
          German eID Service
        </Link>
        <nav className="header__nav">
          <ul>
            <li>
              <NavLink to="/" className={({ isActive }) => (isActive ? 'active' : '')}>
                Home
              </NavLink>
            </li>
            {isAuthenticated ? (
              <>
                <li>
                  <NavLink to="/dashboard" className={({ isActive }) => (isActive ? 'active' : '')}>
                    Dashboard
                  </NavLink>
                </li>
                <li>
                  <button className="button button--danger button--small">Logout</button>
                </li>
              </>
            ) : (
              <>
                <li>
                  <NavLink to="/login" className={({ isActive }) => (isActive ? 'active' : '')}>
                    Login
                  </NavLink>
                </li>
                <li>
                  <NavLink to="/register" className={({ isActive }) => (isActive ? 'active' : '')}>
                    Register
                  </NavLink>
                </li>
              </>
            )}
          </ul>
        </nav>
      </div>
    </header>
  );
};

export default Header;