import React from 'react';
import { Link } from 'react-router-dom';
import './Footer.scss'; // Assuming you'll create a Footer.scss

const Footer: React.FC = () => {
  return (
    <footer className="footer">
      <div className="footer__container">
        <p>&copy; {new Date().getFullYear()} German eID Service. All rights reserved.</p>
        <nav>
          <ul>
            <li><Link to="/privacy">Privacy Policy</Link></li>
            <li><Link to="/terms">Terms of Service</Link></li>
            <li><Link to="/contact">Contact</Link></li>
          </ul>
        </nav>
      </div>
    </footer>
  );
};

export default Footer;