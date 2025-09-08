import React from 'react';
import styles from './Button.module.scss';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({ children, className, ...rest }) => {
  return (
    <button className={`${styles.button} ${className || ''}`} {...rest}>
      {children}
    </button>
  );
};