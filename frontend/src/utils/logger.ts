// A simple logger utility
const logger = {
  info: (...args: any[]) => {
    if (process.env.NODE_ENV !== 'production') {
      console.log('INFO:', ...args);
    }
  },
  warn: (...args: any[]) => {
    if (process.env.NODE_ENV !== 'production') {
      console.warn('WARN:', ...args);
    }
  },
  error: (...args: any[]) => {
    console.error('ERROR:', ...args);
  },
};

export default logger;