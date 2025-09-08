import { useEffect, useRef } from 'react';

const usePolling = (callback: () => Promise<void> | void, interval: number | null) => {
  const savedCallback = useRef<() => Promise<void> | void>();

  // Remember the latest callback.
  useEffect(() => {
    savedCallback.current = callback;
  }, [callback]);

  // Set up the interval.
  useEffect(() => {
    function tick() {
      if (savedCallback.current) {
        savedCallback.current();
      }
    }
    if (interval !== null) {
      const id = setInterval(tick, interval);
      return () => clearInterval(id);
    }
  }, [interval]);
};

export default usePolling;