import { useState, useEffect, useRef, useCallback } from 'react';
import type { VtsResponse } from '../types';
import { rateTracker } from '../utils/rateTracker';

export function useVtsData(initialInterval = 1000) {
  const [data, setData] = useState<VtsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [interval, setInterval_] = useState(initialInterval);
  const timerRef = useRef<number | undefined>(undefined);

  const fetchData = useCallback(async () => {
    try {
      const res = await fetch('/status/format/json');
      if (!res.ok) {
        setError(`HTTP ${res.status}`);
        return;
      }
      const json: VtsResponse = await res.json();
      rateTracker.refresh(json.nowMsec);
      setData(json);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    /* fetchData reaches setState only after an await, except that a
       synchronous throw from fetch() would hit its catch first. Queue the
       first call so the effect body never sets state itself. */
    queueMicrotask(fetchData);
    timerRef.current = window.setInterval(fetchData, interval);
    return () => {
      if (timerRef.current !== undefined) {
        window.clearInterval(timerRef.current);
      }
    };
  }, [fetchData, interval]);

  const setInterval = useCallback((ms: number) => {
    setInterval_(ms);
  }, []);

  return { data, error, interval, setInterval };
}
