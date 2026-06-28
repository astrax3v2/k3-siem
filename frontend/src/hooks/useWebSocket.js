import { useEffect, useRef, useState, useCallback } from 'react';

export function useWebSocket() {
  const ws = useRef(null);
  const [connected, setConnected] = useState(false);
  const [liveEvents, setLiveEvents] = useState([]);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const listeners = useRef({});

  const connect = useCallback(() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = process.env.NODE_ENV === 'development' ? 'localhost:3001' : window.location.host;
    const url = `${proto}//${host}/ws`;

    ws.current = new WebSocket(url);

    ws.current.onopen = () => {
      setConnected(true);
      console.log('[WS] Connected to K3 SIEM live stream');
    };

    ws.current.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'events') {
          setLiveEvents(prev => [...msg.data, ...prev].slice(0, 200));
        }
        if (msg.type === 'alerts') {
          setLiveAlerts(prev => [...msg.data, ...prev].slice(0, 50));
        }
        // Call registered listeners
        Object.values(listeners.current).forEach(fn => fn(msg));
      } catch (_) {}
    };

    ws.current.onclose = () => {
      setConnected(false);
      // Reconnect after 3s
      setTimeout(connect, 3000);
    };

    ws.current.onerror = () => {
      ws.current?.close();
    };
  }, []);

  useEffect(() => {
    connect();
    return () => ws.current?.close();
  }, [connect]);

  const on = useCallback((key, fn) => {
    listeners.current[key] = fn;
    return () => delete listeners.current[key];
  }, []);

  return { connected, liveEvents, liveAlerts, on };
}
