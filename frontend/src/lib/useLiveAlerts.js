import { useEffect, useMemo, useState } from 'react';

export function useLiveAlerts(token) {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);

  const wsUrl = useMemo(() => {
    const apiUrl = import.meta.env.VITE_WS_URL;
    if (apiUrl) return token ? `${apiUrl}?token=${encodeURIComponent(token)}` : apiUrl;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const base = `${protocol}//${window.location.host}/api/v1/alerts/live`;
    return token ? `${base}?token=${encodeURIComponent(token)}` : base;
  }, [token]);

  useEffect(() => {
    if (!token) {
      setConnected(false);
      return undefined;
    }
    const socket = new WebSocket(wsUrl);
    socket.onopen = () => setConnected(true);
    socket.onclose = () => setConnected(false);
    socket.onmessage = (message) => {
      const payload = JSON.parse(message.data);
      if (payload.type === 'alert' && payload.alert) {
        setEvents((current) => [payload.alert, ...current].slice(0, 50));
      }
    };
    return () => socket.close();
  }, [token, wsUrl]);

  return { events, connected };
}
