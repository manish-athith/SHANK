import { useEffect, useMemo, useState } from 'react';
import { notifyAuthInvalid } from './auth.js';

const AUTH_CLOSE_CODES = new Set([1008, 4001, 4401, 4403]);

function isAuthClose(event, opened) {
  const reason = event.reason?.toLowerCase() || '';
  return (
    AUTH_CLOSE_CODES.has(event.code) ||
    reason.includes('auth') ||
    reason.includes('token') ||
    reason.includes('unauthorized') ||
    reason.includes('forbidden') ||
    (!opened && event.code === 1006)
  );
}

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
      setEvents([]);
      return undefined;
    }
    let opened = false;
    const socket = new WebSocket(wsUrl);
    socket.onopen = () => {
      opened = true;
      setConnected(true);
    };
    socket.onclose = (event) => {
      setConnected(false);
      if (isAuthClose(event, opened)) {
        notifyAuthInvalid();
      }
    };
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
