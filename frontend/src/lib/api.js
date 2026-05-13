import axios from 'axios';
import { AUTH_TOKEN_KEY, notifyAuthInvalid, setStoredToken } from './auth.js';

const baseURL = import.meta.env.VITE_API_URL || '/api/v1';

export const api = axios.create({ baseURL });

api.interceptors.request.use((config) => {
  const token = localStorage.getItem(AUTH_TOKEN_KEY);
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      notifyAuthInvalid();
    }
    return Promise.reject(error);
  }
);

export async function login(email, password) {
  const form = new URLSearchParams();
  form.append('username', email);
  form.append('password', password);
  const { data } = await api.post('/auth/login', form, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });
  setStoredToken(data.access_token);
  return data;
}

export async function fetchStats() {
  const { data } = await api.get('/stats');
  return data;
}

export async function fetchAlerts() {
  const { data } = await api.get('/alerts?limit=100');
  return data;
}

export async function detectUrl(url) {
  const { data } = await api.post('/predict-url', { url, source: 'dashboard' });
  return data;
}
