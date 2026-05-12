import axios from 'axios';

const baseURL = import.meta.env.VITE_API_URL || '/api/v1';

export const api = axios.create({ baseURL });

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('shank_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export async function login(email, password) {
  const form = new URLSearchParams();
  form.append('username', email);
  form.append('password', password);
  const { data } = await api.post('/auth/login', form, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });
  localStorage.setItem('shank_token', data.access_token);
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

