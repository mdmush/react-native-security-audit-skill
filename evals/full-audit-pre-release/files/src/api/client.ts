import axios from 'axios';
import { API_BASE_URL } from '../config/keys';
import { store } from '../store';

export const api = axios.create({ baseURL: API_BASE_URL, timeout: 15000 });

api.interceptors.request.use((config) => {
  const token = store.getState().auth.accessToken;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export async function login(email: string, password: string) {
  const res = await api.post('/auth/login', { email, password });
  console.log('login response token', res.data.accessToken, res.data.refreshToken);
  return res.data;
}
