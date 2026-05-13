export const AUTH_TOKEN_KEY = 'shank_token';
export const AUTH_INVALID_EVENT = 'shank:auth-invalid';

const AUTH_RELATED_KEY_PATTERN = /(auth|profile|token|user)/i;

export function getStoredToken() {
  return localStorage.getItem(AUTH_TOKEN_KEY);
}

export function setStoredToken(token) {
  localStorage.setItem(AUTH_TOKEN_KEY, token);
}

export function clearStoredAuth() {
  const keysToRemove = new Set([AUTH_TOKEN_KEY, 'shank_auth', 'shank_profile', 'shank_user']);

  for (let index = 0; index < localStorage.length; index += 1) {
    const key = localStorage.key(index);
    if (key && key.toLowerCase().includes('shank') && AUTH_RELATED_KEY_PATTERN.test(key)) {
      keysToRemove.add(key);
    }
  }

  keysToRemove.forEach((key) => localStorage.removeItem(key));
}

export function notifyAuthInvalid() {
  clearStoredAuth();
  window.dispatchEvent(new Event(AUTH_INVALID_EVENT));
}
