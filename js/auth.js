/**
 * Night Market Authentication Client
 * Handles user authentication, session management, and protected route access
 */

const AuthAPI = {
  // Configuration - Use relative URL for production, localhost for development
  API_URL: window.location.hostname === 'localhost' ? 'http://localhost:3001/api' : '/api',
  TOKEN_KEY: 'nm_auth_token',
  USER_KEY: 'nm_current_user',

  /**
   * Format phone number from international (+233) to local (0XX) format
   * @param {string} phone - Phone number in any format
   * @returns {string} - Phone number in local format (0XXXXXXXXX)
   */
  formatPhoneLocal(phone) {
    if (!phone) return '';
    // Remove all non-digit characters except leading +
    let cleaned = phone.replace(/[^\d+]/g, '');
    // Convert +233 to 0
    if (cleaned.startsWith('+233')) {
      cleaned = '0' + cleaned.slice(4);
    } else if (cleaned.startsWith('233')) {
      cleaned = '0' + cleaned.slice(3);
    }
    return cleaned;
  },

  /**
   * Format phone number from local (0XX) to international (+233) format
   * @param {string} phone - Phone number in any format
   * @returns {string} - Phone number in international format (+233XXXXXXXXX)
   */
  formatPhoneInternational(phone) {
    if (!phone) return '';
    // Remove all non-digit characters
    let cleaned = phone.replace(/\D/g, '');
    // Convert leading 0 to +233
    if (cleaned.startsWith('0')) {
      cleaned = '+233' + cleaned.slice(1);
    } else if (!cleaned.startsWith('233')) {
      cleaned = '+233' + cleaned;
    } else {
      cleaned = '+' + cleaned;
    }
    return cleaned;
  },

  /**
   * Register a new user
   * @param {string} name - User's full name
   * @param {string} phone - User's phone number
   * @returns {Promise<Object>} - { success, message, token, user } or { success, error, message }
   */
  async register(name, phone) {
    try {
      const response = await fetch(`${this.API_URL}/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify({ name, phone })
      });

      const data = await response.json();

      if (data.success) {
        // Store user data; auth cookie is httpOnly
        localStorage.removeItem(this.TOKEN_KEY);
        localStorage.setItem(this.USER_KEY, JSON.stringify(data.user));
      }

      return data;
    } catch (error) {
      console.error('Registration error:', error);
      return {
        success: false,
        error: 'NETWORK_ERROR',
        message: 'Unable to connect to server. Please check your connection.'
      };
    }
  },

  /**
   * Login with name and phone number
   * @param {string} name - User's full name
   * @param {string} phone - User's phone number
   * @returns {Promise<Object>} - { success, message, token, user } or { success, error, message }
   */
  async login(name, phone) {
    try {
      const response = await fetch(`${this.API_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify({ name, phone })
      });

      const data = await response.json();

      if (data.success) {
        // Store user data; auth cookie is httpOnly
        localStorage.removeItem(this.TOKEN_KEY);
        localStorage.setItem(this.USER_KEY, JSON.stringify(data.user));
      }

      return data;
    } catch (error) {
      console.error('Login error:', error);
      return {
        success: false,
        error: 'NETWORK_ERROR',
        message: 'Unable to connect to server. Please check your connection.'
      };
    }
  },



  /**
   * Get current user from server (validates session)
   * @returns {Promise<Object>} - { success, user } or { success, error, message }
   */
  async fetchCurrentUser() {
    try {
      const response = await fetch(`${this.API_URL}/auth/me`, {
        method: 'GET',
        credentials: 'include'
      });

      const data = await response.json();

      if (data.success) {
        // Update stored user data
        localStorage.removeItem(this.TOKEN_KEY);
        localStorage.setItem(this.USER_KEY, JSON.stringify(data.user));
      } else {
        // Token invalid, clear storage
        this.logout();
      }

      return data;
    } catch (error) {
      console.error('Fetch user error:', error);
      return {
        success: false,
        error: 'NETWORK_ERROR',
        message: 'Unable to connect to server.'
      };
    }
  },

  /**
   * Get current user from localStorage (no server call)
   * @returns {Object|null} - User object or null if not logged in
   */
  getCurrentUser() {
    const userStr = localStorage.getItem(this.USER_KEY);
    if (!userStr) return null;
    try {
      return JSON.parse(userStr);
    } catch {
      return null;
    }
  },

  /**
   * Check if user is logged in
   * @returns {boolean}
   */
  isLoggedIn() {
    return !!this.getCurrentUser();
  },

  /**
   * Check if current user is admin
   * @returns {boolean}
   */
  isAdmin() {
    const user = this.getCurrentUser();
    return user && user.role === 'admin';
  },

  /**
   * Logout - clear all stored auth data
   */
  logout() {
    try {
      fetch(`${this.API_URL}/auth/logout`, {
        method: 'POST',
        credentials: 'include'
      }).catch(error => {
        console.warn('Logout request failed:', error);
      });
    } catch (error) {
      console.warn('Logout request failed:', error);
    }
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.USER_KEY);
  },

  /**
   * Require authentication - redirect to login if not logged in
   * @param {string} redirectUrl - URL to redirect to after login (default: current page)
   * @returns {boolean} - true if authenticated, false if redirecting
   */
  requireAuth(redirectUrl = null) {
    if (!this.isLoggedIn()) {
      const returnUrl = redirectUrl || window.location.pathname;
      window.location.href = `/user_login/registration/code.html?redirect=${encodeURIComponent(returnUrl)}`;
      return false;
    }
    return true;
  },

  /**
   * Require admin role - redirect if not admin
   * @returns {boolean} - true if admin, false if redirecting
   */
  requireAdmin() {
    if (!this.requireAuth()) return false;

    if (!this.isAdmin()) {
      window.location.href = '/booking_schedule/code.html';
      return false;
    }
    return true;
  },

  /**
   * Make authenticated API request
   * @param {string} endpoint - API endpoint (e.g., '/bookings')
   * @param {Object} options - Fetch options
   * @returns {Promise<Object>} - API response
   */
  async authFetch(endpoint, options = {}) {
    const url = endpoint.startsWith('http') ? endpoint : `${this.API_URL}${endpoint}`;

    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        credentials: 'include'
      });

      const data = await response.json();

      // If session expired, logout and redirect
      if (response.status === 401 || response.status === 403) {
        if (data.error === 'FORBIDDEN' || data.error === 'UNAUTHORIZED') {
          this.logout();
          this.requireAuth();
        }
      }

      return data;
    } catch (error) {
      console.error('API request error:', error);
      return {
        success: false,
        error: 'NETWORK_ERROR',
        message: 'Unable to connect to server.'
      };
    }
  }
};

// Clear any legacy token storage (auth now uses httpOnly cookies)
try {
  localStorage.removeItem(AuthAPI.TOKEN_KEY);
} catch {
  // Ignore storage access errors (e.g., private mode restrictions)
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = AuthAPI;
}
