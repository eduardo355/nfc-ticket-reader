/**
 * Validation Service — HTTP client for backend communication
 *
 * Sends scanned NFC payloads to the backend for ticket validation.
 */

import axios from 'axios';

// ─── Configuration ────────────────────────────────────────────────

export const API_URL = process.env.EXPO_PUBLIC_API_URL || 'http://10.0.2.2:3000';
const API_KEY = process.env.EXPO_PUBLIC_SCANNER_API_KEY || 'test_key_123';
const SCANNER_ID = process.env.EXPO_PUBLIC_SCANNER_ID || 'scanner-dev-01';

const client = axios.create({
  baseURL: API_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
    'x-api-key': API_KEY,
    'x-scanner-id': SCANNER_ID,
  },
});

// ─── Public API ───────────────────────────────────────────────────

/**
 * Validate a scanned ticket with the backend.
 *
 * @param {object} params
 * @param {'google'|'apple'} params.provider - Wallet provider
 * @param {string} [params.rawPayload]       - Google Smart Tap TLV hex
 * @param {string} [params.encryptedToken]   - Apple VAS encrypted token hex
 * @returns {Promise<{ valid: boolean, ticket?: object, reason?: string }>}
 */
export async function validateTicket({ provider, rawPayload, encryptedToken }) {
  try {
    const body = {
      provider,
      scannedAt: new Date().toISOString(),
      scannerId: SCANNER_ID,
    };

    if (provider === 'google') {
      body.rawPayload = rawPayload;
    } else {
      body.encryptedToken = encryptedToken;
    }

    const response = await client.post('/tickets/validate', body);
    return response.data;

  } catch (err) {
    // Network error or server error
    if (err.response) {
      // Server responded with error status
      return {
        valid: false,
        reason: err.response.data?.reason || 'server_error',
        message: err.response.data?.message || 'Server error',
      };
    }

    // Network unreachable
    throw new Error(
      err.code === 'ECONNABORTED'
        ? 'Timeout — el servidor no respondió'
        : 'Sin conexión al servidor'
    );
  }
}

/**
 * Check if the backend is reachable.
 * @returns {Promise<boolean>}
 */
export async function checkBackendHealth() {
  try {
    const response = await client.get('/health', { timeout: 5000 });
    return response.data?.status === 'ok';
  } catch {
    return false;
  }
}
