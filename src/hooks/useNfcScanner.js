/**
 * useNfcScanner — Custom hook that orchestrates the NFC scan flow
 *
 * States: idle → scanning → validating → success/error → idle
 *
 * Handles:
 * - NFC initialization and readiness checks
 * - Scan → detect provider → read payload → validate with backend
 * - Haptic feedback (vibration)
 * - Auto-reset after result display
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { Vibration, Platform } from 'react-native';
import { initNfc, isNfcEnabled, scanTicket, cancelScan, setCollectorPrivateKey, hasPrivateKey } from '../services/nfcService';
import { validateTicket, checkBackendHealth, API_URL } from '../services/validationService';

// ── Private key (base64url 'd' parameter from the JWK keypair) ──
// This is the private key whose public counterpart was uploaded to Google Pay & Wallet Console.
// Generated with: node generate_keys.js
const COLLECTOR_PRIVATE_KEY_D = 'JRx-71E6V3SPnsNlOEh8GUuFEU5oLBPuHd2idPP_XxM';


const MERCHANT_ID = process.env.EXPO_PUBLIC_APPLE_VAS_MERCHANT_ID || 'com.example.eventapp';
const AUTO_RESET_MS = 4000;

/**
 * @typedef {'idle'|'scanning'|'validating'|'success'|'error'} ScanStatus
 */

/**
 * @returns {{
 *   status: ScanStatus,
 *   ticket: object|null,
 *   error: string|null,
 *   provider: string|null,
 *   nfcReady: boolean,
 *   backendReady: boolean,
 *   scanCount: number,
 *   startScan: () => Promise<void>,
 *   stopScan: () => void,
 *   resetScan: () => void,
 * }}
 */
export default function useNfcScanner() {
  const [status, setStatus] = useState('idle');
  const [ticket, setTicket] = useState(null);
  const [error, setError] = useState(null);
  const [provider, setProvider] = useState(null);
  const [nfcReady, setNfcReady] = useState(false);
  const [backendReady, setBackendReady] = useState(false);
  const [scanCount, setScanCount] = useState(0);
  const [progressLogs, setProgressLogs] = useState([]);

  const resetTimer = useRef(null);
  const isScanning = useRef(false);

  // ── Initialize NFC on mount ──
  useEffect(() => {
    async function init() {
      // Configure the collector private key for Smart Tap crypto
      if (!hasPrivateKey()) {
        setCollectorPrivateKey(COLLECTOR_PRIVATE_KEY_D);
      }

      const ready = await initNfc();
      setNfcReady(ready);

      const healthy = await checkBackendHealth();
      setBackendReady(healthy);
    }
    init();

    // Check backend periodically
    const interval = setInterval(async () => {
      const healthy = await checkBackendHealth();
      setBackendReady(healthy);
    }, 30000);

    return () => {
      clearInterval(interval);
      cancelScan();
      if (resetTimer.current) clearTimeout(resetTimer.current);
    };
  }, []);

  // ── Vibration patterns ──
  const vibrateSuccess = useCallback(() => {
    if (Platform.OS === 'android') {
      Vibration.vibrate([0, 100, 80, 100]); // Two short pulses
    } else {
      Vibration.vibrate(100);
    }
  }, []);

  const vibrateError = useCallback(() => {
    if (Platform.OS === 'android') {
      Vibration.vibrate([0, 400]); // One long pulse
    } else {
      Vibration.vibrate(400);
    }
  }, []);

  // ── Reset to idle ──
  const resetScan = useCallback(() => {
    if (resetTimer.current) clearTimeout(resetTimer.current);
    setStatus('idle');
    setTicket(null);
    setError(null);
    setProvider(null);
    setProgressLogs([]);
  }, []);

  // ── Schedule auto-reset ──
  const scheduleReset = useCallback((isError = false) => {
    if (resetTimer.current) clearTimeout(resetTimer.current);
    // Don't auto-reset on error so the user can read the logs
    if (!isError) {
      resetTimer.current = setTimeout(() => {
        resetScan();
      }, AUTO_RESET_MS);
    }
  }, [resetScan]);

  // ── Stop scanning ──
  const stopScan = useCallback(() => {
    isScanning.current = false;
    cancelScan();
    setStatus('idle');
  }, []);

  // ── Start scan flow ──
  const startScan = useCallback(async () => {
    if (isScanning.current) return;
    if (!nfcReady) {
      setError('NFC no disponible');
      setStatus('error');
      vibrateError();
      scheduleReset(true);
      return;
    }

    // Check NFC is still enabled
    const enabled = await isNfcEnabled();
    if (!enabled) {
      setError('NFC está desactivado. Actívalo en Configuración.');
      setStatus('error');
      vibrateError();
      scheduleReset(true);
      return;
    }

    isScanning.current = true;
    setStatus('scanning');
    setTicket(null);
    setError(null);
    setProvider(null);
    setProgressLogs([
      `API: ${API_URL} [${backendReady ? '✓ CONECTADO' : '✗ SIN CONEXIÓN'}]`,
      'Esperando acercar teléfono...',
    ]);

    try {
      // ── Step 1: Read NFC ──
      const nfcResult = await scanTicket(MERCHANT_ID, (msg) => {
        if (isScanning.current) {
          setProgressLogs((prev) => [...prev, msg]);
        }
      });
      if (!isScanning.current) return; // cancelled

      setProvider(nfcResult.provider);
      setStatus('validating');
      setProgressLogs((prev) => [...prev, 'Enviando a backend para validación...']);

      // ── Step 2: Validate with backend ──
      const result = await validateTicket(nfcResult);
      if (!isScanning.current) return; // cancelled

      if (result.valid) {
        setTicket(result.ticket);
        setStatus('success');
        vibrateSuccess();
        setScanCount(c => c + 1);
        scheduleReset();
      } else {
        setError(getErrorMessage(result.reason));
        setStatus('error');
        vibrateError();
        scheduleReset(true);
      }

    } catch (err) {
      if (!isScanning.current) return;
      console.error('[SCAN]', err.message);
      setError(err.message || 'Error desconocido');
      setStatus('error');
      vibrateError();
      scheduleReset(true);
    } finally {
      isScanning.current = false;
      // scheduleReset is now called explicitly in the success/error branches
    }
  }, [nfcReady, vibrateSuccess, vibrateError, scheduleReset]);

  return {
    status,
    ticket,
    error,
    provider,
    progressLogs,
    nfcReady,
    backendReady,
    scanCount,
    startScan,
    stopScan,
    resetScan,
  };
}

// ─── Error Messages ───────────────────────────────────────────────

function getErrorMessage(reason) {
  switch (reason) {
    case 'already_used':
      return 'Este ticket ya fue utilizado';
    case 'not_found':
      return 'Ticket no encontrado';
    case 'expired':
      return 'Este ticket ha expirado';
    case 'invalid_payload':
      return 'Datos del ticket inválidos';
    case 'decrypt_failed':
      return 'No se pudo leer el ticket';
    case 'server_error':
      return 'Error del servidor';
    default:
      return reason || 'Error desconocido';
  }
}
