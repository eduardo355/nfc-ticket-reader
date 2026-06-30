/**
 * ScannerScreen — Main UI for the NFC ticket reader
 *
 * Premium dark design with animated NFC waves, glassmorphism cards,
 * and contextual result display (success/error).
 */

import React, { useEffect, useRef } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Animated,
  Easing,
  StatusBar,
  SafeAreaView,
  Dimensions,
  Platform,
  ScrollView,
} from 'react-native';
import useNfcScanner from '../hooks/useNfcScanner';

const { width: SCREEN_WIDTH } = Dimensions.get('window');

// ─── Color Palette ────────────────────────────────────────────────
const COLORS = {
  bg: '#0A0A1A',
  bgGrad1: '#0F0F2E',
  bgGrad2: '#1A0A2E',
  surface: 'rgba(255, 255, 255, 0.06)',
  surfaceBorder: 'rgba(255, 255, 255, 0.10)',
  primary: '#6C5CE7',
  primaryLight: '#A29BFE',
  success: '#00E676',
  successBg: 'rgba(0, 230, 118, 0.08)',
  successBorder: 'rgba(0, 230, 118, 0.25)',
  error: '#FF5252',
  errorBg: 'rgba(255, 82, 82, 0.08)',
  errorBorder: 'rgba(255, 82, 82, 0.25)',
  warning: '#FFD600',
  textPrimary: '#FFFFFF',
  textSecondary: 'rgba(255, 255, 255, 0.60)',
  textTertiary: 'rgba(255, 255, 255, 0.35)',
};

// ─── Animated NFC Waves ───────────────────────────────────────────
function NfcWaves({ active, color = COLORS.primary }) {
  const wave1 = useRef(new Animated.Value(0)).current;
  const wave2 = useRef(new Animated.Value(0)).current;
  const wave3 = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    if (!active) {
      wave1.setValue(0);
      wave2.setValue(0);
      wave3.setValue(0);
      return;
    }

    const createWave = (anim, delay) =>
      Animated.loop(
        Animated.sequence([
          Animated.delay(delay),
          Animated.timing(anim, {
            toValue: 1,
            duration: 2000,
            easing: Easing.out(Easing.ease),
            useNativeDriver: true,
          }),
          Animated.timing(anim, {
            toValue: 0,
            duration: 0,
            useNativeDriver: true,
          }),
        ])
      );

    const anim = Animated.parallel([
      createWave(wave1, 0),
      createWave(wave2, 500),
      createWave(wave3, 1000),
    ]);

    anim.start();
    return () => anim.stop();
  }, [active]);

  const renderWave = (anim, size) => {
    const scale = anim.interpolate({
      inputRange: [0, 1],
      outputRange: [0.3, 1],
    });
    const opacity = anim.interpolate({
      inputRange: [0, 0.5, 1],
      outputRange: [0.6, 0.3, 0],
    });

    return (
      <Animated.View
        style={[
          styles.wave,
          {
            width: size,
            height: size,
            borderRadius: size / 2,
            borderColor: color,
            transform: [{ scale }],
            opacity,
          },
        ]}
      />
    );
  };

  return (
    <View style={styles.wavesContainer}>
      {renderWave(wave1, 200)}
      {renderWave(wave2, 260)}
      {renderWave(wave3, 320)}
    </View>
  );
}

// ─── Pulsing Icon ─────────────────────────────────────────────────
function PulsingNfcIcon({ active }) {
  const pulse = useRef(new Animated.Value(1)).current;

  useEffect(() => {
    if (!active) {
      pulse.setValue(1);
      return;
    }

    const anim = Animated.loop(
      Animated.sequence([
        Animated.timing(pulse, {
          toValue: 1.1,
          duration: 800,
          easing: Easing.inOut(Easing.ease),
          useNativeDriver: true,
        }),
        Animated.timing(pulse, {
          toValue: 1,
          duration: 800,
          easing: Easing.inOut(Easing.ease),
          useNativeDriver: true,
        }),
      ])
    );

    anim.start();
    return () => anim.stop();
  }, [active]);

  return (
    <Animated.View style={[styles.nfcIcon, { transform: [{ scale: pulse }] }]}>
      <Text style={styles.nfcIconText}>📡</Text>
    </Animated.View>
  );
}

// ─── Status Badge ─────────────────────────────────────────────────
function StatusBadge({ ready, label }) {
  return (
    <View style={[styles.badge, ready ? styles.badgeReady : styles.badgeNotReady]}>
      <View style={[styles.badgeDot, { backgroundColor: ready ? COLORS.success : COLORS.error }]} />
      <Text style={styles.badgeText}>{label}</Text>
    </View>
  );
}

// ─── Ticket Card (Success) ────────────────────────────────────────
function TicketCard({ ticket, provider }) {
  const fadeIn = useRef(new Animated.Value(0)).current;
  const slideUp = useRef(new Animated.Value(30)).current;

  useEffect(() => {
    Animated.parallel([
      Animated.timing(fadeIn, { toValue: 1, duration: 400, useNativeDriver: true }),
      Animated.spring(slideUp, { toValue: 0, friction: 8, useNativeDriver: true }),
    ]).start();
  }, []);

  return (
    <Animated.View style={[styles.ticketCard, { opacity: fadeIn, transform: [{ translateY: slideUp }] }]}>
      <View style={styles.ticketHeader}>
        <Text style={styles.ticketCheckmark}>✓</Text>
        <Text style={styles.ticketValid}>ACCESO VÁLIDO</Text>
      </View>

      <View style={styles.ticketDivider} />

      <View style={styles.ticketBody}>
        <Text style={styles.ticketHolderName}>{ticket.holderName}</Text>
        <Text style={styles.ticketEventName}>{ticket.eventName}</Text>

        <View style={styles.ticketDetails}>
          <View style={styles.ticketDetailItem}>
            <Text style={styles.ticketDetailLabel}>ASIENTO</Text>
            <Text style={styles.ticketDetailValue}>{ticket.seat}</Text>
          </View>
          <View style={styles.ticketDetailItem}>
            <Text style={styles.ticketDetailLabel}>TIPO</Text>
            <Text style={[styles.ticketDetailValue, styles.ticketType]}>{ticket.type}</Text>
          </View>
          <View style={styles.ticketDetailItem}>
            <Text style={styles.ticketDetailLabel}>FECHA</Text>
            <Text style={styles.ticketDetailValue}>{ticket.eventDate}</Text>
          </View>
        </View>
      </View>

      <View style={styles.ticketFooter}>
        <Text style={styles.ticketProvider}>
          {provider === 'google' ? '🟢 Google Wallet' : '🍎 Apple Wallet'}
        </Text>
        <Text style={styles.ticketId}>#{ticket.ticketId}</Text>
      </View>
    </Animated.View>
  );
}

// ─── Error Card ───────────────────────────────────────────────────
function ErrorCard({ message }) {
  const fadeIn = useRef(new Animated.Value(0)).current;
  const shake = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    Animated.parallel([
      Animated.timing(fadeIn, { toValue: 1, duration: 300, useNativeDriver: true }),
      Animated.sequence([
        Animated.timing(shake, { toValue: 10, duration: 50, useNativeDriver: true }),
        Animated.timing(shake, { toValue: -10, duration: 50, useNativeDriver: true }),
        Animated.timing(shake, { toValue: 8, duration: 50, useNativeDriver: true }),
        Animated.timing(shake, { toValue: -8, duration: 50, useNativeDriver: true }),
        Animated.timing(shake, { toValue: 0, duration: 50, useNativeDriver: true }),
      ]),
    ]).start();
  }, []);

  // Map error to icon
  let icon = '❌';
  if (message?.includes('utilizado')) icon = '🔒';
  if (message?.includes('expirado')) icon = '⏰';
  if (message?.includes('no encontrado')) icon = '🔍';

  return (
    <Animated.View
      style={[styles.errorCard, { opacity: fadeIn, transform: [{ translateX: shake }] }]}
    >
      <Text style={styles.errorIcon}>{icon}</Text>
      <Text style={styles.errorTitle}>ACCESO DENEGADO</Text>
      <Text style={styles.errorMessage}>{message}</Text>
    </Animated.View>
  );
}

// ─── Main Screen ──────────────────────────────────────────────────
export default function ScannerScreen() {
  const {
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
  } = useNfcScanner();

  const isIdle = status === 'idle';
  const isScanning = status === 'scanning';
  const isValidating = status === 'validating';
  const isSuccess = status === 'success';
  const isError = status === 'error';
  const isActive = isScanning || isValidating;

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor={COLORS.bg} />

      {/* ── Header ── */}
      <View style={styles.header}>
        <View style={styles.headerLeft}>
          <Text style={styles.headerTitle}>NFC Reader</Text>
          <Text style={styles.headerSubtitle}>Validación de tickets</Text>
        </View>
        <View style={styles.headerRight}>
          <StatusBadge ready={nfcReady} label="NFC" />
          <StatusBadge ready={backendReady} label="API" />
        </View>
      </View>

      {/* ── Scan Counter ── */}
      <View style={styles.counterBar}>
        <Text style={styles.counterText}>
          Tickets escaneados: <Text style={styles.counterNumber}>{scanCount}</Text>
        </Text>
      </View>

      {/* ── Main Content ── */}
      <View style={styles.content}>
        {/* Idle / Scanning state */}
        {(isIdle || isActive) && (
          <View style={styles.scanArea}>
            <NfcWaves
              active={isActive}
              color={isValidating ? COLORS.primaryLight : COLORS.primary}
            />
            <PulsingNfcIcon active={isActive} />

            <Text style={styles.scanTitle}>
              {isIdle && 'Listo para escanear'}
              {isScanning && 'Acerca el ticket...'}
              {isValidating && 'Validando...'}
            </Text>
            <View style={styles.logsContainer}>
              {progressLogs && progressLogs.map((log, i) => (
                <Text key={i} style={styles.logText}>
                  {'>'} {log}
                </Text>
              ))}
            </View>
          </View>
        )}

        {isError ? (
          <View style={{flex: 1, width: '100%'}}>
             <ErrorCard message={error} />
             <ScrollView style={styles.logsContainer} contentContainerStyle={{paddingVertical: 10}}>
                {progressLogs && progressLogs.map((log, i) => (
                  <Text key={i} style={styles.logText}>
                    {'>'} {log}
                  </Text>
                ))}
             </ScrollView>
          </View>
        ) : isSuccess && ticket ? (
          <TicketCard ticket={ticket} provider={provider} />
        ) : null}
      </View>

      {/* ── Action Button ── */}
      <View style={styles.footer}>
        {(isIdle || isError) && (
          <TouchableOpacity
            style={[styles.scanButton, !nfcReady && styles.scanButtonDisabled]}
            onPress={startScan}
            disabled={!nfcReady}
            activeOpacity={0.8}
          >
            <Text style={styles.scanButtonText}>
              {isError ? 'Reintentar' : 'Iniciar Escaneo'}
            </Text>
          </TouchableOpacity>
        )}

        {isActive && (
          <TouchableOpacity
            style={[styles.scanButton, styles.cancelButton]}
            onPress={stopScan}
            activeOpacity={0.8}
          >
            <Text style={styles.scanButtonText}>Cancelar</Text>
          </TouchableOpacity>
        )}

        {isSuccess && (
          <TouchableOpacity
            style={styles.scanButton}
            onPress={resetScan}
            activeOpacity={0.8}
          >
            <Text style={styles.scanButtonText}>Siguiente Ticket</Text>
          </TouchableOpacity>
        )}
      </View>
    </SafeAreaView>
  );
}

// ─── Styles ───────────────────────────────────────────────────────
const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: COLORS.bg,
  },

  // ── Header ──
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 24,
    paddingTop: 16,
    paddingBottom: 12,
  },
  headerLeft: {},
  headerTitle: {
    fontSize: 24,
    fontWeight: '700',
    color: COLORS.textPrimary,
    letterSpacing: -0.5,
  },
  headerSubtitle: {
    fontSize: 13,
    color: COLORS.textSecondary,
    marginTop: 2,
  },
  headerRight: {
    flexDirection: 'row',
    gap: 8,
  },

  // ── Status Badge ──
  badge: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 10,
    paddingVertical: 5,
    borderRadius: 20,
    gap: 6,
  },
  badgeReady: {
    backgroundColor: 'rgba(0, 230, 118, 0.10)',
    borderWidth: 1,
    borderColor: 'rgba(0, 230, 118, 0.20)',
  },
  badgeNotReady: {
    backgroundColor: 'rgba(255, 82, 82, 0.10)',
    borderWidth: 1,
    borderColor: 'rgba(255, 82, 82, 0.20)',
  },
  badgeDot: {
    width: 6,
    height: 6,
    borderRadius: 3,
  },
  badgeText: {
    fontSize: 12,
    fontWeight: '600',
    color: COLORS.textSecondary,
  },

  // ── Counter ──
  counterBar: {
    paddingHorizontal: 24,
    paddingVertical: 10,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.surfaceBorder,
  },
  counterText: {
    fontSize: 13,
    color: COLORS.textTertiary,
  },
  counterNumber: {
    color: COLORS.primaryLight,
    fontWeight: '700',
  },

  // ── Content ──
  content: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 24,
  },

  // ── Scan Area ──
  scanArea: {
    alignItems: 'center',
    justifyContent: 'center',
  },
  wavesContainer: {
    width: 320,
    height: 320,
    alignItems: 'center',
    justifyContent: 'center',
    position: 'relative',
  },
  wave: {
    position: 'absolute',
    borderWidth: 2,
  },
  nfcIcon: {
    position: 'absolute',
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: COLORS.surface,
    borderWidth: 1,
    borderColor: COLORS.surfaceBorder,
    alignItems: 'center',
    justifyContent: 'center',
  },
  nfcIconText: {
    fontSize: 36,
  },
  scanTitle: {
    fontSize: 22,
    fontWeight: '600',
    color: COLORS.textPrimary,
    marginTop: 24,
    textAlign: 'center',
  },
  scanSubtitle: {
    fontSize: 14,
    color: COLORS.textSecondary,
    marginTop: 8,
    textAlign: 'center',
    maxWidth: 280,
  },
  logsContainer: {
    marginTop: 16,
    width: '100%',
    paddingHorizontal: 20,
    backgroundColor: 'rgba(0,0,0,0.3)',
    borderRadius: 8,
    paddingVertical: 10,
    minHeight: 100,
  },
  logText: {
    fontSize: 12,
    color: COLORS.textTertiary,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    marginBottom: 4,
  },

  // ── Ticket Card ──
  ticketCard: {
    width: SCREEN_WIDTH - 48,
    backgroundColor: COLORS.successBg,
    borderWidth: 1,
    borderColor: COLORS.successBorder,
    borderRadius: 20,
    overflow: 'hidden',
  },
  ticketHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 16,
    gap: 10,
  },
  ticketCheckmark: {
    fontSize: 24,
    color: COLORS.success,
    fontWeight: '700',
  },
  ticketValid: {
    fontSize: 18,
    fontWeight: '800',
    color: COLORS.success,
    letterSpacing: 2,
  },
  ticketDivider: {
    height: 1,
    backgroundColor: COLORS.successBorder,
    marginHorizontal: 20,
  },
  ticketBody: {
    padding: 20,
  },
  ticketHolderName: {
    fontSize: 24,
    fontWeight: '700',
    color: COLORS.textPrimary,
    marginBottom: 4,
  },
  ticketEventName: {
    fontSize: 15,
    color: COLORS.textSecondary,
    marginBottom: 20,
  },
  ticketDetails: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  ticketDetailItem: {
    flex: 1,
  },
  ticketDetailLabel: {
    fontSize: 10,
    fontWeight: '700',
    color: COLORS.textTertiary,
    letterSpacing: 1,
    marginBottom: 4,
  },
  ticketDetailValue: {
    fontSize: 16,
    fontWeight: '600',
    color: COLORS.textPrimary,
  },
  ticketType: {
    color: COLORS.primaryLight,
  },
  ticketFooter: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 12,
    borderTopWidth: 1,
    borderTopColor: COLORS.successBorder,
  },
  ticketProvider: {
    fontSize: 13,
    color: COLORS.textSecondary,
  },
  ticketId: {
    fontSize: 12,
    color: COLORS.textTertiary,
    fontFamily: 'monospace',
  },

  // ── Error Card ──
  errorCard: {
    width: SCREEN_WIDTH - 48,
    backgroundColor: COLORS.errorBg,
    borderWidth: 1,
    borderColor: COLORS.errorBorder,
    borderRadius: 20,
    padding: 32,
    alignItems: 'center',
  },
  errorIcon: {
    fontSize: 48,
    marginBottom: 16,
  },
  errorTitle: {
    fontSize: 18,
    fontWeight: '800',
    color: COLORS.error,
    letterSpacing: 2,
    marginBottom: 8,
  },
  errorMessage: {
    fontSize: 15,
    color: COLORS.textSecondary,
    textAlign: 'center',
  },

  // ── Footer ──
  footer: {
    paddingHorizontal: 24,
    paddingBottom: 32,
    paddingTop: 16,
  },
  scanButton: {
    backgroundColor: COLORS.primary,
    borderRadius: 16,
    paddingVertical: 18,
    alignItems: 'center',
    justifyContent: 'center',
  },
  scanButtonDisabled: {
    opacity: 0.4,
  },
  cancelButton: {
    backgroundColor: 'rgba(255, 255, 255, 0.08)',
    borderWidth: 1,
    borderColor: COLORS.surfaceBorder,
  },
  scanButtonText: {
    fontSize: 17,
    fontWeight: '700',
    color: COLORS.textPrimary,
    letterSpacing: 0.5,
  },
});
