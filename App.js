/**
 * NFC Ticket Reader — Entry Point
 *
 * Android NFC reader app for validating Google Wallet
 * and Apple Wallet (VAS) event tickets.
 */

import ScannerScreen from './src/screens/ScannerScreen';

import React from 'react';
import { View, Text, ScrollView, SafeAreaView } from 'react-native';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ error, errorInfo });
  }

  render() {
    if (this.state.hasError) {
      return (
        <SafeAreaView style={{ flex: 1, backgroundColor: '#b71c1c', padding: 20 }}>
          <Text style={{ fontSize: 24, fontWeight: 'bold', color: '#fff', marginBottom: 10 }}>App Crash</Text>
          <ScrollView>
            <Text style={{ color: '#fff', fontSize: 16 }}>{this.state.error && this.state.error.toString()}</Text>
            <Text style={{ color: '#fff', fontSize: 12, marginTop: 20 }}>{this.state.errorInfo && this.state.errorInfo.componentStack}</Text>
          </ScrollView>
        </SafeAreaView>
      );
    }
    return this.props.children;
  }
}

export default function App() {
  return (
    <ErrorBoundary>
      <ScannerScreen />
    </ErrorBoundary>
  );
}
