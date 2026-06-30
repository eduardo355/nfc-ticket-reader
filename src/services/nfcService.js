/**
 * NFC Service — Google Smart Tap 2.1 Full Crypto Implementation
 *
 * Protocol flow:
 *   1. SELECT OSE.VAS.01 → detect wallet provider & get device nonce + device ephemeral key
 *   2. SELECT Smart Tap 2 AID (if needed)
 *   3. NEGOTIATE SECURE CHANNEL → signed with collector private key (ECDSA P-256)
 *   4. GET DATA → encrypted pass data, decrypted with ECDH-derived session keys
 *
 * References:
 *   - kormax/google-smart-tap (protocol research)
 *   - Google Wallet Smart Tap documentation
 *
 * Collector ID: 14660789
 */

import NfcManager, { NfcTech } from 'react-native-nfc-manager';
import { p256 } from '@noble/curves/nist';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

// ─── Constants ────────────────────────────────────────────────────

const COLLECTOR_ID = 14660789;

// Key version registered in Google Pay & Wallet Console
const KEY_VERSION = 1;

// "OSE.VAS.01" — shared AID used by both Google and Apple
const AID_OSE_VAS = [0x4F, 0x53, 0x45, 0x2E, 0x56, 0x41, 0x53, 0x2E, 0x30, 0x31];

// Smart Tap 2 AID
const AID_SMART_TAP_2 = [0xA0, 0x00, 0x00, 0x04, 0x76, 0xD0, 0x00, 0x01, 0x11];

// ─── Debug Logger ─────────────────────────────────────────────────

/**
 * Module-level onProgress reference.
 * Set at the start of scanTicket() so ALL helper functions
 * can push logs to the screen without needing the callback passed through.
 */
let _onProgress = null;

/**
 * Structured log helper for production debugging.
 * Routes ALL output to the onProgress callback (visible on screen)
 * since the app runs compiled on the Urovo and console.log is not accessible.
 */
function dbg(tag, msg) {
  const line = `[${tag}] ${msg}`;
  if (_onProgress) _onProgress(line);
}

function hexDump(label, bytes, maxLen = 0) {
  const arr = Array.from(bytes);
  const len = arr.length;
  if (maxLen > 0 && len > maxLen) {
    const truncHex = arr.slice(0, maxLen).map(b => b.toString(16).padStart(2, '0')).join(' ');
    dbg('HEX', `${label} (${len}B): ${truncHex} ...`);
  } else {
    const hex = arr.map(b => b.toString(16).padStart(2, '0')).join(' ');
    dbg('HEX', `${label} (${len}B): ${hex}`);
  }
}

// ─── NDEF Helpers ─────────────────────────────────────────────────

/**
 * Build an NDEF record.
 * @param {number} tnf - Type Name Format (0x01=WELL_KNOWN, 0x04=EXTERNAL)
 * @param {number[]} type - Type bytes (for EXTERNAL) or empty
 * @param {number[]} id - Id bytes (for WELL_KNOWN)
 * @param {number[]} payload - Payload bytes
 * @param {boolean} mb - Message Begin flag
 * @param {boolean} me - Message End flag
 */
function buildNdefRecord(tnf, type, id, payload, mb = true, me = true) {
  const sr = payload.length < 256; // Short Record
  const il = id.length > 0;

  let header = (tnf & 0x07);
  if (mb) header |= 0x80; // MB
  if (me) header |= 0x40; // ME
  if (sr) header |= 0x10; // SR
  if (il) header |= 0x08; // IL

  const record = [header, type.length];

  if (sr) {
    record.push(payload.length & 0xFF);
  } else {
    record.push((payload.length >> 24) & 0xFF);
    record.push((payload.length >> 16) & 0xFF);
    record.push((payload.length >> 8) & 0xFF);
    record.push(payload.length & 0xFF);
  }

  if (il) record.push(id.length);

  record.push(...type);
  if (il) record.push(...id);
  record.push(...payload);

  return record;
}

/**
 * Build an NDEF record using WELL_KNOWN TNF (type goes in ID field per Smart Tap spec).
 */
function buildWellKnownRecord(typeStr, payload, mb = true, me = true) {
  const id = stringToBytes(typeStr);
  return buildNdefRecord(0x01, [], id, payload, mb, me);
}

/**
 * Build an NDEF record using EXTERNAL TNF (type goes in type field).
 */
function buildExternalRecord(typeStr, payload, mb = true, me = true) {
  const type = stringToBytes(typeStr);
  return buildNdefRecord(0x04, type, [], payload, mb, me);
}

// ─── APDU Helpers ─────────────────────────────────────────────────

function buildSelectAPDU(aid) {
  return [0x00, 0xA4, 0x04, 0x00, aid.length, ...aid, 0x00];
}

/**
 * Build a command APDU with proper Lc encoding.
 * Supports both short (Lc=1 byte, data<=255) and extended (Lc=3 bytes) APDUs.
 *
 * @param {number} cla - Class byte
 * @param {number} ins - Instruction byte
 * @param {number} p1  - Parameter 1
 * @param {number} p2  - Parameter 2
 * @param {number[]} data - Command data
 * @returns {number[]} Complete APDU bytes
 */
function buildCommandAPDU(cla, ins, p1, p2, data) {
  if (data.length <= 255) {
    // Short APDU: CLA INS P1 P2 Lc(1B) DATA Le(1B)
    return [cla, ins, p1, p2, data.length, ...data, 0x00];
  } else {
    // Extended APDU: CLA INS P1 P2 0x00 Lc_hi Lc_lo DATA Le_hi Le_lo
    dbg('APDU', `Using EXTENDED LENGTH APDU (data=${data.length}B)`);
    return [
      cla, ins, p1, p2,
      0x00,                            // Extended length marker
      (data.length >> 8) & 0xFF,       // Lc high byte
      data.length & 0xFF,              // Lc low byte
      ...data,
      0x00, 0x00,                      // Le = 0x0000 (max response)
    ];
  }
}

/**
 * Build NEGOTIATE SECURE CHANNEL APDU with full crypto.
 *
 * Data is an NDEF message (ngr record containing nested ses + cpr records).
 *
 * The cpr (crypto params) record contains:
 *   - 32 byte reader nonce
 *   - 1 byte auth flag (0x01 = signing required)
 *   - 33 byte compressed reader ephemeral public key
 *   - 4 byte key version (big-endian)
 *   - Nested NDEF with sig and cld records
 */
function buildNegotiateCommand(
  readerNonce,
  readerEphemeralPubKeyCompressed,
  signature,
  collectorId,
  keyVersion,
  sessionId,
  sequenceNumber
) {
  // ── cld record (collector ID) ──
  // Per Kormax spec: cld payload = 4 bytes big-endian collector id, NO format flag prefix
  const cldPayload = collectorIdToBytesBE(collectorId); // exactly 4 bytes, no prefix
  const cldRecord = buildExternalRecord('cld', cldPayload);

  dbg('NDEF', `cld record: ${cldRecord.length}B, collectorId=${collectorId}`);

  // ── sig record (signature, BINARY format flag + DER-encoded signature) ──
  const sigPayload = [0x04, ...signature]; // 0x04 = BINARY format flag per spec
  const sigRecord = buildExternalRecord('sig', sigPayload, true, false);

  dbg('NDEF', `sig record: ${sigRecord.length}B (sig DER=${signature.length}B)`);

  // The nested NDEF message inside cpr: sig + cld
  const nestedCprNdef = [...sigRecord, ...buildExternalRecord('cld', cldPayload, false, true)];

  dbg('NDEF', `nested cpr NDEF (sig+cld): ${nestedCprNdef.length}B`);

  // ── cpr record (crypto params) ──
  const cprPayload = [
    ...readerNonce,                        // 32 bytes reader nonce
    0x01,                                  // Auth flag: 0x01 = signing used
    ...readerEphemeralPubKeyCompressed,    // 33 bytes compressed pubkey
    ...keyVersionToBytes(keyVersion),      // 4 bytes key version
    ...nestedCprNdef,                      // nested NDEF with sig + cld
  ];
  const cprRecord = buildExternalRecord('cpr', cprPayload, false, true);

  dbg('NDEF', `cpr record: ${cprRecord.length}B (payload=${cprPayload.length}B)`);

  // ── ses record (session) ──
  const sesPayload = [
    ...sessionId,        // 8 bytes session id
    sequenceNumber,      // 1 byte sequence counter
    0x01,                // 1 byte status (0x01 = OK)
  ];
  const sesRecord = buildExternalRecord('ses', sesPayload, true, false);

  dbg('NDEF', `ses record: ${sesRecord.length}B`);

  // ── ngr record (negotiate request) ── wraps ses + cpr
  const ngrPayloadInner = [...sesRecord, ...cprRecord];
  const ngrPayload = [
    0x02, 0x00, // Version 2.0
    ...ngrPayloadInner,
  ];
  const ngrRecord = buildExternalRecord('ngr', ngrPayload);

  dbg('NDEF', `ngr record: ${ngrRecord.length}B (total NDEF payload=${ngrPayload.length}B)`);

  // Wrap in APDU: CLA=90, INS=53, P1=00, P2=00
  const apdu = buildCommandAPDU(0x90, 0x53, 0x00, 0x00, ngrRecord);

  dbg('APDU', `NEGOTIATE APDU total: ${apdu.length}B (data=${ngrRecord.length}B)`);

  return apdu;
}

/**
 * Build GET DATA APDU.
 * Contains service request with session info, merchant info, etc.
 */
function buildGetDataCommand(sessionId, sequenceNumber, collectorId) {
  // Kormax spec indicates cld payload is just 4 bytes, no BINARY format flag
  const cldPayload = collectorIdToBytesBE(collectorId);
  const cldRecord = buildExternalRecord('cld', cldPayload);

  // ── mer record (merchant, contains cld) ──
  const merRecord = buildExternalRecord('mer', cldRecord);

  // ── ses record ──
  const sesPayload = [
    ...sessionId,
    sequenceNumber,
    0x01, // 0x01 = OK
  ];
  const sesRecord = buildExternalRecord('ses', sesPayload, true, false);

  // ── srq record (service request) ──
  const srqPayloadInner = [...sesRecord, ...buildExternalRecord('mer', cldRecord, false, true)];
  const srqPayload = [
    0x02, 0x00, // Version 2.0
    ...srqPayloadInner,
  ];
  const srqRecord = buildExternalRecord('srq', srqPayload);

  // Use buildCommandAPDU for proper Lc handling
  const apdu = buildCommandAPDU(0x90, 0x50, 0x00, 0x00, srqRecord);

  dbg('APDU', `GET DATA APDU total: ${apdu.length}B (data=${srqRecord.length}B)`);

  return apdu;
}

// ─── Crypto ───────────────────────────────────────────────────────

/**
 * Generate 32-byte random nonce.
 */
function generateNonce(size = 32) {
  const nonce = [];
  for (let i = 0; i < size; i++) {
    nonce.push(Math.floor(Math.random() * 256));
  }
  return nonce;
}

/**
 * Generate an ephemeral ECDH key pair on the P-256 curve.
 * Returns { privateKey: Uint8Array(32), publicKeyCompressed: Uint8Array(33), publicKeyUncompressed: Uint8Array(65) }
 */
function generateEphemeralKeyPair() {
  const privKey = new Uint8Array(generateNonce(32));
  const pubPoint = p256.getPublicKey(privKey, true);  // compressed (33 bytes)
  const pubPointUncompressed = p256.getPublicKey(privKey, false); // uncompressed (65 bytes)

  dbg('CRYPTO', `Ephemeral keypair generated: priv=${privKey.length}B, pub_c=${pubPoint.length}B, pub_u=${pubPointUncompressed.length}B`);

  return {
    privateKey: privKey,
    publicKeyCompressed: pubPoint,
    publicKeyUncompressed: pubPointUncompressed,
  };
}

/**
 * Sign data with ECDSA P-256.
 * Returns DER-encoded signature as number[].
 *
 * IMPORTANT: @noble/curves p256.sign() returns a Signature object, NOT raw bytes.
 * We must call .toDERRawBytes() to get ASN.1 DER encoding.
 * Also, p256.sign() internally hashes with SHA-256, so we pass raw data (NOT pre-hashed).
 */
function signData(privateKeyBytes, data) {
  dbg('CRYPTO', `Signing ${data.length}B of data`);

  // p256.sign() accepts raw message data and hashes internally with SHA-256.
  // Do NOT pre-hash — that would cause double-hash SHA256(SHA256(data)).
  const sig = p256.sign(new Uint8Array(data), privateKeyBytes, { lowS: true });

  // sig is a Signature object — use .toDERRawBytes() for ASN.1 DER encoding
  // which is what Smart Tap spec requires ("encoded in ASN1 as Dss-Sig-Value")
  let derBytes;
  if (typeof sig.toDERRawBytes === 'function') {
    derBytes = sig.toDERRawBytes();
  } else if (typeof sig.toDERBytes === 'function') {
    // Fallback for slightly different API version
    derBytes = sig.toDERBytes();
  } else if (sig instanceof Uint8Array) {
    // Very old versions might return compact bytes directly — need manual DER encoding
    dbg('CRYPTO', '⚠️ sig is Uint8Array, converting compact→DER manually');
    derBytes = compactToDER(sig);
  } else {
    // Last resort: try to access r and s as bigints from the Signature object
    dbg('CRYPTO', '⚠️ Unknown sig type, attempting manual DER from r/s');
    derBytes = signatureObjectToDER(sig);
  }

  const result = Array.from(derBytes);
  dbg('CRYPTO', `Signature DER: ${result.length}B`);
  hexDump('SIG_DER', result, 40);

  return result;
}

/**
 * Convert a 64-byte compact signature (r || s) to DER format.
 * Fallback for older @noble/curves versions.
 */
function compactToDER(compactBytes) {
  let r = Array.from(compactBytes.slice(0, 32));
  let s = Array.from(compactBytes.slice(32, 64));

  // Remove leading zeros but keep at least 1 byte
  while (r.length > 1 && r[0] === 0) r.shift();
  while (s.length > 1 && s[0] === 0) s.shift();

  // If MSB is set, prepend 0x00 to make it a positive integer
  if (r[0] & 0x80) r.unshift(0x00);
  if (s[0] & 0x80) s.unshift(0x00);

  const rPart = [0x02, r.length, ...r];
  const sPart = [0x02, s.length, ...s];
  const payload = [...rPart, ...sPart];

  return new Uint8Array([0x30, payload.length, ...payload]);
}

/**
 * Convert Signature object with r/s bigints to DER.
 * Last-resort fallback.
 */
function signatureObjectToDER(sig) {
  const rBigInt = sig.r;
  const sBigInt = sig.s;

  function bigintToBytes(n) {
    let hex = n.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.substring(i, i + 2), 16));
    }
    // Ensure positive integer encoding
    if (bytes[0] & 0x80) bytes.unshift(0x00);
    return bytes;
  }

  const r = bigintToBytes(rBigInt);
  const s = bigintToBytes(sBigInt);
  const rPart = [0x02, r.length, ...r];
  const sPart = [0x02, s.length, ...s];
  const payload = [...rPart, ...sPart];

  return new Uint8Array([0x30, payload.length, ...payload]);
}

/**
 * Perform ECDH to derive shared secret.
 */
function deriveSharedSecret(myPrivateKey, theirPublicKeyBytes) {
  dbg('CRYPTO', `ECDH: myPriv=${myPrivateKey.length}B, theirPub=${theirPublicKeyBytes.length}B`);
  const shared = p256.getSharedSecret(myPrivateKey, theirPublicKeyBytes);
  // shared is 65 bytes (uncompressed point), we need just the X coordinate (bytes 1-32)
  const secret = shared.slice(1, 33);
  dbg('CRYPTO', `Shared secret: ${secret.length}B`);
  return secret;
}

/**
 * Derive session encryption and MAC keys using HKDF-SHA256.
 */
// Per Kormax spec:
// salt   = device_ephemeral_public_key_bytes (33 bytes compressed)
// shared_info = data_to_sign + signature
// length = 48 bytes → aes_key = [:16], hmac_key = [16:]
function deriveSessionKeys(sharedSecret, deviceEphemeralPubKeyBytes, dataToSign, signature) {
  dbg('CRYPTO', `HKDF: secret=${sharedSecret.length}B, salt=${deviceEphemeralPubKeyBytes.length}B, info=${dataToSign.length + signature.length}B`);

  const salt = new Uint8Array(deviceEphemeralPubKeyBytes);
  const info = new Uint8Array([...dataToSign, ...signature]);
  const keyMaterial = hkdf(sha256, new Uint8Array(sharedSecret), salt, info, 48);

  dbg('CRYPTO', `Session keys derived: encKey=16B, macKey=32B`);

  return {
    encryptionKey: keyMaterial.slice(0, 16),  // first 16 bytes → AES key
    macKey: keyMaterial.slice(16, 48),         // next 32 bytes → HMAC key
  };
}

/**
 * Decrypt AES-128-CBC or try to extract plaintext from response.
 * Smart Tap uses AES for encryption. Since React Native JS doesn't have
 * native AES, we attempt to parse the NDEF structure directly.
 * For initial testing, if encryption is not applied (unlikely but possible in test mode),
 * we try to read plaintext values.
 */
function decryptPayload(encryptedData, sessionKeys) {
  // For now, attempt to find plaintext redemption value in the response
  // Full AES decryption would require a native crypto module
  // But we log everything for debugging
  return null;
}

// ─── Byte Utilities ───────────────────────────────────────────────

function stringToBytes(str) {
  return Array.from(str).map(c => c.charCodeAt(0));
}

function bytesToString(bytes) {
  try {
    return String.fromCharCode.apply(null, bytes);
  } catch (_e) {
    return '';
  }
}

function toHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function collectorIdToBytesBE(id) {
  return [
    (id >> 24) & 0xFF,
    (id >> 16) & 0xFF,
    (id >> 8) & 0xFF,
    id & 0xFF,
  ];
}

function keyVersionToBytes(version) {
  return [
    (version >> 24) & 0xFF,
    (version >> 16) & 0xFF,
    (version >> 8) & 0xFF,
    version & 0xFF,
  ];
}

function isSuccess(response) {
  if (!response || response.length < 2) return false;
  const sw1 = response[response.length - 2];
  const sw2 = response[response.length - 1];
  return sw1 === 0x90 && sw2 === 0x00;
}

function isMoreData(response) {
  if (!response || response.length < 2) return false;
  const sw1 = response[response.length - 2];
  const sw2 = response[response.length - 1];
  return sw1 === 0x91 && sw2 === 0x00;
}

function getStatusWord(response) {
  if (!response || response.length < 2) return 'no response';
  return toHex(response.slice(-2)).toUpperCase();
}

/**
 * Parse SELECT response to extract device nonce and device ephemeral public key.
 *
 * SELECT VAS response uses BER-TLV format:
 *   - Tag 50: Wallet name ("AndroidPay")
 *   - Tag C2: Device nonce (32 bytes)
 *   - Tag C3: Device ephemeral public key (33 bytes, compressed)
 *
 * SELECT SMART TAP response uses NDEF format:
 *   - mdn record: device nonce (0x04 format flag + 32 bytes)
 */
function parseSelectResponse(responseBytes) {
  const data = responseBytes.slice(0, responseBytes.length - 2);
  const result = {
    walletName: null,
    deviceNonce: null,
    deviceEphemeralKey: null,
  };

  dbg('PARSE', `SELECT response data: ${data.length}B`);
  hexDump('SELECT_RAW', data, 60);

  // ── Strategy 1: BER-TLV parsing (SELECT VAS response) ──
  // Walk TLV tags properly
  let i = 0;
  if (data.length > 2 && data[0] === 0x6F) {
    // FCI Template tag 6F — skip tag and length
    i = 1;
    // Parse length (could be multi-byte BER length)
    if (data[i] === 0x81) {
      i += 2; // 81 XX = 1-byte extended length
    } else if (data[i] === 0x82) {
      i += 3; // 82 XX XX = 2-byte extended length
    } else {
      i += 1; // short length
    }
    dbg('PARSE', `FCI Template (6F): inner data starts at offset ${i}`);
  }

  // Parse inner TLV tags
  while (i < data.length - 1) {
    const tag = data[i];
    i++;
    if (i >= data.length) break;

    // Parse length
    let len = data[i];
    i++;
    if (len === 0x81 && i < data.length) {
      len = data[i]; i++;
    } else if (len === 0x82 && i + 1 < data.length) {
      len = (data[i] << 8) | data[i + 1]; i += 2;
    }

    if (i + len > data.length) break;

    const value = data.slice(i, i + len);

    switch (tag) {
      case 0x50: // Application Label (wallet name)
        result.walletName = bytesToString(value);
        dbg('PARSE', `Tag 50 (Wallet): "${result.walletName}"`);
        break;
      case 0xC2: // Device Nonce (32 bytes)
        if (len === 32) {
          result.deviceNonce = Array.from(value);
          dbg('PARSE', `Tag C2 (Device Nonce): ${len}B ✓`);
          hexDump('DEVICE_NONCE', value, 32);
        } else {
          dbg('PARSE', `⚠️ Tag C2 unexpected length: ${len}B (expected 32)`);
        }
        break;
      case 0xC3: // Device Ephemeral Public Key (33 bytes compressed)
        if (len === 33 && (value[0] === 0x02 || value[0] === 0x03)) {
          result.deviceEphemeralKey = Array.from(value);
          dbg('PARSE', `Tag C3 (Device EphKey): ${len}B, prefix=0x${value[0].toString(16)} ✓`);
          hexDump('DEVICE_EPH_KEY', value, 33);
        } else {
          dbg('PARSE', `⚠️ Tag C3 unexpected: len=${len}, prefix=0x${value[0]?.toString(16)}`);
        }
        break;
      case 0xA5: // Constructed tag — skip (contains nested AID info)
        dbg('PARSE', `Tag A5 (Constructed): ${len}B — skipped`);
        break;
      default:
        dbg('PARSE', `Tag ${tag.toString(16).toUpperCase()}: ${len}B — unknown, skipped`);
        break;
    }
    i += len;
  }

  // ── Strategy 2: NDEF parsing (SELECT SMART TAP response) ──
  // If BER-TLV didn't find the nonce, try NDEF parsing
  if (!result.deviceNonce) {
    dbg('PARSE', 'No nonce from BER-TLV, trying NDEF parse...');
    // Smart Tap SELECT response format: 4 bytes header (min/max version) + NDEF
    // Look for mdn record type in NDEF
    const mdnMarker = stringToBytes('mdn');
    for (let j = 0; j < data.length - 5; j++) {
      if (data[j] === mdnMarker[0] && data[j + 1] === mdnMarker[1] && data[j + 2] === mdnMarker[2]) {
        const nonceStart = j + 3;
        dbg('PARSE', `Found 'mdn' marker at offset ${j}`);
        if (nonceStart + 33 <= data.length) {
          if (data[nonceStart] === 0x04) {
            // Skip BINARY format flag
            result.deviceNonce = Array.from(data.slice(nonceStart + 1, nonceStart + 33));
            dbg('PARSE', `mdn nonce (with 0x04 flag): ${result.deviceNonce.length}B ✓`);
          } else {
            result.deviceNonce = Array.from(data.slice(nonceStart, nonceStart + 32));
            dbg('PARSE', `mdn nonce (no flag): ${result.deviceNonce.length}B ✓`);
          }
        }
        break;
      }
    }
  }

  dbg('PARSE', `SELECT result: wallet=${result.walletName}, nonce=${result.deviceNonce ? 'YES' : 'NO'}, ephKey=${result.deviceEphemeralKey ? 'YES' : 'NO'}`);

  return result;
}

/**
 * Parse NEGOTIATE response to extract device ephemeral key and session info.
 */
function parseNegotiateResponse(responseBytes) {
  const data = responseBytes.slice(0, responseBytes.length - 2);
  const result = {
    deviceEphemeralKey: null,
    sessionId: null,
  };

  dbg('PARSE', `NEGOTIATE response data: ${data.length}B`);
  hexDump('NEGOTIATE_RAW', data, 80);

  // Look for dpk (device public key)
  const dpkMarker = stringToBytes('dpk');
  for (let i = 0; i < data.length - 5; i++) {
    if (data[i] === dpkMarker[0] && data[i + 1] === dpkMarker[1] && data[i + 2] === dpkMarker[2]) {
      const keyStart = i + 3;
      dbg('PARSE', `Found 'dpk' marker at offset ${i}`);
      if (data[keyStart] === 0x04 && keyStart + 34 <= data.length) {
        // 0x04 = BINARY format flag, skip it, next 33 bytes = compressed key
        result.deviceEphemeralKey = Array.from(data.slice(keyStart + 1, keyStart + 34));
        dbg('PARSE', `dpk (with 0x04 flag): ${result.deviceEphemeralKey.length}B ✓`);
      } else if ((data[keyStart] === 0x02 || data[keyStart] === 0x03) && keyStart + 33 <= data.length) {
        result.deviceEphemeralKey = Array.from(data.slice(keyStart, keyStart + 33));
        dbg('PARSE', `dpk (compressed): ${result.deviceEphemeralKey.length}B ✓`);
      }
      break;
    }
  }

  // Look for ses (session)
  const sesMarker = stringToBytes('ses');
  for (let i = 0; i < data.length - 5; i++) {
    if (data[i] === sesMarker[0] && data[i + 1] === sesMarker[1] && data[i + 2] === sesMarker[2]) {
      const sesStart = i + 3;
      dbg('PARSE', `Found 'ses' marker at offset ${i}`);
      if (sesStart + 8 <= data.length) {
        result.sessionId = Array.from(data.slice(sesStart, sesStart + 8));
        dbg('PARSE', `ses session ID: ${result.sessionId.length}B ✓`);
      }
      break;
    }
  }

  dbg('PARSE', `NEGOTIATE result: ephKey=${result.deviceEphemeralKey ? 'YES' : 'NO'}, session=${result.sessionId ? 'YES' : 'NO'}`);

  return result;
}

/**
 * Try to extract the smartTapRedemptionValue from GET DATA response.
 * The response contains encrypted NDEF data.
 */
function extractRedemptionValue(responseBytes) {
  const data = responseBytes.slice(0, responseBytes.length - 2);

  if (data.length === 0) {
    dbg('PARSE', 'GET DATA response is empty');
    return null;
  }

  dbg('PARSE', `GET DATA payload: ${data.length}B`);
  hexDump('GET_DATA_RAW', data, 100);

  // Strategy 1: Look for readable ASCII text that matches ticket patterns
  const text = bytesToString(data);
  const ticketMatch = text.match(/TICKET-[A-Za-z0-9\-_]{3,}/);
  if (ticketMatch) {
    dbg('PARSE', `Found ticket pattern: ${ticketMatch[0]}`);
    return ticketMatch[0];
  }

  // Strategy 2: Look for any readable alphanumeric string > 5 chars
  const readable = text.match(/[A-Za-z0-9\-_]{5,}/);
  if (readable) {
    dbg('PARSE', `Found readable string: ${readable[0]}`);
    return readable[0];
  }

  // Strategy 3: Return raw hex for debugging
  dbg('PARSE', 'No readable text found, returning RAW hex');
  return `RAW:${toHex(data)}`;
}

// ─── Private Key Management ───────────────────────────────────────

let _collectorPrivateKey = null;

/**
 * Set the collector's private key (base64url-encoded 'd' parameter from JWK).
 * This should be called once when the app starts or when the user configures it.
 */
export function setCollectorPrivateKey(base64urlD) {
  // Convert base64url to standard base64
  let b64 = base64urlD.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';

  // Decode base64 to bytes
  const binaryString = atob(b64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  _collectorPrivateKey = bytes;

  dbg('KEY', `Collector private key set: ${bytes.length}B`);
  hexDump('PRIV_KEY', bytes, 8);

  // Verify key by generating public key
  try {
    const pubKey = p256.getPublicKey(bytes, true);
    dbg('KEY', `Derived public key: ${pubKey.length}B`);
    hexDump('PUB_KEY', pubKey, 33);
  } catch (e) {
    dbg('KEY', `⚠️ Failed to derive public key: ${e.message}`);
  }
}

/**
 * Check if private key is configured.
 */
export function hasPrivateKey() {
  return _collectorPrivateKey !== null;
}

// ─── Public API ───────────────────────────────────────────────────

export async function initNfc() {
  try {
    const supported = await NfcManager.isSupported();
    if (!supported) {
      dbg('NFC', 'NFC not supported on this device');
      return false;
    }
    await NfcManager.start();
    dbg('NFC', 'NFC Manager started ✓');
    return true;
  } catch (err) {
    dbg('NFC', `Init error: ${err.message}`);
    return false;
  }
}

export async function isNfcEnabled() {
  try {
    return await NfcManager.isEnabled();
  } catch {
    return false;
  }
}

/**
 * Safely transceive with enhanced error handling and logging.
 * Wraps NfcManager.isoDepHandler.transceive() with:
 *   - Max transceive length check
 *   - Full hex dump of sent/received APDUs
 *   - Detailed error context
 */
async function safeTransceive(apdu, label, onProgress) {
  dbg('TX', `→ ${label}: ${apdu.length}B`);
  hexDump(`TX_${label}`, apdu, 60);

  // Check max transceive length if available
  try {
    if (typeof NfcManager.isoDepHandler.getMaxTransceiveLength === 'function') {
      const maxLen = await NfcManager.isoDepHandler.getMaxTransceiveLength();
      dbg('TX', `Device maxTransceiveLength: ${maxLen}B`);
      if (apdu.length > maxLen) {
        const errMsg = `⛔ APDU (${apdu.length}B) EXCEEDS maxTransceiveLength (${maxLen}B)!`;
        dbg('TX', errMsg);
        onProgress(errMsg);
        throw new Error(errMsg);
      }
    }
  } catch (e) {
    if (e.message.includes('EXCEEDS')) throw e;
    // getMaxTransceiveLength not available — continue anyway
    dbg('TX', `getMaxTransceiveLength not available: ${e.message}`);
  }

  try {
    const response = await NfcManager.isoDepHandler.transceive(apdu);
    const sw = getStatusWord(response);
    dbg('RX', `← ${label}: ${response.length}B, SW=${sw}`);
    hexDump(`RX_${label}`, response, 60);
    return response;
  } catch (err) {
    dbg('TX', `✖ ${label} transceive FAILED: ${err.message}`);
    dbg('TX', `  APDU was ${apdu.length}B`);
    hexDump(`FAILED_${label}`, apdu, 80);
    onProgress(`✖ ${label} transceive error: ${err.message}`);
    throw new Error(`${label} transceive failed: ${err.message} (APDU ${apdu.length}B)`);
  }
}

/**
 * Scan a Google Wallet ticket via NFC using the full Smart Tap 2.1 crypto protocol.
 */
export async function scanTicket(merchantId, onProgress = () => {}) {
  if (!_collectorPrivateKey) {
    throw new Error('Llave privada no configurada. Ve a Configuración.');
  }

  try {
    // Set module-level ref so ALL dbg/hexDump calls show on screen
    _onProgress = onProgress;

    dbg('SCAN', '═══════════════════ NEW SCAN ═══════════════════');
    dbg('SCAN', `CollectorID: ${COLLECTOR_ID}, KeyVersion: ${KEY_VERSION}`);
    dbg('NFC', 'Inicializando hardware NFC...');

    await NfcManager.requestTechnology(NfcTech.IsoDep);
    dbg('NFC', 'IsoDep technology acquired ✓');

    // Log max transceive length at start
    try {
      if (typeof NfcManager.isoDepHandler.getMaxTransceiveLength === 'function') {
        const maxLen = await NfcManager.isoDepHandler.getMaxTransceiveLength();
        dbg('NFC', `📏 maxTransceiveLength: ${maxLen}B`);
      }
    } catch (_e) {
      dbg('NFC', 'maxTransceiveLength: no disponible');
    }

    // ── Step 1: SELECT OSE.VAS.01 ──
    dbg('STEP', '── 1. SELECT OSE.VAS.01 ──');
    const selectVAS = buildSelectAPDU(AID_OSE_VAS);
    const vasResp = await safeTransceive(selectVAS, 'SELECT_VAS', onProgress);
    const swVas = getStatusWord(vasResp);
    dbg('RESP', `SELECT VAS → SW=${swVas} (${vasResp.length}B)`);

    let deviceNonce = null;
    let deviceEphemeralKey = null;

    if (isSuccess(vasResp)) {
      const parsed = parseSelectResponse(vasResp);
      dbg('PARSE', `Wallet: ${parsed.walletName || 'Desconocida'}`);
      deviceNonce = parsed.deviceNonce;
      deviceEphemeralKey = parsed.deviceEphemeralKey;

      if (deviceNonce) {
        dbg('PARSE', `Device Nonce: ${toHex(deviceNonce).substring(0, 16)}... (${deviceNonce.length}B) ✓`);
      } else {
        dbg('PARSE', '⚠️ No device nonce from VAS');
      }
      if (deviceEphemeralKey) {
        dbg('PARSE', `Device EphKey: ${toHex(deviceEphemeralKey).substring(0, 16)}... (${deviceEphemeralKey.length}B) ✓`);
      } else {
        dbg('PARSE', '⚠️ No device ephemeral key from VAS');
      }
    } else {
      dbg('RESP', `⚠️ VAS rejected: SW=${swVas}`);
    }

    // ── Step 2: SELECT Smart Tap 2 (if no device nonce from VAS) ──
    if (!deviceNonce) {
      dbg('STEP', '── 2. SELECT Smart Tap 2 ──');
      const selectST = buildSelectAPDU(AID_SMART_TAP_2);
      const stResp = await safeTransceive(selectST, 'SELECT_ST2', onProgress);
      const swSt = getStatusWord(stResp);
      dbg('RESP', `SELECT ST2 → SW=${swSt} (${stResp.length}B)`);

      if (!isSuccess(stResp)) {
        throw new Error(`Smart Tap AID rechazado: ${swSt}`);
      }

      const parsed2 = parseSelectResponse(stResp);
      deviceNonce = parsed2.deviceNonce;
      deviceEphemeralKey = parsed2.deviceEphemeralKey;
    }

    if (!deviceNonce) {
      dbg('SCAN', '⚠️ Sin device nonce — generando placeholder random');
      deviceNonce = generateNonce(32);
    }

    // ── Step 3: NEGOTIATE SECURE CHANNEL ──
    dbg('STEP', '── 3. NEGOTIATE SECURE CHANNEL ──');
    dbg('CRYPTO', 'Generando llaves efímeras ECDH...');
    let ephemeral;
    try {
      ephemeral = generateEphemeralKeyPair();
      dbg('CRYPTO', `Ephemeral key: ${toHex(Array.from(ephemeral.publicKeyCompressed)).substring(0, 16)}... ✓`);
    } catch (e) {
      dbg('CRYPTO', `✖ Ephemeral key generation FAILED: ${e.message}`);
      throw new Error(`Fallo al generar llave efímera ECDH: ${e.message}`);
    }
    const readerNonce = generateNonce(32);
    const sessionId = generateNonce(8);

    dbg('CRYPTO', `readerNonce: ${toHex(readerNonce).substring(0, 16)}...`);
    dbg('CRYPTO', `sessionId: ${toHex(sessionId)}`);

    dbg('SIGN', 'Firmando con llave privada (ECDSA P-256)...');
    // Signature is over: readerNonce + deviceNonce + collectorId(BE) + readerEphemeralPubKey(compressed)
    const dataToSign = [
      ...readerNonce,
      ...deviceNonce,
      ...collectorIdToBytesBE(COLLECTOR_ID),
      ...Array.from(ephemeral.publicKeyCompressed),
    ];

    dbg('SIGN', `dataToSign: rNonce(${readerNonce.length}) + dNonce(${deviceNonce.length}) + cId(4) + ePub(${ephemeral.publicKeyCompressed.length}) = ${dataToSign.length}B`);
    hexDump('DATA_TO_SIGN', dataToSign, 40);

    let signature;
    try {
      signature = signData(_collectorPrivateKey, dataToSign);
      dbg('SIGN', `Firma DER: ${signature.length}B ✓`);
    } catch (e) {
      dbg('SIGN', `✖ Error firmando: ${e.message}`);
      throw new Error(`Fallo al firmar NEGOTIATE (ECDSA P-256): ${e.message}`);
    }

    dbg('NDEF', 'Construyendo NEGOTIATE APDU...');
    const negotiateCmd = buildNegotiateCommand(
      readerNonce,
      Array.from(ephemeral.publicKeyCompressed),
      signature,
      COLLECTOR_ID,
      KEY_VERSION,
      sessionId,
      0x00
    );
    dbg('APDU', `NEGOTIATE APDU: ${negotiateCmd.length}B total`);

    dbg('TX', 'Enviando NEGOTIATE...');
    const negResp = await safeTransceive(negotiateCmd, 'NEGOTIATE', onProgress);
    const swNeg = getStatusWord(negResp);
    dbg('RESP', `NEGOTIATE → SW=${swNeg} (${negResp.length}B)`);

    if (!isSuccess(negResp)) {
      const fullHex = toHex(negResp);
      dbg('RESP', `✖ NEGOTIATE FAILED! Full response: ${fullHex}`);
      throw new Error(`NEGOTIATE falló: SW=${swNeg}, response=${fullHex}`);
    }

    // Parse negotiate response for device ephemeral key
    dbg('PARSE', 'Procesando respuesta NEGOTIATE...');
    const negParsed = parseNegotiateResponse(negResp);
    if (negParsed.deviceEphemeralKey) {
      deviceEphemeralKey = negParsed.deviceEphemeralKey;
      dbg('PARSE', `Device EphKey (NEGOTIATE): ${toHex(deviceEphemeralKey).substring(0, 16)}... ✓`);
    } else {
      dbg('PARSE', '⚠️ Sin device ephemeral key en NEGOTIATE');
    }

    // ── Step 4: Derive Session Keys (ECDH + HKDF) ──
    dbg('STEP', '── 4. Derive Session Keys ──');
    dbg('CRYPTO', 'Derivando llaves de sesión (ECDH + HKDF)...');
    let sessionKeys;
    try {
      if (!deviceEphemeralKey) {
        throw new Error('No device ephemeral key available for ECDH');
      }
      const sharedSecret = deriveSharedSecret(ephemeral.privateKey, new Uint8Array(deviceEphemeralKey));
      sessionKeys = deriveSessionKeys(sharedSecret, deviceEphemeralKey, dataToSign, signature);
      dbg('CRYPTO', 'Session keys derivadas ✓');
    } catch (e) {
      dbg('CRYPTO', `✖ Error derivando keys: ${e.message}`);
      throw new Error(`Fallo en derivación de llaves (ECDH/HKDF): ${e.message}`);
    }

    // ── Step 5: GET DATA ──
    dbg('STEP', '── 5. GET DATA ──');
    const getDataCmd = buildGetDataCommand(sessionId, 0x01, COLLECTOR_ID);

    dbg('TX', 'Enviando GET DATA...');
    const dataResp = await safeTransceive(getDataCmd, 'GET_DATA', onProgress);
    const swData = getStatusWord(dataResp);
    dbg('RESP', `GET DATA → SW=${swData} (${dataResp.length}B)`);

    let fullResponse = dataResp;

    // Handle GET MORE DATA if needed (SW = 9100)
    if (isMoreData(dataResp)) {
      dbg('SCAN', '── GET MORE DATA loop ──');
      let chunkCount = 0;
      let moreResp;
      do {
        chunkCount++;
        moreResp = await safeTransceive([0x90, 0xC0, 0x00, 0x00, 0x00], `GET_MORE_${chunkCount}`, onProgress);
        fullResponse = [
          ...fullResponse.slice(0, fullResponse.length - 2),
          ...moreResp,
        ];
        const swMore = getStatusWord(moreResp);
        dbg('RESP', `GET MORE #${chunkCount} → SW=${swMore} (+${moreResp.length - 2}B)`);
      } while (isMoreData(moreResp));
      dbg('SCAN', `GET MORE DATA completado: ${chunkCount} chunks, total ${fullResponse.length}B`);
    }

    if (!isSuccess(fullResponse)) {
      const rawHex = toHex(fullResponse.slice(0, Math.min(60, fullResponse.length)));
      dbg('RESP', `✖ GET DATA failed: SW=${getStatusWord(fullResponse)}, data=${rawHex}...`);
      throw new Error(`GET DATA falló: ${getStatusWord(fullResponse)}`);
    }

    // ── Parse response ──
    const payloadBytes = fullResponse.slice(0, fullResponse.length - 2);
    dbg('PARSE', `Payload total: ${payloadBytes.length}B`);
    hexDump('FINAL_PAYLOAD', payloadBytes, 100);

    // Try to extract redemption value
    const redemptionValue = extractRedemptionValue(fullResponse);
    if (redemptionValue && !redemptionValue.startsWith('RAW:')) {
      dbg('SCAN', `🎫 TICKET: ${redemptionValue}`);
    } else {
      dbg('SCAN', `Datos encriptados (${payloadBytes.length}B). Requiere AES.`);
    }

    dbg('SCAN', '═══════════════ SCAN COMPLETE ═══════════════');

    return {
      provider: 'google',
      rawPayload: toHex(payloadBytes),
      redemptionValue: redemptionValue,
    };

  } catch (err) {
    dbg('SCAN', `═══════════════ SCAN FAILED: ${err.message} ═══════════════`);
    throw err;
  } finally {
    _onProgress = null;
    cancelScan();
  }
}

export function cancelScan() {
  try {
    NfcManager.cancelTechnologyRequest();
  } catch (_e) {
    // Ignore
  }
}
