/**
 * @quxtech/pqc-crypto - VoIP Security Module
 * ============================================================================
 * Post-Quantum secure VoIP communications.
 *
 * Features:
 * - PQC key exchange for call establishment (ML-KEM)
 * - Call authentication with digital signatures (ML-DSA)
 * - SRTP-compatible key derivation
 * - Voice frame encryption with AES-256-GCM
 * - Replay protection with sequence numbers and rollover counter
 * ============================================================================
 */
import { gcm } from '@noble/ciphers/aes';
import { sha3_256 } from '@noble/hashes/sha3';
import { hkdf } from '@noble/hashes/hkdf';
import { bytesToHex, hexToBytes, utf8ToBytes, randomBytes } from '@noble/hashes/utils';
import * as kem from './kem.js';
import * as dsa from './dsa.js';
// =============================================================================
// CONSTANTS
// =============================================================================
const SRTP_ENCRYPTION_LABEL = 'SRTP encryption';
const SRTP_AUTH_LABEL = 'SRTP authentication';
const SRTP_SALT_LABEL = 'SRTP salt';
// Maximum sequence number before rollover
const MAX_SEQUENCE_NUMBER = 65535;
// Default frame size (20ms of Opus at 48kHz)
const DEFAULT_FRAME_SIZE = 960;
// =============================================================================
// SESSION STORAGE
// =============================================================================
// Active VoIP sessions
const activeSessions = new Map();
// Session statistics
const sessionStats = new Map();
// =============================================================================
// KEY GENERATION
// =============================================================================
/**
 * Generate VoIP key pair (KEM for key exchange + DSA for signing)
 * @param securityLevel - NIST security level
 * @returns VoIP key pair
 */
export function generateKeyPair(securityLevel = '5') {
    const kemKeys = kem.generateKeyPairHex(securityLevel);
    const dsaKeys = dsa.generateKeyPairHex(securityLevel);
    return {
        kem: kemKeys,
        dsa: dsaKeys,
        securityLevel,
    };
}
/**
 * Generate a unique call ID
 * @returns Random call ID (32 hex characters)
 */
export function generateCallId() {
    return bytesToHex(randomBytes(16));
}
/**
 * Generate a random SSRC (Synchronization Source identifier)
 * @returns 32-bit SSRC value
 */
export function generateSSRC() {
    const bytes = randomBytes(4);
    return new DataView(bytes.buffer).getUint32(0, false);
}
// =============================================================================
// CALL ESTABLISHMENT
// =============================================================================
/**
 * Create a call request (caller initiates)
 * @param callerKeys - Caller's VoIP key pair
 * @param codec - Optional codec preference
 * @param metadata - Optional call metadata
 * @returns Call request to send to callee
 */
export function createCallRequest(callerKeys, codec, metadata) {
    const callId = generateCallId();
    const timestamp = Date.now();
    // Data to sign (without signature field)
    const signatureData = JSON.stringify({
        callId,
        callerKemPublicKey: callerKeys.kem.publicKey,
        callerDsaPublicKey: callerKeys.dsa.publicKey,
        timestamp,
        codec,
    });
    const signature = dsa.sign(signatureData, callerKeys.dsa.secretKey, callerKeys.securityLevel);
    return {
        callId,
        callerKemPublicKey: callerKeys.kem.publicKey,
        callerDsaPublicKey: callerKeys.dsa.publicKey,
        timestamp,
        signature,
        codec,
        metadata,
    };
}
/**
 * Verify a call request signature
 * @param request - Call request to verify
 * @param securityLevel - NIST security level
 * @returns True if signature is valid
 */
export function verifyCallRequest(request, securityLevel = '5') {
    const signatureData = JSON.stringify({
        callId: request.callId,
        callerKemPublicKey: request.callerKemPublicKey,
        callerDsaPublicKey: request.callerDsaPublicKey,
        timestamp: request.timestamp,
        codec: request.codec,
    });
    return dsa.verify(signatureData, request.signature, request.callerDsaPublicKey, securityLevel);
}
/**
 * Accept a call (callee responds)
 * @param request - Incoming call request
 * @param calleeKeys - Callee's VoIP key pair
 * @returns Call response and established session
 */
export function acceptCall(request, calleeKeys) {
    // Verify the incoming request
    if (!verifyCallRequest(request, calleeKeys.securityLevel)) {
        throw new Error('Invalid call request signature');
    }
    // Encapsulate shared secret to caller's public key
    const { ciphertext, sharedSecret } = kem.encapsulate(request.callerKemPublicKey, calleeKeys.securityLevel);
    const timestamp = Date.now();
    // Sign the response
    const signatureData = JSON.stringify({
        callId: request.callId,
        ciphertext,
        calleeDsaPublicKey: calleeKeys.dsa.publicKey,
        timestamp,
        codec: request.codec,
    });
    const signature = dsa.sign(signatureData, calleeKeys.dsa.secretKey, calleeKeys.securityLevel);
    const response = {
        callId: request.callId,
        ciphertext,
        calleeDsaPublicKey: calleeKeys.dsa.publicKey,
        timestamp,
        signature,
        codec: request.codec,
    };
    // Derive SRTP keys
    const srtpKeys = deriveSRTPKeys(sharedSecret);
    // Create session
    const session = {
        callId: request.callId,
        role: 'callee',
        state: 'connected',
        sharedSecret,
        srtpKeys,
        localDsaPublicKey: calleeKeys.dsa.publicKey,
        remoteDsaPublicKey: request.callerDsaPublicKey,
        establishedAt: timestamp,
        sequenceNumber: 0,
        rolloverCounter: 0,
        ssrc: generateSSRC(),
        codec: request.codec,
    };
    // Store session
    activeSessions.set(request.callId, session);
    initSessionStats(request.callId);
    return { response, session };
}
/**
 * Complete call establishment (caller processes response)
 * @param request - Original call request
 * @param response - Call response from callee
 * @param callerKeys - Caller's VoIP key pair
 * @returns Established session
 */
export function completeCall(request, response, callerKeys) {
    // Verify the response signature
    const signatureData = JSON.stringify({
        callId: response.callId,
        ciphertext: response.ciphertext,
        calleeDsaPublicKey: response.calleeDsaPublicKey,
        timestamp: response.timestamp,
        codec: response.codec,
    });
    const valid = dsa.verify(signatureData, response.signature, response.calleeDsaPublicKey, callerKeys.securityLevel);
    if (!valid) {
        throw new Error('Invalid call response signature');
    }
    // Decapsulate to recover shared secret
    const sharedSecret = kem.decapsulate(response.ciphertext, callerKeys.kem.secretKey, callerKeys.securityLevel);
    // Derive SRTP keys
    const srtpKeys = deriveSRTPKeys(sharedSecret);
    // Create session
    const session = {
        callId: response.callId,
        role: 'caller',
        state: 'connected',
        sharedSecret,
        srtpKeys,
        localDsaPublicKey: callerKeys.dsa.publicKey,
        remoteDsaPublicKey: response.calleeDsaPublicKey,
        establishedAt: Date.now(),
        sequenceNumber: 0,
        rolloverCounter: 0,
        ssrc: generateSSRC(),
        codec: response.codec,
    };
    // Store session
    activeSessions.set(response.callId, session);
    initSessionStats(response.callId);
    return session;
}
// =============================================================================
// KEY DERIVATION
// =============================================================================
/**
 * Derive SRTP keys from shared secret
 * @param sharedSecret - PQC shared secret (hex)
 * @returns SRTP key set
 */
export function deriveSRTPKeys(sharedSecret) {
    const secret = hexToBytes(sharedSecret);
    // Derive encryption key (32 bytes for AES-256)
    const encryptionKey = hkdf(sha3_256, secret, undefined, utf8ToBytes(SRTP_ENCRYPTION_LABEL), 32);
    // Derive authentication key (32 bytes)
    const authenticationKey = hkdf(sha3_256, secret, undefined, utf8ToBytes(SRTP_AUTH_LABEL), 32);
    // Derive salt key (14 bytes for SRTP)
    const saltKey = hkdf(sha3_256, secret, undefined, utf8ToBytes(SRTP_SALT_LABEL), 14);
    return {
        encryptionKey: bytesToHex(encryptionKey),
        authenticationKey: bytesToHex(authenticationKey),
        saltKey: bytesToHex(saltKey),
    };
}
// =============================================================================
// VOICE FRAME ENCRYPTION
// =============================================================================
/**
 * Encrypt a voice frame
 * @param callId - Call identifier
 * @param payload - Voice data (Uint8Array)
 * @param timestamp - RTP timestamp
 * @returns Encrypted frame
 */
export function encryptFrame(callId, payload, timestamp) {
    const session = activeSessions.get(callId);
    if (!session) {
        throw new Error(`No active session for call ${callId}`);
    }
    if (session.state !== 'connected') {
        throw new Error(`Session not in connected state: ${session.state}`);
    }
    // Increment sequence number with rollover
    session.sequenceNumber++;
    if (session.sequenceNumber > MAX_SEQUENCE_NUMBER) {
        session.sequenceNumber = 0;
        session.rolloverCounter++;
    }
    // Build nonce from salt + SSRC + sequence number + ROC
    const nonce = buildNonce(session.srtpKeys.saltKey, session.ssrc, session.sequenceNumber, session.rolloverCounter);
    // Encrypt with AES-256-GCM
    const key = hexToBytes(session.srtpKeys.encryptionKey);
    const cipher = gcm(key, nonce);
    const ciphertext = cipher.encrypt(payload);
    // The GCM auth tag is appended to ciphertext by noble/ciphers
    // Extract it (last 16 bytes)
    const authTag = ciphertext.slice(-16);
    const encryptedPayload = ciphertext.slice(0, -16);
    // Update stats
    updateStats(callId, 'sent', payload.length);
    return {
        sequenceNumber: session.sequenceNumber,
        timestamp,
        ssrc: session.ssrc,
        nonce: bytesToHex(nonce),
        ciphertext: bytesToHex(encryptedPayload),
        authTag: bytesToHex(authTag),
    };
}
/**
 * Decrypt a voice frame
 * @param callId - Call identifier
 * @param frame - Encrypted frame
 * @returns Decrypted frame
 */
export function decryptFrame(callId, frame) {
    const session = activeSessions.get(callId);
    if (!session) {
        throw new Error(`No active session for call ${callId}`);
    }
    if (session.state !== 'connected') {
        throw new Error(`Session not in connected state: ${session.state}`);
    }
    // Reconstruct ciphertext with auth tag
    const ciphertext = hexToBytes(frame.ciphertext);
    const authTag = hexToBytes(frame.authTag);
    const fullCiphertext = new Uint8Array(ciphertext.length + authTag.length);
    fullCiphertext.set(ciphertext);
    fullCiphertext.set(authTag, ciphertext.length);
    // Decrypt with AES-256-GCM
    const key = hexToBytes(session.srtpKeys.encryptionKey);
    const nonce = hexToBytes(frame.nonce);
    const cipher = gcm(key, nonce);
    let payload;
    try {
        payload = cipher.decrypt(fullCiphertext);
    }
    catch {
        throw new Error('Frame decryption failed - authentication error');
    }
    // Update stats
    updateStats(callId, 'received', payload.length);
    return {
        sequenceNumber: frame.sequenceNumber,
        timestamp: frame.timestamp,
        ssrc: frame.ssrc,
        payload,
    };
}
/**
 * Build SRTP-style nonce
 */
function buildNonce(saltKey, ssrc, sequenceNumber, roc) {
    const salt = hexToBytes(saltKey);
    const nonce = new Uint8Array(12);
    // Copy salt (14 bytes -> 12 bytes, truncate)
    nonce.set(salt.slice(0, 12));
    // XOR in SSRC and index
    const view = new DataView(nonce.buffer);
    const index = (roc * (MAX_SEQUENCE_NUMBER + 1)) + sequenceNumber;
    // XOR SSRC at bytes 4-7
    const currentSsrc = view.getUint32(4, false);
    view.setUint32(4, currentSsrc ^ ssrc, false);
    // XOR index at bytes 8-11
    const currentIndex = view.getUint32(8, false);
    view.setUint32(8, currentIndex ^ index, false);
    return nonce;
}
// =============================================================================
// SESSION MANAGEMENT
// =============================================================================
/**
 * Get active session
 * @param callId - Call identifier
 * @returns VoIP session or null
 */
export function getSession(callId) {
    return activeSessions.get(callId) ?? null;
}
/**
 * Update session state
 * @param callId - Call identifier
 * @param state - New state
 */
export function setSessionState(callId, state) {
    const session = activeSessions.get(callId);
    if (session) {
        session.state = state;
    }
}
/**
 * Put call on hold
 * @param callId - Call identifier
 */
export function holdCall(callId) {
    setSessionState(callId, 'hold');
}
/**
 * Resume call from hold
 * @param callId - Call identifier
 */
export function resumeCall(callId) {
    setSessionState(callId, 'connected');
}
/**
 * Terminate a call
 * @param callId - Call identifier
 * @returns Final session statistics
 */
export function terminateCall(callId) {
    const session = activeSessions.get(callId);
    if (!session) {
        return null;
    }
    session.state = 'terminated';
    // Get final stats
    const stats = getSessionStats(callId);
    // Cleanup
    activeSessions.delete(callId);
    sessionStats.delete(callId);
    return stats;
}
/**
 * Get number of active calls
 */
export function getActiveCallCount() {
    let count = 0;
    for (const session of activeSessions.values()) {
        if (session.state === 'connected' || session.state === 'hold') {
            count++;
        }
    }
    return count;
}
/**
 * Get all active call IDs
 */
export function getActiveCallIds() {
    return Array.from(activeSessions.keys());
}
// =============================================================================
// STATISTICS
// =============================================================================
/**
 * Initialize session statistics
 */
function initSessionStats(callId) {
    sessionStats.set(callId, {
        callId,
        duration: 0,
        framesSent: 0,
        framesReceived: 0,
        bytesEncrypted: 0,
        bytesDecrypted: 0,
        packetsLost: 0,
    });
}
/**
 * Update session statistics
 */
function updateStats(callId, direction, bytes) {
    const stats = sessionStats.get(callId);
    if (!stats)
        return;
    if (direction === 'sent') {
        stats.framesSent++;
        stats.bytesEncrypted += bytes;
    }
    else {
        stats.framesReceived++;
        stats.bytesDecrypted += bytes;
    }
}
/**
 * Get session statistics
 * @param callId - Call identifier
 * @returns Session statistics
 */
export function getSessionStats(callId) {
    const stats = sessionStats.get(callId);
    if (!stats)
        return null;
    const session = activeSessions.get(callId);
    if (session) {
        stats.duration = Date.now() - session.establishedAt;
    }
    return { ...stats };
}
/**
 * Report packet loss
 * @param callId - Call identifier
 * @param count - Number of lost packets
 */
export function reportPacketLoss(callId, count = 1) {
    const stats = sessionStats.get(callId);
    if (stats) {
        stats.packetsLost += count;
    }
}
// =============================================================================
// UTILITIES
// =============================================================================
/**
 * Estimate bandwidth usage (bytes per second)
 * @param codec - Voice codec
 * @param frameSize - Frame size in samples
 * @param sampleRate - Sample rate in Hz
 * @returns Estimated bandwidth in bytes per second
 */
export function estimateBandwidth(codec = 'OPUS', frameSize = DEFAULT_FRAME_SIZE, sampleRate = 48000) {
    // Approximate bitrates for different codecs
    const codecBitrates = {
        OPUS: 32000, // 32 kbps for Opus
        G711: 64000, // 64 kbps for G.711
        G722: 64000, // 64 kbps for G.722
        G729: 8000, // 8 kbps for G.729
        PCMU: 64000, // 64 kbps for PCMU
        PCMA: 64000, // 64 kbps for PCMA
    };
    const bitrate = codecBitrates[codec];
    const frameDuration = frameSize / sampleRate; // seconds
    const framesPerSecond = 1 / frameDuration;
    // Add encryption overhead (nonce, auth tag, headers)
    const overheadPerFrame = 12 + 16 + 12; // nonce + auth tag + RTP-like header
    const payloadBytesPerSecond = bitrate / 8;
    const overheadBytesPerSecond = framesPerSecond * overheadPerFrame;
    return Math.ceil(payloadBytesPerSecond + overheadBytesPerSecond);
}
/**
 * Get algorithm information for security level
 */
export function getAlgorithmInfo(securityLevel = '5') {
    return {
        kem: kem.getAlgorithmName(securityLevel),
        dsa: dsa.getAlgorithmName(securityLevel),
        symmetric: 'AES-256-GCM',
        keyExchangeSize: kem.getCiphertextSize(securityLevel),
        signatureSize: dsa.getSignatureSize(securityLevel),
    };
}
export default {
    // Key generation
    generateKeyPair,
    generateCallId,
    generateSSRC,
    // Call establishment
    createCallRequest,
    verifyCallRequest,
    acceptCall,
    completeCall,
    // Key derivation
    deriveSRTPKeys,
    // Frame encryption
    encryptFrame,
    decryptFrame,
    // Session management
    getSession,
    setSessionState,
    holdCall,
    resumeCall,
    terminateCall,
    getActiveCallCount,
    getActiveCallIds,
    // Statistics
    getSessionStats,
    reportPacketLoss,
    // Utilities
    estimateBandwidth,
    getAlgorithmInfo,
};
//# sourceMappingURL=voip.js.map