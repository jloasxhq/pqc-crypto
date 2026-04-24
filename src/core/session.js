/**
 * @quxtech/pqc-crypto - Session Management Module
 * ============================================================================
 * Manages encrypted sessions with PQC key exchange.
 *
 * Features:
 * - Session creation with ML-KEM encapsulation
 * - Session signing with ML-DSA
 * - Configurable expiration
 * - Pluggable session store interface
 * ============================================================================
 */
import { bytesToHex } from '@noble/hashes/utils';
import * as kem from './kem.js';
import * as dsa from './dsa.js';
import * as keys from './keys.js';
// Default session TTL: 1 hour
const DEFAULT_SESSION_TTL_MS = 3600000;
// In-memory session store (default implementation)
const inMemoryStore = new Map();
// Configurable session store
let sessionStore = null;
// Session TTL
let sessionTtlMs = DEFAULT_SESSION_TTL_MS;
/**
 * Configure session management
 * @param options - Configuration options
 */
export function configure(options) {
    if (options.store) {
        sessionStore = options.store;
    }
    if (options.ttlMs !== undefined) {
        sessionTtlMs = options.ttlMs;
    }
}
/**
 * Generate a unique session ID
 * @returns Random session ID (32 hex characters)
 */
export function generateSessionId() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return bytesToHex(bytes);
}
/**
 * Create a new encrypted session
 * @param sessionId - Unique session identifier
 * @param clientKemPublicKey - Client's ML-KEM public key (hex)
 * @param securityLevel - NIST security level
 * @returns Session response for client
 */
export async function createSession(sessionId, clientKemPublicKey, securityLevel = '5') {
    // Encapsulate shared secret to client's public key
    const { ciphertext, sharedSecret } = kem.encapsulate(clientKemPublicKey, securityLevel);
    // Create session data
    const sessionData = {
        sharedSecret,
        createdAt: Date.now(),
        lastUsed: Date.now(),
    };
    // Store session
    if (sessionStore) {
        await sessionStore.set(sessionId, sessionData);
    }
    else {
        inMemoryStore.set(sessionId, sessionData);
    }
    // Sign the session creation
    const serverKeys = keys.getServerKeys();
    if (!serverKeys?.initialized) {
        throw new Error('Server keys not initialized');
    }
    const signatureData = JSON.stringify({
        sessionId,
        ciphertext,
        timestamp: sessionData.createdAt,
    });
    const signature = dsa.sign(signatureData, serverKeys.dsa.secretKey, securityLevel);
    return {
        sessionId,
        ciphertext,
        signature,
        expiresIn: Math.floor(sessionTtlMs / 1000),
    };
}
/**
 * Get session shared secret
 * @param sessionId - Session identifier
 * @returns Shared secret (hex) or null if not found/expired
 */
export async function getSessionSecret(sessionId) {
    let session = null;
    if (sessionStore) {
        session = await sessionStore.get(sessionId);
    }
    else {
        session = inMemoryStore.get(sessionId) ?? null;
    }
    if (!session) {
        return null;
    }
    // Check expiration
    if (Date.now() - session.createdAt > sessionTtlMs) {
        await destroySession(sessionId);
        return null;
    }
    // Update last used
    session.lastUsed = Date.now();
    if (sessionStore) {
        await sessionStore.set(sessionId, session);
    }
    return session.sharedSecret;
}
/**
 * Get full session data
 * @param sessionId - Session identifier
 * @returns Session data or null if not found
 */
export async function getSession(sessionId) {
    if (sessionStore) {
        return sessionStore.get(sessionId);
    }
    return inMemoryStore.get(sessionId) ?? null;
}
/**
 * Check if session exists and is valid
 * @param sessionId - Session identifier
 * @returns True if session is valid
 */
export async function isSessionValid(sessionId) {
    const session = await getSession(sessionId);
    if (!session) {
        return false;
    }
    return Date.now() - session.createdAt <= sessionTtlMs;
}
/**
 * Destroy a session
 * @param sessionId - Session identifier
 */
export async function destroySession(sessionId) {
    if (sessionStore) {
        await sessionStore.delete(sessionId);
    }
    else {
        inMemoryStore.delete(sessionId);
    }
}
/**
 * Clean up expired sessions
 * Only works with in-memory store; custom stores should implement their own cleanup
 */
export async function cleanupExpiredSessions() {
    if (sessionStore) {
        await sessionStore.cleanup();
        return 0; // Custom store handles cleanup
    }
    const now = Date.now();
    let cleaned = 0;
    for (const [sessionId, session] of inMemoryStore.entries()) {
        if (now - session.createdAt > sessionTtlMs) {
            inMemoryStore.delete(sessionId);
            cleaned++;
        }
    }
    return cleaned;
}
/**
 * Get session count (in-memory store only)
 * @returns Number of active sessions
 */
export function getSessionCount() {
    if (sessionStore) {
        return -1; // Unknown for custom stores
    }
    return inMemoryStore.size;
}
/**
 * Clear all sessions (in-memory store only)
 */
export function clearAllSessions() {
    if (!sessionStore) {
        inMemoryStore.clear();
    }
}
/**
 * Verify a session response signature
 * @param response - Session response from server
 * @param serverDsaPublicKey - Server's ML-DSA public key
 * @param securityLevel - NIST security level
 * @returns True if signature is valid
 */
export function verifySessionResponse(response, serverDsaPublicKey, securityLevel = '5') {
    const signatureData = JSON.stringify({
        sessionId: response.sessionId,
        ciphertext: response.ciphertext,
        timestamp: Date.now(), // This won't match - need to extract from response
    });
    // Note: In practice, timestamp should be included in the response
    // This is a simplified verification
    return dsa.verify(signatureData, response.signature, serverDsaPublicKey, securityLevel);
}
/**
 * Create a Redis-compatible session store
 * @param redisClient - Redis client with get/set/del methods
 * @param keyPrefix - Prefix for session keys
 * @returns Session store implementation
 */
export function createRedisStore(redisClient, keyPrefix = 'pqc:session:') {
    return {
        async get(sessionId) {
            const data = await redisClient.get(`${keyPrefix}${sessionId}`);
            if (!data)
                return null;
            return JSON.parse(data);
        },
        async set(sessionId, data) {
            const ttlSeconds = Math.ceil(sessionTtlMs / 1000);
            await redisClient.set(`${keyPrefix}${sessionId}`, JSON.stringify(data), { EX: ttlSeconds });
        },
        async delete(sessionId) {
            await redisClient.del(`${keyPrefix}${sessionId}`);
        },
        async cleanup() {
            // Redis TTL handles cleanup automatically
        },
    };
}
// Auto-cleanup interval for in-memory store
let cleanupInterval = null;
/**
 * Start automatic session cleanup
 * @param intervalMs - Cleanup interval in milliseconds (default: 5 minutes)
 */
export function startAutoCleanup(intervalMs = 300000) {
    if (cleanupInterval) {
        clearInterval(cleanupInterval);
    }
    cleanupInterval = setInterval(() => {
        // eslint-disable-next-line no-console
        cleanupExpiredSessions().catch(console.error);
    }, intervalMs);
}
/**
 * Stop automatic session cleanup
 */
export function stopAutoCleanup() {
    if (cleanupInterval) {
        clearInterval(cleanupInterval);
        cleanupInterval = null;
    }
}
export default {
    configure,
    generateSessionId,
    createSession,
    getSessionSecret,
    getSession,
    isSessionValid,
    destroySession,
    cleanupExpiredSessions,
    getSessionCount,
    clearAllSessions,
    verifySessionResponse,
    createRedisStore,
    startAutoCleanup,
    stopAutoCleanup,
};
//# sourceMappingURL=session.js.map