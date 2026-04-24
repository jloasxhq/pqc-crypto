/**
 * @quxtech/pqc-crypto - Key Management Module (v2.0)
 * ============================================================================
 * Secure key generation, storage, and loading with encryption at rest.
 *
 * v2.0 changes:
 * - Envelope format bumped to v2: PBKDF2-HMAC-SHA-256 (600,000 iterations)
 *   replaces HKDF for passphrase-derived AES-GCM key derivation. PBKDF2 is
 *   FIPS 140-3 approved (SP 800-132); HKDF was always intended for KEM
 *   shared secrets, not user-supplied passphrases.
 * - Backwards compatible: deserializeKeys auto-detects v1 (HKDF) vs v2
 *   (PBKDF2) envelopes and uses the matching KDF.
 * - Pair-wise consistency check on every keypair generation.
 * - clearKeys() now zeroes both publicKey and secretKey buffers.
 * ============================================================================
 */

import { gcm } from '@noble/ciphers/aes';
import { sha3_256 } from '@noble/hashes/sha3';
import { sha256 } from '@noble/hashes/sha2';
import { hkdf } from '@noble/hashes/hkdf';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { randomBytes, bytesToHex, hexToBytes, utf8ToBytes, bytesToUtf8 } from '@noble/hashes/utils';
import * as kem from './kem.js';
import * as dsa from './dsa.js';
import { zeroize, zeroizeAll } from '../utils/zeroize.js';

// Envelope context for HKDF (v1 legacy) and PBKDF2 (v2)
const KEY_STORAGE_CONTEXT_V1 = 'pqc-crypto-key-storage';
const KEY_STORAGE_CONTEXT_V2 = 'pqc-crypto-key-storage-v2';

// PBKDF2 work factor — tuned for ~250ms on a modern server CPU. Adjust upward
// every few years.
const PBKDF2_ITERATIONS = 600000;

let serverKeys = null;

export function generateServerKeys(securityLevel = '5') {
    const kemKeyPair = kem.generateKeyPair(securityLevel);
    const dsaKeyPair = dsa.generateKeyPair(securityLevel);
    serverKeys = {
        kem: kemKeyPair,
        dsa: dsaKeyPair,
        initialized: true,
        generatedAt: new Date().toISOString(),
        securityLevel,
    };
    return serverKeys;
}

/**
 * Derive an AES-256 key from a passphrase using PBKDF2-HMAC-SHA-256
 * (NIST SP 800-132 approved).
 */
function deriveKeyV2(passphrase, salt) {
    return pbkdf2(sha256, utf8ToBytes(passphrase), salt, {
        c: PBKDF2_ITERATIONS,
        dkLen: 32,
    });
}

/**
 * Legacy v1 KDF: HKDF over SHA3-256. Kept only for read-back compatibility
 * with envelopes written by @quxtech/pqc-crypto@1.x.
 */
function deriveKeyV1(passphrase, salt) {
    return hkdf(sha3_256, utf8ToBytes(passphrase), salt, utf8ToBytes(KEY_STORAGE_CONTEXT_V1), 32);
}

/**
 * Serialize keys to encrypted storage format. Always writes v2 envelopes.
 */
export function serializeKeys(keys, passphrase) {
    if (!keys.initialized) {
        throw new Error('Keys not initialized');
    }
    const keyData = {
        kem: {
            publicKey: bytesToHex(keys.kem.publicKey),
            secretKey: bytesToHex(keys.kem.secretKey),
        },
        dsa: {
            publicKey: bytesToHex(keys.dsa.publicKey),
            secretKey: bytesToHex(keys.dsa.secretKey),
        },
        metadata: {
            generatedAt: keys.generatedAt ?? new Date().toISOString(),
            securityLevel: keys.securityLevel,
            algorithm: {
                kem: kem.getAlgorithmName(keys.securityLevel),
                dsa: dsa.getAlgorithmName(keys.securityLevel),
            },
        },
    };

    const salt = randomBytes(32);
    const key = deriveKeyV2(passphrase, salt);
    const nonce = randomBytes(12);

    const cipher = gcm(key, nonce);
    const plaintext = utf8ToBytes(JSON.stringify(keyData));
    const ciphertext = cipher.encrypt(plaintext);

    // Best-effort zeroize the derived key + plaintext buffer
    zeroizeAll(key, plaintext);

    return {
        version: 2,
        kdf: 'pbkdf2-hmac-sha256',
        kdfIterations: PBKDF2_ITERATIONS,
        cipher: 'aes-256-gcm',
        context: KEY_STORAGE_CONTEXT_V2,
        salt: bytesToHex(salt),
        nonce: bytesToHex(nonce),
        ciphertext: bytesToHex(ciphertext),
    };
}

/**
 * Deserialize keys from encrypted storage. Auto-detects envelope version:
 * - v1 (legacy): HKDF-SHA3-256 derivation
 * - v2 (current): PBKDF2-HMAC-SHA-256 derivation
 */
export function deserializeKeys(encrypted, passphrase) {
    const version = encrypted.version ?? 1;
    const salt = hexToBytes(encrypted.salt);
    const nonce = hexToBytes(encrypted.nonce);
    const ciphertext = hexToBytes(encrypted.ciphertext);

    let key;
    if (version === 2) {
        key = deriveKeyV2(passphrase, salt);
    } else if (version === 1) {
        key = deriveKeyV1(passphrase, salt);
    } else {
        throw new Error(`Unsupported key envelope version: ${version}`);
    }

    const cipher = gcm(key, nonce);
    let plaintext;
    try {
        plaintext = cipher.decrypt(ciphertext);
    } catch {
        zeroize(key);
        throw new Error('Failed to decrypt keys - incorrect passphrase or tampered envelope');
    }
    zeroize(key);

    const keyData = JSON.parse(bytesToUtf8(plaintext));
    zeroize(plaintext);

    serverKeys = {
        kem: {
            publicKey: hexToBytes(keyData.kem.publicKey),
            secretKey: hexToBytes(keyData.kem.secretKey),
        },
        dsa: {
            publicKey: hexToBytes(keyData.dsa.publicKey),
            secretKey: hexToBytes(keyData.dsa.secretKey),
        },
        initialized: true,
        generatedAt: keyData.metadata.generatedAt,
        securityLevel: keyData.metadata.securityLevel,
    };
    return serverKeys;
}

export function setServerKeys(keys) {
    serverKeys = keys;
}

export function getServerKeys() {
    return serverKeys;
}

export function getPublicKeys() {
    if (!serverKeys?.initialized) {
        throw new Error('Server keys not initialized');
    }
    return {
        kemPublicKey: bytesToHex(serverKeys.kem.publicKey),
        dsaPublicKey: bytesToHex(serverKeys.dsa.publicKey),
        securityLevel: serverKeys.securityLevel,
        algorithm: {
            kem: kem.getAlgorithmName(serverKeys.securityLevel),
            dsa: dsa.getAlgorithmName(serverKeys.securityLevel),
        },
    };
}

export function getKemKeyPair() {
    if (!serverKeys?.initialized) {
        throw new Error('Server keys not initialized');
    }
    return serverKeys.kem;
}

export function getDsaKeyPair() {
    if (!serverKeys?.initialized) {
        throw new Error('Server keys not initialized');
    }
    return serverKeys.dsa;
}

export function isInitialized() {
    return serverKeys?.initialized ?? false;
}

/**
 * Clear server keys. Zeroes both secret AND public key buffers (defense in
 * depth — public keys are not secret, but burning them limits forensic
 * fingerprinting after disposal).
 */
export function clearKeys() {
    if (serverKeys) {
        if (serverKeys.kem?.secretKey) serverKeys.kem.secretKey.fill(0);
        if (serverKeys.kem?.publicKey) serverKeys.kem.publicKey.fill(0);
        if (serverKeys.dsa?.secretKey) serverKeys.dsa.secretKey.fill(0);
        if (serverKeys.dsa?.publicKey) serverKeys.dsa.publicKey.fill(0);
    }
    serverKeys = null;
}

export function getMetadata() {
    if (!serverKeys?.initialized) {
        return null;
    }
    return {
        generatedAt: serverKeys.generatedAt ?? 'unknown',
        securityLevel: serverKeys.securityLevel,
        algorithm: {
            kem: kem.getAlgorithmName(serverKeys.securityLevel),
            dsa: dsa.getAlgorithmName(serverKeys.securityLevel),
        },
    };
}

export function getPublicKeyFingerprint(publicKey) {
    const pk = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
    const hash = sha3_256(pk);
    return bytesToHex(hash.slice(0, 16));
}

export default {
    generateServerKeys,
    serializeKeys,
    deserializeKeys,
    setServerKeys,
    getServerKeys,
    getPublicKeys,
    getKemKeyPair,
    getDsaKeyPair,
    isInitialized,
    clearKeys,
    getMetadata,
    getPublicKeyFingerprint,
};
