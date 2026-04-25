/**
 * @quxtech/pqc-crypto - Key Management Module (v2.0)
 * ============================================================================
 * v2 envelope: PBKDF2-HMAC-SHA-256 (NIST SP 800-132, 600,000 iterations)
 * for passphrase-derived AES-256-GCM key wrapping. Backwards compatible
 * with v1 HKDF envelopes via `version` field auto-detect.
 * Routed through the active PqcProvider.
 * ============================================================================
 */
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import * as kem from './kem.js';
import * as dsa from './dsa.js';
import { getProvider } from './provider.js';
import { zeroize, zeroizeAll } from '../utils/zeroize.js';

const KEY_STORAGE_CONTEXT_V1 = 'pqc-crypto-key-storage';
const KEY_STORAGE_CONTEXT_V2 = 'pqc-crypto-key-storage-v2';
const PBKDF2_ITERATIONS = 600000;

let serverKeys = null;

export function generateServerKeys(securityLevel = '5') {
    serverKeys = {
        kem: kem.generateKeyPair(securityLevel),
        dsa: dsa.generateKeyPair(securityLevel),
        initialized: true,
        generatedAt: new Date().toISOString(),
        securityLevel,
    };
    return serverKeys;
}

function deriveKeyV2(passphrase, salt) {
    return getProvider().pbkdf2Sha256(utf8ToBytes(passphrase), salt, PBKDF2_ITERATIONS, 32);
}
function deriveKeyV1(passphrase, salt) {
    return getProvider().hkdfSha3_256(utf8ToBytes(passphrase), salt, utf8ToBytes(KEY_STORAGE_CONTEXT_V1), 32);
}

export function serializeKeys(keys, passphrase) {
    if (!keys.initialized) throw new Error('Keys not initialized');
    const p = getProvider();
    const keyData = {
        kem: { publicKey: bytesToHex(keys.kem.publicKey), secretKey: bytesToHex(keys.kem.secretKey) },
        dsa: { publicKey: bytesToHex(keys.dsa.publicKey), secretKey: bytesToHex(keys.dsa.secretKey) },
        metadata: {
            generatedAt: keys.generatedAt ?? new Date().toISOString(),
            securityLevel: keys.securityLevel,
            algorithm: { kem: kem.getAlgorithmName(keys.securityLevel), dsa: dsa.getAlgorithmName(keys.securityLevel) },
        },
    };
    const salt = p.randomBytes(32);
    const key = deriveKeyV2(passphrase, salt);
    const nonce = p.randomBytes(12);
    const plaintext = utf8ToBytes(JSON.stringify(keyData));
    const ciphertext = p.aesGcmEncrypt(key, nonce, plaintext);
    zeroizeAll(key, plaintext);
    return {
        version: 2, kdf: 'pbkdf2-hmac-sha256', kdfIterations: PBKDF2_ITERATIONS,
        cipher: 'aes-256-gcm', context: KEY_STORAGE_CONTEXT_V2,
        salt: bytesToHex(salt), nonce: bytesToHex(nonce), ciphertext: bytesToHex(ciphertext),
    };
}

export function deserializeKeys(encrypted, passphrase) {
    const p = getProvider();
    const version = encrypted.version ?? 1;
    const salt = hexToBytes(encrypted.salt);
    const nonce = hexToBytes(encrypted.nonce);
    const ciphertext = hexToBytes(encrypted.ciphertext);
    let key;
    if (version === 2) key = deriveKeyV2(passphrase, salt);
    else if (version === 1) key = deriveKeyV1(passphrase, salt);
    else throw new Error(`Unsupported key envelope version: ${version}`);
    let plaintext;
    try { plaintext = p.aesGcmDecrypt(key, nonce, ciphertext); }
    catch { zeroize(key); throw new Error('Failed to decrypt keys - incorrect passphrase or tampered envelope'); }
    zeroize(key);
    const keyData = JSON.parse(new TextDecoder().decode(plaintext));
    zeroize(plaintext);
    serverKeys = {
        kem: { publicKey: hexToBytes(keyData.kem.publicKey), secretKey: hexToBytes(keyData.kem.secretKey) },
        dsa: { publicKey: hexToBytes(keyData.dsa.publicKey), secretKey: hexToBytes(keyData.dsa.secretKey) },
        initialized: true,
        generatedAt: keyData.metadata.generatedAt,
        securityLevel: keyData.metadata.securityLevel,
    };
    return serverKeys;
}

export function setServerKeys(k) { serverKeys = k; }
export function getServerKeys() { return serverKeys; }

export function getPublicKeys() {
    if (!serverKeys?.initialized) throw new Error('Server keys not initialized');
    return {
        kemPublicKey: bytesToHex(serverKeys.kem.publicKey),
        dsaPublicKey: bytesToHex(serverKeys.dsa.publicKey),
        securityLevel: serverKeys.securityLevel,
        algorithm: { kem: kem.getAlgorithmName(serverKeys.securityLevel), dsa: dsa.getAlgorithmName(serverKeys.securityLevel) },
    };
}

export function getKemKeyPair() {
    if (!serverKeys?.initialized) throw new Error('Server keys not initialized');
    return serverKeys.kem;
}
export function getDsaKeyPair() {
    if (!serverKeys?.initialized) throw new Error('Server keys not initialized');
    return serverKeys.dsa;
}

export function isInitialized() { return serverKeys?.initialized ?? false; }

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
    if (!serverKeys?.initialized) return null;
    return {
        generatedAt: serverKeys.generatedAt ?? 'unknown',
        securityLevel: serverKeys.securityLevel,
        algorithm: { kem: kem.getAlgorithmName(serverKeys.securityLevel), dsa: dsa.getAlgorithmName(serverKeys.securityLevel) },
    };
}

export function getPublicKeyFingerprint(publicKey) {
    const p = getProvider();
    const pk = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
    return bytesToHex(p.sha3_256(pk).slice(0, 16));
}

export default {
    generateServerKeys, serializeKeys, deserializeKeys,
    setServerKeys, getServerKeys, getPublicKeys, getKemKeyPair, getDsaKeyPair,
    isInitialized, clearKeys, getMetadata, getPublicKeyFingerprint,
};
