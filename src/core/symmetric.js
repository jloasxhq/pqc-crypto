/**
 * @quxtech/pqc-crypto - Symmetric Encryption Module (AES-256-GCM)
 * ============================================================================
 * AES-256-GCM symmetric encryption with PQC-derived keys, via the active
 * PqcProvider. HKDF key derivation also goes through the provider so a
 * FIPS-validated backend can replace it transparently.
 * ============================================================================
 */
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { getProvider } from './provider.js';

const DEFAULT_CONTEXT = 'pqc-crypto-encrypt';

export function deriveKey(sharedSecret, context = DEFAULT_CONTEXT, salt) {
    const secret = typeof sharedSecret === 'string' ? hexToBytes(sharedSecret) : sharedSecret;
    const saltBytes = salt
        ? (typeof salt === 'string' ? hexToBytes(salt) : salt)
        : undefined;
    return getProvider().hkdfSha3_256(secret, saltBytes, utf8ToBytes(context), 32);
}

export function deriveKeyHex(sharedSecret, context = DEFAULT_CONTEXT, salt) {
    return bytesToHex(deriveKey(sharedSecret, context, salt));
}

export function encrypt(data, key, aad) {
    const p = getProvider();
    const keyBytes = typeof key === 'string' ? hexToBytes(key) : key;
    if (keyBytes.length !== 32) throw new Error('Key must be 32 bytes');
    const nonce = p.randomBytes(12);
    let plaintext;
    if (data instanceof Uint8Array) plaintext = data;
    else if (typeof data === 'string') plaintext = utf8ToBytes(data);
    else plaintext = utf8ToBytes(JSON.stringify(data));
    const ciphertext = p.aesGcmEncrypt(keyBytes, nonce, plaintext, aad);
    return { nonce: bytesToHex(nonce), ciphertext: bytesToHex(ciphertext) };
}

export function encryptWithSecret(data, sharedSecret, options = {}) {
    const key = deriveKey(sharedSecret, options.context ?? DEFAULT_CONTEXT);
    return encrypt(data, key);
}

export function decrypt(encryptedData, key, aad) {
    const p = getProvider();
    const keyBytes = typeof key === 'string' ? hexToBytes(key) : key;
    if (keyBytes.length !== 32) throw new Error('Key must be 32 bytes');
    const nonce = hexToBytes(encryptedData.nonce);
    const ciphertext = hexToBytes(encryptedData.ciphertext);
    return p.aesGcmDecrypt(keyBytes, nonce, ciphertext, aad);
}

export function decryptToString(encryptedData, key, aad) {
    return new TextDecoder().decode(decrypt(encryptedData, key, aad));
}

export function decryptToJson(encryptedData, key, aad) {
    return JSON.parse(decryptToString(encryptedData, key, aad));
}

export function decryptWithSecret(encryptedData, sharedSecret, options = {}) {
    const key = deriveKey(sharedSecret, options.context ?? DEFAULT_CONTEXT);
    return decryptToString(encryptedData, key);
}

export function generateRandomBytes(length) { return getProvider().randomBytes(length); }
export function generateRandomHex(length) { return bytesToHex(getProvider().randomBytes(length)); }
export function generateKey() { return getProvider().randomBytes(32); }
export function generateKeyHex() { return bytesToHex(getProvider().randomBytes(32)); }

export default {
    deriveKey, deriveKeyHex,
    encrypt, encryptWithSecret,
    decrypt, decryptToString, decryptToJson, decryptWithSecret,
    generateRandomBytes, generateRandomHex, generateKey, generateKeyHex,
};
