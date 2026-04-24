/**
 * @quxtech/pqc-crypto - Symmetric Encryption Module (AES-256-GCM)
 * ============================================================================
 * Implements AES-256-GCM symmetric encryption with PQC-derived keys.
 *
 * Uses HKDF with SHA3-256 for key derivation from shared secrets.
 * ============================================================================
 */
import { gcm } from '@noble/ciphers/aes';
import { sha3_256 } from '@noble/hashes/sha3';
import { hkdf } from '@noble/hashes/hkdf';
import { randomBytes, bytesToHex, hexToBytes, utf8ToBytes, bytesToUtf8 } from '@noble/hashes/utils';
// Default context string for key derivation
const DEFAULT_CONTEXT = 'pqc-crypto-encrypt';
/**
 * Derive a symmetric key from a shared secret using HKDF
 * @param sharedSecret - PQC shared secret (hex string or Uint8Array)
 * @param context - Context string for domain separation
 * @param salt - Optional salt (hex string or Uint8Array)
 * @returns 32-byte derived key
 */
export function deriveKey(sharedSecret, context = DEFAULT_CONTEXT, salt) {
    const secret = typeof sharedSecret === 'string' ? hexToBytes(sharedSecret) : sharedSecret;
    const saltBytes = salt
        ? (typeof salt === 'string' ? hexToBytes(salt) : salt)
        : undefined;
    return hkdf(sha3_256, secret, saltBytes, utf8ToBytes(context), 32);
}
/**
 * Derive a symmetric key and return as hex string
 * @param sharedSecret - PQC shared secret
 * @param context - Context string for domain separation
 * @param salt - Optional salt
 * @returns Hex-encoded 32-byte key
 */
export function deriveKeyHex(sharedSecret, context = DEFAULT_CONTEXT, salt) {
    return bytesToHex(deriveKey(sharedSecret, context, salt));
}
/**
 * Encrypt data using AES-256-GCM
 * @param data - Data to encrypt (string, object, or Uint8Array)
 * @param key - 32-byte encryption key (hex string or Uint8Array)
 * @param aad - Optional additional authenticated data
 * @returns Encrypted data with nonce
 */
export function encrypt(data, key, aad) {
    const keyBytes = typeof key === 'string' ? hexToBytes(key) : key;
    if (keyBytes.length !== 32) {
        throw new Error('Key must be 32 bytes');
    }
    const nonce = randomBytes(12);
    let plaintext;
    if (data instanceof Uint8Array) {
        plaintext = data;
    }
    else if (typeof data === 'string') {
        plaintext = utf8ToBytes(data);
    }
    else {
        plaintext = utf8ToBytes(JSON.stringify(data));
    }
    const cipher = gcm(keyBytes, nonce, aad);
    const ciphertext = cipher.encrypt(plaintext);
    return {
        nonce: bytesToHex(nonce),
        ciphertext: bytesToHex(ciphertext),
    };
}
/**
 * Encrypt data using a shared secret (derives key internally)
 * @param data - Data to encrypt
 * @param sharedSecret - PQC shared secret
 * @param options - Encryption options
 * @returns Encrypted data with nonce
 */
export function encryptWithSecret(data, sharedSecret, options = {}) {
    const key = deriveKey(sharedSecret, options.context ?? DEFAULT_CONTEXT);
    return encrypt(data, key);
}
/**
 * Decrypt data using AES-256-GCM
 * @param encryptedData - Encrypted data with nonce
 * @param key - 32-byte decryption key (hex string or Uint8Array)
 * @param aad - Optional additional authenticated data
 * @returns Decrypted data as Uint8Array
 */
export function decrypt(encryptedData, key, aad) {
    const keyBytes = typeof key === 'string' ? hexToBytes(key) : key;
    if (keyBytes.length !== 32) {
        throw new Error('Key must be 32 bytes');
    }
    const nonce = hexToBytes(encryptedData.nonce);
    const ciphertext = hexToBytes(encryptedData.ciphertext);
    const cipher = gcm(keyBytes, nonce, aad);
    return cipher.decrypt(ciphertext);
}
/**
 * Decrypt data to string
 * @param encryptedData - Encrypted data with nonce
 * @param key - 32-byte decryption key
 * @param aad - Optional additional authenticated data
 * @returns Decrypted string
 */
export function decryptToString(encryptedData, key, aad) {
    const plaintext = decrypt(encryptedData, key, aad);
    return bytesToUtf8(plaintext);
}
/**
 * Decrypt data to JSON object
 * @param encryptedData - Encrypted data with nonce
 * @param key - 32-byte decryption key
 * @param aad - Optional additional authenticated data
 * @returns Parsed JSON object
 */
export function decryptToJson(encryptedData, key, aad) {
    const plaintext = decryptToString(encryptedData, key, aad);
    return JSON.parse(plaintext);
}
/**
 * Decrypt data using a shared secret
 * @param encryptedData - Encrypted data with nonce
 * @param sharedSecret - PQC shared secret
 * @param options - Decryption options
 * @returns Decrypted string
 */
export function decryptWithSecret(encryptedData, sharedSecret, options = {}) {
    const key = deriveKey(sharedSecret, options.context ?? DEFAULT_CONTEXT);
    return decryptToString(encryptedData, key);
}
/**
 * Generate random bytes
 * @param length - Number of bytes
 * @returns Random bytes as Uint8Array
 */
export function generateRandomBytes(length) {
    return randomBytes(length);
}
/**
 * Generate random bytes as hex string
 * @param length - Number of bytes
 * @returns Hex-encoded random bytes
 */
export function generateRandomHex(length) {
    return bytesToHex(randomBytes(length));
}
/**
 * Generate a random 32-byte key
 * @returns 32-byte key as Uint8Array
 */
export function generateKey() {
    return randomBytes(32);
}
/**
 * Generate a random 32-byte key as hex string
 * @returns Hex-encoded 32-byte key
 */
export function generateKeyHex() {
    return bytesToHex(randomBytes(32));
}
export default {
    deriveKey,
    deriveKeyHex,
    encrypt,
    encryptWithSecret,
    decrypt,
    decryptToString,
    decryptToJson,
    decryptWithSecret,
    generateRandomBytes,
    generateRandomHex,
    generateKey,
    generateKeyHex,
};
//# sourceMappingURL=symmetric.js.map