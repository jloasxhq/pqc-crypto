/**
 * @quxtech/pqc-crypto - Hash Utilities Module (v2.0)
 * ============================================================================
 * SHA-3 hash functions (NIST FIPS 202).
 *
 * v2.0 changes:
 * - keccak256 / keccak512 now throw if FIPS mode is enabled (Keccak uses
 *   different padding than SHA-3 and is NOT covered by FIPS 202).
 * ============================================================================
 */
import { sha3_256, sha3_512, keccak_256, keccak_512 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { assertApprovedAlgorithm } from '../core/fips.js';

function toBytes(data) {
    if (data instanceof Uint8Array) return data;
    if (typeof data === 'string' && data.startsWith('0x')) return hexToBytes(data.slice(2));
    return utf8ToBytes(data);
}

export function sha3256(data) {
    return bytesToHex(sha3_256(toBytes(data)));
}

export function sha3512(data) {
    return bytesToHex(sha3_512(toBytes(data)));
}

/**
 * Ethereum-style Keccak-256. NOT FIPS 202 (different padding).
 * Throws if FIPS mode is enabled.
 */
export function keccak256(data) {
    assertApprovedAlgorithm('Keccak-256');
    return bytesToHex(keccak_256(toBytes(data)));
}

/**
 * Keccak-512. NOT FIPS 202. Throws if FIPS mode is enabled.
 */
export function keccak512(data) {
    assertApprovedAlgorithm('Keccak-512');
    return bytesToHex(keccak_512(toBytes(data)));
}

export function sha3256Bytes(data) {
    return sha3_256(typeof data === 'string' ? utf8ToBytes(data) : data);
}

export function sha3512Bytes(data) {
    return sha3_512(typeof data === 'string' ? utf8ToBytes(data) : data);
}

export function hashMultiple(...values) {
    const combined = values.map(v => v instanceof Uint8Array ? bytesToHex(v) : v).join(':');
    return sha3256(combined);
}

export function hashObject(data) {
    const sortedKeys = Object.keys(data).sort();
    const values = sortedKeys.map(k => `${k}=${JSON.stringify(data[k])}`);
    return sha3256(values.join('&'));
}

export function fingerprint(data) {
    return sha3256(data).slice(0, 32);
}

export function verifyHash(data, expectedHash) {
    return sha3256(data).toLowerCase() === expectedHash.toLowerCase();
}

export default {
    sha3256,
    sha3512,
    keccak256,
    keccak512,
    sha3256Bytes,
    sha3512Bytes,
    hashMultiple,
    hashObject,
    fingerprint,
    verifyHash,
};
