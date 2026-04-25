/**
 * @quxtech/pqc-crypto - Hash Utilities Module (v2.0)
 * ============================================================================
 * SHA-3 hash functions (NIST FIPS 202) via the active PqcProvider.
 * Keccak variants are NOT delegated (provider abstraction is for FIPS-
 * approved algorithms only) and are gated by FIPS mode.
 * ============================================================================
 */
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { keccak_256, keccak_512 } from '@noble/hashes/sha3';
import { getProvider } from '../core/provider.js';
import { assertApprovedAlgorithm } from '../core/fips.js';

function toBytes(data) {
    if (data instanceof Uint8Array) return data;
    if (typeof data === 'string' && data.startsWith('0x')) return hexToBytes(data.slice(2));
    return utf8ToBytes(data);
}

export function sha3256(data) { return bytesToHex(getProvider().sha3_256(toBytes(data))); }
export function sha3512(data) { return bytesToHex(getProvider().sha3_512(toBytes(data))); }

export function keccak256(data) {
    assertApprovedAlgorithm('Keccak-256');
    return bytesToHex(keccak_256(toBytes(data)));
}
export function keccak512(data) {
    assertApprovedAlgorithm('Keccak-512');
    return bytesToHex(keccak_512(toBytes(data)));
}

export function sha3256Bytes(data) { return getProvider().sha3_256(typeof data === 'string' ? utf8ToBytes(data) : data); }
export function sha3512Bytes(data) { return getProvider().sha3_512(typeof data === 'string' ? utf8ToBytes(data) : data); }

export function hashMultiple(...values) {
    const combined = values.map(v => v instanceof Uint8Array ? bytesToHex(v) : v).join(':');
    return sha3256(combined);
}

export function hashObject(data) {
    const sortedKeys = Object.keys(data).sort();
    const values = sortedKeys.map(k => `${k}=${JSON.stringify(data[k])}`);
    return sha3256(values.join('&'));
}

export function fingerprint(data) { return sha3256(data).slice(0, 32); }

export function verifyHash(data, expectedHash) {
    return sha3256(data).toLowerCase() === expectedHash.toLowerCase();
}

export default {
    sha3256, sha3512, keccak256, keccak512,
    sha3256Bytes, sha3512Bytes,
    hashMultiple, hashObject, fingerprint, verifyHash,
};
