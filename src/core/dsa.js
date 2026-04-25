/**
 * @quxtech/pqc-crypto - Digital Signature Module (ML-DSA / CRYSTALS-Dilithium)
 * ============================================================================
 * Implements NIST FIPS 204 ML-DSA via the active PqcProvider.
 * ============================================================================
 */
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { getProvider } from './provider.js';
import { checkErrorState } from './fips.js';
import { zeroize } from '../utils/zeroize.js';

const DSA_NAMES = { '3': 'ML-DSA-65', '5': 'ML-DSA-87' };
const PAIRWISE_PROBE = utf8ToBytes('@quxtech/pqc-crypto pair-wise consistency probe');
const PAIRWISE_PROBE_TAMPER = utf8ToBytes('@quxtech/pqc-crypto pair-wise consistency probe!');

function pairwiseCheck(kp, level) {
    const p = getProvider();
    const sig = p.dsaSign(PAIRWISE_PROBE, kp.secretKey, level);
    const ok = p.dsaVerify(PAIRWISE_PROBE, sig, kp.publicKey, level);
    if (!ok) {
        zeroize(kp.secretKey); zeroize(kp.publicKey); zeroize(sig);
        throw new Error(`${DSA_NAMES[level]} pair-wise consistency failed at keygen`);
    }
    const tamperOk = p.dsaVerify(PAIRWISE_PROBE_TAMPER, sig, kp.publicKey, level);
    if (tamperOk) {
        zeroize(kp.secretKey); zeroize(kp.publicKey); zeroize(sig);
        throw new Error(`${DSA_NAMES[level]} negative test failed at keygen`);
    }
    zeroize(sig);
}

export function generateKeyPair(securityLevel = '5') {
    checkErrorState();
    const kp = getProvider().dsaKeygen(securityLevel);
    pairwiseCheck(kp, securityLevel);
    return kp;
}

export function generateKeyPairHex(securityLevel = '5') {
    const kp = generateKeyPair(securityLevel);
    return { publicKey: bytesToHex(kp.publicKey), secretKey: bytesToHex(kp.secretKey) };
}

export function sign(message, secretKey, securityLevel = '5') {
    checkErrorState();
    const msg = typeof message === 'string' ? utf8ToBytes(message) : message;
    const sk = typeof secretKey === 'string' ? hexToBytes(secretKey) : secretKey;
    return bytesToHex(getProvider().dsaSign(msg, sk, securityLevel));
}

export function verify(message, signature, publicKey, securityLevel = '5') {
    checkErrorState();
    const msg = typeof message === 'string' ? utf8ToBytes(message) : message;
    const sig = typeof signature === 'string' ? hexToBytes(signature) : signature;
    const pk = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
    return getProvider().dsaVerify(msg, sig, pk, securityLevel);
}

export function signWithTimestamp(data, secretKey, securityLevel = '5') {
    const timestamp = Date.now();
    const dataStr = typeof data === 'string' ? data : bytesToHex(data);
    const message = `${dataStr}:${timestamp}`;
    return { signature: sign(message, secretKey, securityLevel), timestamp };
}

export function verifyWithTimestamp(data, signature, timestamp, publicKey, maxAgeMs = 300000, securityLevel = '5') {
    const age = Date.now() - timestamp;
    if (age > maxAgeMs) return { valid: false, error: 'Signature expired' };
    if (age < -30000) return { valid: false, error: 'Signature timestamp in future' };
    const dataStr = typeof data === 'string' ? data : bytesToHex(data);
    const message = `${dataStr}:${timestamp}`;
    if (!verify(message, signature, publicKey, securityLevel)) return { valid: false, error: 'Invalid signature' };
    return { valid: true };
}

export function getAlgorithmName(securityLevel = '5') { return DSA_NAMES[securityLevel]; }
export function getPublicKeySize(level = '5') { return level === '5' ? 2592 : 1952; }
export function getSecretKeySize(level = '5') { return level === '5' ? 4896 : 4032; }
export function getSignatureSize(level = '5') { return level === '5' ? 4627 : 3309; }

export default {
    generateKeyPair, generateKeyPairHex, sign, verify,
    signWithTimestamp, verifyWithTimestamp,
    getAlgorithmName, getPublicKeySize, getSecretKeySize, getSignatureSize,
};
