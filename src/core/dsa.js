/**
 * @quxtech/pqc-crypto - Digital Signature Module (ML-DSA / CRYSTALS-Dilithium)
 * ============================================================================
 * Implements NIST FIPS 204 ML-DSA for post-quantum digital signatures.
 *
 * Supported algorithms:
 * - ML-DSA-65 (NIST Security Level 3, ~AES-192)
 * - ML-DSA-87 (NIST Security Level 5, ~AES-256)
 *
 * v2.0 changes:
 * - Pair-wise consistency check on every keypair generation (sign->verify
 *   smoke test plus tampered-message negative test).
 * - Approved-mode error-state check at the entry of every public function.
 * ============================================================================
 */
import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import { bytesToHex, hexToBytes, utf8ToBytes, randomBytes } from '@noble/hashes/utils';
import { checkErrorState } from './fips.js';
import { zeroize } from '../utils/zeroize.js';

const DSA_ALGORITHMS = {
    '3': ml_dsa65,
    '5': ml_dsa87,
};
const DSA_NAMES = {
    '3': 'ML-DSA-65',
    '5': 'ML-DSA-87',
};

const PAIRWISE_PROBE = utf8ToBytes('@quxtech/pqc-crypto pair-wise consistency probe');
const PAIRWISE_PROBE_TAMPER = utf8ToBytes('@quxtech/pqc-crypto pair-wise consistency probe!');

function pairwiseCheck(kp, dsaImpl, level) {
    const sig = dsaImpl.sign(kp.secretKey, PAIRWISE_PROBE);
    if (!dsaImpl.verify(kp.publicKey, PAIRWISE_PROBE, sig)) {
        zeroize(kp.secretKey);
        zeroize(kp.publicKey);
        zeroize(sig);
        throw new Error(`ML-DSA-${level === '5' ? '87' : '65'} pair-wise consistency failed at keygen`);
    }
    if (dsaImpl.verify(kp.publicKey, PAIRWISE_PROBE_TAMPER, sig)) {
        zeroize(kp.secretKey);
        zeroize(kp.publicKey);
        zeroize(sig);
        throw new Error(`ML-DSA-${level === '5' ? '87' : '65'} negative test failed at keygen`);
    }
    zeroize(sig);
}

export function generateKeyPair(securityLevel = '5') {
    checkErrorState();
    const dsaImpl = DSA_ALGORITHMS[securityLevel];
    if (!dsaImpl) throw new Error(`Unknown security level: ${securityLevel}`);
    const seed = randomBytes(32);
    const kp = dsaImpl.keygen(seed);
    zeroize(seed);
    pairwiseCheck(kp, dsaImpl, securityLevel);
    return kp;
}

export function generateKeyPairHex(securityLevel = '5') {
    const keyPair = generateKeyPair(securityLevel);
    return {
        publicKey: bytesToHex(keyPair.publicKey),
        secretKey: bytesToHex(keyPair.secretKey),
    };
}

export function sign(message, secretKey, securityLevel = '5') {
    checkErrorState();
    const dsaImpl = DSA_ALGORITHMS[securityLevel];
    if (!dsaImpl) throw new Error(`Unknown security level: ${securityLevel}`);
    const msg = typeof message === 'string' ? utf8ToBytes(message) : message;
    const sk = typeof secretKey === 'string' ? hexToBytes(secretKey) : secretKey;
    const signature = dsaImpl.sign(sk, msg);
    return bytesToHex(signature);
}

export function verify(message, signature, publicKey, securityLevel = '5') {
    checkErrorState();
    const dsaImpl = DSA_ALGORITHMS[securityLevel];
    if (!dsaImpl) return false;
    const msg = typeof message === 'string' ? utf8ToBytes(message) : message;
    const sig = typeof signature === 'string' ? hexToBytes(signature) : signature;
    const pk = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
    try {
        return dsaImpl.verify(pk, msg, sig);
    } catch {
        return false;
    }
}

export function signWithTimestamp(data, secretKey, securityLevel = '5') {
    const timestamp = Date.now();
    const dataStr = typeof data === 'string' ? data : bytesToHex(data);
    const message = `${dataStr}:${timestamp}`;
    const signature = sign(message, secretKey, securityLevel);
    return { signature, timestamp };
}

export function verifyWithTimestamp(data, signature, timestamp, publicKey, maxAgeMs = 300000, securityLevel = '5') {
    const age = Date.now() - timestamp;
    if (age > maxAgeMs) {
        return { valid: false, error: 'Signature expired' };
    }
    if (age < -30000) {
        return { valid: false, error: 'Signature timestamp in future' };
    }
    const dataStr = typeof data === 'string' ? data : bytesToHex(data);
    const message = `${dataStr}:${timestamp}`;
    const valid = verify(message, signature, publicKey, securityLevel);
    if (!valid) {
        return { valid: false, error: 'Invalid signature' };
    }
    return { valid: true };
}

export function getAlgorithmName(securityLevel = '5') {
    return DSA_NAMES[securityLevel];
}

export function getPublicKeySize(securityLevel = '5') {
    return securityLevel === '5' ? 2592 : 1952;
}

export function getSecretKeySize(securityLevel = '5') {
    return securityLevel === '5' ? 4896 : 4032;
}

export function getSignatureSize(securityLevel = '5') {
    return securityLevel === '5' ? 4627 : 3309;
}

export default {
    generateKeyPair,
    generateKeyPairHex,
    sign,
    verify,
    signWithTimestamp,
    verifyWithTimestamp,
    getAlgorithmName,
    getPublicKeySize,
    getSecretKeySize,
    getSignatureSize,
};
