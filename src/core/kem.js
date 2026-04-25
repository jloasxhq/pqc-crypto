/**
 * @quxtech/pqc-crypto - Key Encapsulation Module (ML-KEM / CRYSTALS-Kyber)
 * ============================================================================
 * Implements NIST FIPS 203 ML-KEM via the active PqcProvider.
 *
 * All cryptographic operations are delegated to getProvider() so that
 * integrators can swap in a FIPS-validated backend without touching
 * call-sites.
 * ============================================================================
 */
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { getProvider } from './provider.js';
import { checkErrorState } from './fips.js';
import { constantTimeEqual, zeroize } from '../utils/zeroize.js';

const KEM_NAMES = { '3': 'ML-KEM-768', '5': 'ML-KEM-1024' };

/**
 * Internal: pair-wise consistency check (FIPS 140-3 conditional self-test
 * on asymmetric keypair generation).
 */
function pairwiseCheck(kp, level) {
    const p = getProvider();
    const { ciphertext, sharedSecret } = p.kemEncapsulate(kp.publicKey, level);
    const recovered = p.kemDecapsulate(ciphertext, kp.secretKey, level);
    const ok = constantTimeEqual(sharedSecret, recovered);
    zeroize(sharedSecret);
    zeroize(recovered);
    zeroize(ciphertext);
    if (!ok) {
        zeroize(kp.secretKey);
        zeroize(kp.publicKey);
        throw new Error(`${KEM_NAMES[level]} pair-wise consistency failed at keygen`);
    }
}

export function generateKeyPair(securityLevel = '5') {
    checkErrorState();
    const kp = getProvider().kemKeygen(securityLevel);
    pairwiseCheck(kp, securityLevel);
    return kp;
}

export function generateKeyPairHex(securityLevel = '5') {
    const keyPair = generateKeyPair(securityLevel);
    return {
        publicKey: bytesToHex(keyPair.publicKey),
        secretKey: bytesToHex(keyPair.secretKey),
    };
}

export function encapsulate(recipientPublicKey, securityLevel = '5') {
    checkErrorState();
    const pk = typeof recipientPublicKey === 'string' ? hexToBytes(recipientPublicKey) : recipientPublicKey;
    const out = getProvider().kemEncapsulate(pk, securityLevel);
    return {
        ciphertext: bytesToHex(out.ciphertext),
        sharedSecret: bytesToHex(out.sharedSecret),
    };
}

export function decapsulate(ciphertext, secretKey, securityLevel = '5') {
    checkErrorState();
    const ct = typeof ciphertext === 'string' ? hexToBytes(ciphertext) : ciphertext;
    const sk = typeof secretKey === 'string' ? hexToBytes(secretKey) : secretKey;
    const ss = getProvider().kemDecapsulate(ct, sk, securityLevel);
    return bytesToHex(ss);
}

export function getAlgorithmName(securityLevel = '5') {
    return KEM_NAMES[securityLevel];
}

export function getPublicKeySize(level = '5') { return level === '5' ? 1568 : 1184; }
export function getSecretKeySize(level = '5') { return level === '5' ? 3168 : 2400; }
export function getCiphertextSize(level = '5') { return level === '5' ? 1568 : 1088; }
export function getSharedSecretSize() { return 32; }

export default {
    generateKeyPair, generateKeyPairHex, encapsulate, decapsulate,
    getAlgorithmName, getPublicKeySize, getSecretKeySize, getCiphertextSize, getSharedSecretSize,
};
