/**
 * @quxtech/pqc-crypto - Key Encapsulation Module (ML-KEM / CRYSTALS-Kyber)
 * ============================================================================
 * Implements NIST FIPS 203 ML-KEM for post-quantum key encapsulation.
 *
 * Supported algorithms:
 * - ML-KEM-768  (NIST Security Level 3, ~AES-192)
 * - ML-KEM-1024 (NIST Security Level 5, ~AES-256)
 *
 * v2.0 changes:
 * - Pair-wise consistency check on every keypair generation. If a freshly
 *   generated keypair fails encapsulate/decapsulate round-trip the call
 *   throws and returns no key material to the caller.
 * - Approved-mode error-state check at the entry of every public function.
 * ============================================================================
 */
import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import { checkErrorState } from './fips.js';
import { constantTimeEqual, zeroize } from '../utils/zeroize.js';

const KEM_ALGORITHMS = {
    '3': ml_kem768,
    '5': ml_kem1024,
};
const KEM_NAMES = {
    '3': 'ML-KEM-768',
    '5': 'ML-KEM-1024',
};

/**
 * Internal: pair-wise consistency check after keygen. Throws if the generated
 * keypair does not encapsulate-decapsulate cleanly (FIPS 140-3 conditional
 * test on asymmetric keypair generation).
 */
function pairwiseCheck(kp, kemImpl, level) {
    const { cipherText, sharedSecret } = kemImpl.encapsulate(kp.publicKey);
    const recovered = kemImpl.decapsulate(cipherText, kp.secretKey);
    const ok = constantTimeEqual(sharedSecret, recovered);
    zeroize(sharedSecret);
    zeroize(recovered);
    zeroize(cipherText);
    if (!ok) {
        // The keypair is suspect — burn it and refuse to return.
        zeroize(kp.secretKey);
        zeroize(kp.publicKey);
        throw new Error(`ML-KEM-${level === '5' ? '1024' : '768'} pair-wise consistency failed at keygen`);
    }
}

export function generateKeyPair(securityLevel = '5') {
    checkErrorState();
    const kemImpl = KEM_ALGORITHMS[securityLevel];
    if (!kemImpl) throw new Error(`Unknown security level: ${securityLevel}`);
    const seed = randomBytes(64);
    const kp = kemImpl.keygen(seed);
    zeroize(seed);
    pairwiseCheck(kp, kemImpl, securityLevel);
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
    const kemImpl = KEM_ALGORITHMS[securityLevel];
    if (!kemImpl) throw new Error(`Unknown security level: ${securityLevel}`);
    const publicKey = typeof recipientPublicKey === 'string'
        ? hexToBytes(recipientPublicKey)
        : recipientPublicKey;
    const { cipherText, sharedSecret } = kemImpl.encapsulate(publicKey);
    return {
        ciphertext: bytesToHex(cipherText),
        sharedSecret: bytesToHex(sharedSecret),
    };
}

export function decapsulate(ciphertext, secretKey, securityLevel = '5') {
    checkErrorState();
    const kemImpl = KEM_ALGORITHMS[securityLevel];
    if (!kemImpl) throw new Error(`Unknown security level: ${securityLevel}`);
    const ct = typeof ciphertext === 'string' ? hexToBytes(ciphertext) : ciphertext;
    const sk = typeof secretKey === 'string' ? hexToBytes(secretKey) : secretKey;
    const sharedSecret = kemImpl.decapsulate(ct, sk);
    return bytesToHex(sharedSecret);
}

export function getAlgorithmName(securityLevel = '5') {
    return KEM_NAMES[securityLevel];
}

export function getPublicKeySize(securityLevel = '5') {
    return securityLevel === '5' ? 1568 : 1184;
}

export function getSecretKeySize(securityLevel = '5') {
    return securityLevel === '5' ? 3168 : 2400;
}

export function getCiphertextSize(securityLevel = '5') {
    return securityLevel === '5' ? 1568 : 1088;
}

export function getSharedSecretSize() {
    return 32;
}

export default {
    generateKeyPair,
    generateKeyPairHex,
    encapsulate,
    decapsulate,
    getAlgorithmName,
    getPublicKeySize,
    getSecretKeySize,
    getCiphertextSize,
    getSharedSecretSize,
};
