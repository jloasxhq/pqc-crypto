/**
 * @quxtech/pqc-crypto - Post-Quantum Cryptography Library (v2.0)
 * ============================================================================
 * A modular post-quantum cryptography library implementing:
 * - NIST FIPS 203 ML-KEM (CRYSTALS-Kyber) for key encapsulation
 * - NIST FIPS 204 ML-DSA (CRYSTALS-Dilithium) for digital signatures
 * - NIST FIPS 202 SHA-3 for hashing
 * - NIST SP 800-132 PBKDF2-HMAC-SHA-256 for passphrase-derived key wrapping
 * - AES-256-GCM for symmetric encryption
 *
 * IMPORTANT: This library is NOT FIPS 140-3 validated. Algorithm
 * implementations come from the @noble/* pure-JS family (audited by
 * Cure53). For an actual FIPS-validated deployment, future major versions
 * will introduce a PqcProvider abstraction that delegates approved-mode
 * operations to a validated backend (OpenSSL FIPS, BoringCrypto, PKCS#11).
 * See SECURITY.md and the v2.0 release notes for details.
 *
 * v2.0 highlights:
 * - Opt-in setFipsMode() with power-on self-tests + non-approved algorithm
 *   gating (Keccak)
 * - Pair-wise consistency on every keygen
 * - PBKDF2-HMAC-SHA-256 (FIPS-approved) for serialized key envelopes,
 *   replacing v1's HKDF passphrase wrap. v1 envelopes remain readable.
 * - Documented memory hygiene + best-effort zeroization helpers
 * ============================================================================
 */

// Core modules
export * as kem from './core/kem.js';
export * as dsa from './core/dsa.js';
export * as symmetric from './core/symmetric.js';
export * as keys from './core/keys.js';
export * as session from './core/session.js';
export * as voip from './core/voip.js';

// FIPS mode + self-tests (v2.0)
export * as fips from './core/fips.js';
export * as selftest from './core/selftest.js';

// Utility modules
export * as hash from './utils/hash.js';
export * as zeroize from './utils/zeroize.js';

import * as kemModule from './core/kem.js';
import * as dsaModule from './core/dsa.js';
import * as symmetricModule from './core/symmetric.js';
import * as keysModule from './core/keys.js';
import * as sessionModule from './core/session.js';
import * as voipModule from './core/voip.js';
import * as hashModule from './utils/hash.js';
import * as fipsModule from './core/fips.js';
import * as selftestModule from './core/selftest.js';
import * as zeroizeModule from './utils/zeroize.js';

// Top-level convenience re-exports
export const { setFipsMode, isFipsMode } = fipsModule;
export const { runSelfTests } = selftestModule;

export function generateKeyPairs(securityLevel = '5') {
    return {
        kem: kemModule.generateKeyPairHex(securityLevel),
        dsa: dsaModule.generateKeyPairHex(securityLevel),
        securityLevel,
        algorithm: {
            kem: kemModule.getAlgorithmName(securityLevel),
            dsa: dsaModule.getAlgorithmName(securityLevel),
        },
    };
}

export function quickEncapsulate(recipientKemPublicKey, securityLevel = '5') {
    const { ciphertext, sharedSecret } = kemModule.encapsulate(recipientKemPublicKey, securityLevel);
    const encryptionKey = symmetricModule.deriveKeyHex(sharedSecret);
    return { ciphertext, encryptionKey, sharedSecret };
}

export function quickDecapsulate(ciphertext, kemSecretKey, securityLevel = '5') {
    const sharedSecret = kemModule.decapsulate(ciphertext, kemSecretKey, securityLevel);
    const encryptionKey = symmetricModule.deriveKeyHex(sharedSecret);
    return { encryptionKey, sharedSecret };
}

export function encryptAndSign(data, recipientKemPublicKey, senderDsaSecretKey, securityLevel = '5') {
    const { ciphertext: kemCiphertext, sharedSecret } = kemModule.encapsulate(recipientKemPublicKey, securityLevel);
    const encrypted = symmetricModule.encryptWithSecret(data, sharedSecret);
    const signatureData = `${encrypted.nonce}:${encrypted.ciphertext}:${kemCiphertext}`;
    const signature = dsaModule.sign(signatureData, senderDsaSecretKey, securityLevel);
    return { kemCiphertext, encryptedData: encrypted, signature, timestamp: Date.now() };
}

export function verifyAndDecrypt(payload, senderDsaPublicKey, recipientKemSecretKey, securityLevel = '5') {
    const signatureData = `${payload.encryptedData.nonce}:${payload.encryptedData.ciphertext}:${payload.kemCiphertext}`;
    const valid = dsaModule.verify(signatureData, payload.signature, senderDsaPublicKey, securityLevel);
    if (!valid) {
        throw new Error('Signature verification failed');
    }
    const sharedSecret = kemModule.decapsulate(payload.kemCiphertext, recipientKemSecretKey, securityLevel);
    return symmetricModule.decryptWithSecret(payload.encryptedData, sharedSecret);
}

export function getAlgorithmInfo(securityLevel = '5') {
    return {
        kem: kemModule.getAlgorithmName(securityLevel),
        dsa: dsaModule.getAlgorithmName(securityLevel),
        symmetric: 'AES-256-GCM',
        hash: 'SHA3-256/512',
        kdf: 'PBKDF2-HMAC-SHA-256 (passphrase wrap), HKDF-SHA3-256 (KEM secret)',
        securityLevel,
        nistFips: ['FIPS 203', 'FIPS 204', 'FIPS 202', 'SP 800-132'],
        library: '@quxtech/pqc-crypto@2.0.0',
        fipsValidated: false,
        fipsModeEnabled: fipsModule.isFipsMode(),
    };
}

export function computeHash(data) {
    return hashModule.sha3256(data);
}

export default {
    kem: kemModule.default,
    dsa: dsaModule.default,
    symmetric: symmetricModule.default,
    keys: keysModule.default,
    session: sessionModule.default,
    voip: voipModule.default,
    hash: hashModule.default,
    fips: fipsModule.default,
    selftest: selftestModule.default,
    zeroize: zeroizeModule.default,
    setFipsMode: fipsModule.setFipsMode,
    isFipsMode: fipsModule.isFipsMode,
    runSelfTests: selftestModule.runSelfTests,
    generateKeyPairs,
    quickEncapsulate,
    quickDecapsulate,
    encryptAndSign,
    verifyAndDecrypt,
    getAlgorithmInfo,
    computeHash,
};
