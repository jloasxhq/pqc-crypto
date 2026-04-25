/**
 * @quxtech/pqc-crypto - Post-Quantum Cryptography Library (v2.0)
 * ============================================================================
 * NOT FIPS 140-3 validated. FIPS-aligned with opt-in approved-mode gating
 * and a PqcProvider abstraction for future delegation to validated backends.
 * See SECURITY.md for the full validation-status statement.
 * ============================================================================
 */

// Core
export * as kem from './core/kem.js';
export * as dsa from './core/dsa.js';
export * as symmetric from './core/symmetric.js';
export * as keys from './core/keys.js';
export * as session from './core/session.js';
export * as voip from './core/voip.js';
export * as hybrid from './core/hybrid.js';
export * as fips from './core/fips.js';
export * as selftest from './core/selftest.js';
export * as provider from './core/provider.js';

// Utility
export * as hash from './utils/hash.js';
export * as zeroize from './utils/zeroize.js';
export * as metrics from './utils/metrics.js';

import * as kemModule from './core/kem.js';
import * as dsaModule from './core/dsa.js';
import * as symmetricModule from './core/symmetric.js';
import * as keysModule from './core/keys.js';
import * as sessionModule from './core/session.js';
import * as voipModule from './core/voip.js';
import * as hybridModule from './core/hybrid.js';
import * as fipsModule from './core/fips.js';
import * as selftestModule from './core/selftest.js';
import * as providerModule from './core/provider.js';
import * as hashModule from './utils/hash.js';
import * as zeroizeModule from './utils/zeroize.js';
import * as metricsModule from './utils/metrics.js';

// Wire provider-change hook into fips.js so that swapping the provider
// resets the self-test gate (matches FIPS 140-3 module-state semantics).
providerModule._onProviderChange(() => fipsModule._onProviderReset());

// Top-level convenience re-exports
export const { setFipsMode, isFipsMode } = fipsModule;
export const { runSelfTests } = selftestModule;
export const { setProvider, getProvider } = providerModule;
export const { initMetrics, metricsHandler } = metricsModule;

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
    if (!dsaModule.verify(signatureData, payload.signature, senderDsaPublicKey, securityLevel)) {
        throw new Error('Signature verification failed');
    }
    const sharedSecret = kemModule.decapsulate(payload.kemCiphertext, recipientKemSecretKey, securityLevel);
    return symmetricModule.decryptWithSecret(payload.encryptedData, sharedSecret);
}

export function getAlgorithmInfo(securityLevel = '5') {
    const p = providerModule.getProvider();
    return {
        kem: kemModule.getAlgorithmName(securityLevel),
        dsa: dsaModule.getAlgorithmName(securityLevel),
        symmetric: 'AES-256-GCM',
        hash: 'SHA3-256/512',
        kdf: 'PBKDF2-HMAC-SHA-256 (passphrase wrap), HKDF-SHA3-256 (KEM secret)',
        hybridSuites: [
            'X25519+ML-KEM-768', 'X25519+ML-KEM-1024',
            'P-384+ML-KEM-768', 'P-384+ML-KEM-1024',
        ],
        securityLevel,
        nistFips: ['FIPS 203', 'FIPS 204', 'FIPS 202', 'SP 800-132', 'SP 800-56C Rev 2'],
        library: '@quxtech/pqc-crypto@2.0.0',
        fipsValidated: p.isFipsValidated,
        fipsCertNumber: p.fipsCertNumber || null,
        fipsModeEnabled: fipsModule.isFipsMode(),
        provider: p.name,
    };
}

export function computeHash(data) { return hashModule.sha3256(data); }

export default {
    kem: kemModule.default,
    dsa: dsaModule.default,
    symmetric: symmetricModule.default,
    keys: keysModule.default,
    session: sessionModule.default,
    voip: voipModule.default,
    hybrid: hybridModule.default,
    hash: hashModule.default,
    fips: fipsModule.default,
    selftest: selftestModule.default,
    provider: providerModule.default,
    zeroize: zeroizeModule.default,
    metrics: metricsModule.default,
    setFipsMode: fipsModule.setFipsMode,
    isFipsMode: fipsModule.isFipsMode,
    runSelfTests: selftestModule.runSelfTests,
    setProvider: providerModule.setProvider,
    getProvider: providerModule.getProvider,
    initMetrics: metricsModule.initMetrics,
    metricsHandler: metricsModule.metricsHandler,
    generateKeyPairs,
    quickEncapsulate,
    quickDecapsulate,
    encryptAndSign,
    verifyAndDecrypt,
    getAlgorithmInfo,
    computeHash,
};
