/**
 * @quxtech/pqc-crypto - Power-on Self-Tests + Pair-wise Consistency (v2.0)
 * ============================================================================
 * Implements:
 * - Power-on KAT for SHA3-256 and SHA3-512 (NIST FIPS 202 sample vectors)
 * - Round-trip self-consistency for AES-256-GCM and HKDF-SHA3-256
 * - Pair-wise consistency checks for ML-KEM and ML-DSA keygen + negative test
 *
 * Triggered automatically on first setFipsMode(true). Available manually
 * via runSelfTests().
 *
 * KAT scope (v2.0): minimal set targeting "no broken-on-arrival" regressions.
 * Full NIST CAVP suites (ACVP) are on the v2.x roadmap (backlog F-01 long
 * tail) and require checked-in vector files which are out of scope for this
 * release. The vectors below are sufficient to detect implementation drift
 * if @noble/* dependencies are tampered with or replaced.
 *
 * On any failure, _enterErrorState() is invoked and the module refuses
 * subsequent crypto ops in approved mode.
 * ============================================================================
 */

import { sha3_256, sha3_512 } from '@noble/hashes/sha3';
import { hkdf } from '@noble/hashes/hkdf';
import { gcm } from '@noble/ciphers/aes';
import { bytesToHex, hexToBytes, utf8ToBytes, randomBytes } from '@noble/hashes/utils';
import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem';
import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import {
    _registerSelfTestRunner,
    _markSelfTestPassed,
    _enterErrorState,
} from './fips.js';
import { constantTimeEqual } from '../utils/zeroize.js';

// =============================================================================
// SHA-3 KAT (NIST FIPS 202 sample vectors — empty input + "abc")
// =============================================================================

const SHA3_KAT = [
    {
        algo: 'SHA3-256',
        fn: sha3_256,
        input: new Uint8Array(0),
        expected: 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
    },
    {
        algo: 'SHA3-256',
        fn: sha3_256,
        input: utf8ToBytes('abc'),
        expected: '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
    },
    {
        algo: 'SHA3-512',
        fn: sha3_512,
        input: new Uint8Array(0),
        expected:
            'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
    },
];

function runSha3Kat() {
    for (const v of SHA3_KAT) {
        const got = bytesToHex(v.fn(v.input));
        if (got !== v.expected) {
            throw new Error(`${v.algo} KAT failed: got ${got} expected ${v.expected}`);
        }
    }
}

// =============================================================================
// HKDF-SHA3-256 round-trip self-consistency
// =============================================================================

function runHkdfRoundtrip() {
    const ikm = utf8ToBytes('@quxtech selftest ikm');
    const salt = utf8ToBytes('@quxtech selftest salt');
    const info = utf8ToBytes('@quxtech selftest info');
    const out1 = hkdf(sha3_256, ikm, salt, info, 32);
    const out2 = hkdf(sha3_256, ikm, salt, info, 32);
    if (!constantTimeEqual(out1, out2)) {
        throw new Error('HKDF-SHA3-256 not deterministic');
    }
    if (out1.length !== 32) {
        throw new Error(`HKDF-SHA3-256 length mismatch: ${out1.length}`);
    }
}

// =============================================================================
// AES-256-GCM round-trip self-consistency
// =============================================================================

function runAesGcmRoundtrip() {
    const key = randomBytes(32);
    const nonce = randomBytes(12);
    const aad = utf8ToBytes('@quxtech aad');
    const plaintext = utf8ToBytes('@quxtech selftest plaintext that is at least one block long.');

    const enc = gcm(key, nonce, aad);
    const ciphertext = enc.encrypt(plaintext);
    if (constantTimeEqual(ciphertext, plaintext)) {
        throw new Error('AES-256-GCM produced plaintext-equal output');
    }
    const dec = gcm(key, nonce, aad);
    const decrypted = dec.decrypt(ciphertext);
    if (!constantTimeEqual(decrypted, plaintext)) {
        throw new Error('AES-256-GCM round-trip mismatch');
    }
    // Tamper test: flipping a ciphertext bit must cause decrypt to throw
    const tampered = new Uint8Array(ciphertext);
    tampered[0] ^= 1;
    let tamperRejected = false;
    try {
        const dec2 = gcm(key, nonce, aad);
        dec2.decrypt(tampered);
    } catch {
        tamperRejected = true;
    }
    if (!tamperRejected) {
        throw new Error('AES-256-GCM accepted tampered ciphertext');
    }
}

// =============================================================================
// ML-KEM pair-wise consistency
// =============================================================================

function runMlKemPairwise() {
    for (const [name, kem] of [['ml-kem-768', ml_kem768], ['ml-kem-1024', ml_kem1024]]) {
        const seed = new Uint8Array(64);
        for (let i = 0; i < 64; i++) seed[i] = i;
        const kp = kem.keygen(seed);
        const { cipherText, sharedSecret } = kem.encapsulate(kp.publicKey);
        const recovered = kem.decapsulate(cipherText, kp.secretKey);
        if (!constantTimeEqual(sharedSecret, recovered)) {
            throw new Error(`${name} pair-wise consistency failed`);
        }
    }
}

// =============================================================================
// ML-DSA pair-wise consistency + negative test
// =============================================================================

function runMlDsaPairwise() {
    for (const [name, dsa] of [['ml-dsa-65', ml_dsa65], ['ml-dsa-87', ml_dsa87]]) {
        const seed = new Uint8Array(32);
        for (let i = 0; i < 32; i++) seed[i] = i;
        const kp = dsa.keygen(seed);
        const message = utf8ToBytes('@quxtech/pqc-crypto self-test');
        const sig = dsa.sign(kp.secretKey, message);
        if (!dsa.verify(kp.publicKey, message, sig)) {
            throw new Error(`${name} pair-wise consistency failed`);
        }
        const tampered = utf8ToBytes('@quxtech/pqc-crypto self-test!');
        if (dsa.verify(kp.publicKey, tampered, sig)) {
            throw new Error(`${name} negative test failed (accepted bad signature)`);
        }
    }
}

/**
 * Run all power-on self-tests. Throws and enters error state on any failure.
 * Idempotent — safe to call multiple times.
 */
export function runSelfTests() {
    try {
        runSha3Kat();
        runHkdfRoundtrip();
        runAesGcmRoundtrip();
        runMlKemPairwise();
        runMlDsaPairwise();
        _markSelfTestPassed();
    } catch (err) {
        _enterErrorState(err);
        throw err;
    }
}

// Wire into fips.js so setFipsMode(true) can trigger us without circular import.
_registerSelfTestRunner(runSelfTests);

export default {
    runSelfTests,
};
