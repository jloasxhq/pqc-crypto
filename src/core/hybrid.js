/**
 * @quxtech/pqc-crypto - Hybrid KEM (v2.0)
 * ============================================================================
 * Hybrid post-quantum + classical key encapsulation per NIST SP 800-56C
 * Rev 2 (HKDF-based combiner). Supports two classical curves:
 *   - X25519  (RFC 7748; widely deployed; not in FIPS 186-5)
 *   - P-384   (NIST FIPS 186-5; CNSA 2.0 / TLS 1.3 negotiable)
 *
 * Pair the classical curve with one ML-KEM parameter set:
 *   - Level 3: ML-KEM-768 + X25519        ≈ TLS 1.3 X25519MLKEM768
 *   - Level 3: ML-KEM-768 + ECDH-P-384    ≈ CNSA 2.0 transitional
 *   - Level 5: ML-KEM-1024 + ECDH-P-384   ≈ CNSA 2.0 strict
 *
 * Combiner (SP 800-56C Rev 2 §4.2 KDF-with-concatenated-Z):
 *   shared_secret = HKDF-SHA3-256(ikm = ss_classical || ss_pqc,
 *                                 salt = SUITE_LABEL,
 *                                 info = "PQC_HYBRID_v1",
 *                                 length = 32)
 * The classical concatenation order matches IETF
 * draft-ietf-tls-hybrid-design (classical first, PQC second). Suite label
 * provides domain separation across (curve, level) combinations.
 * ============================================================================
 */

import { getProvider } from './provider.js';
import { checkErrorState } from './fips.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { zeroize } from '../utils/zeroize.js';

const SUITE_LABELS = {
    'X25519+ML-KEM-768':   'qux-hybrid-x25519-mlkem768-v1',
    'X25519+ML-KEM-1024':  'qux-hybrid-x25519-mlkem1024-v1',
    'P-384+ML-KEM-768':    'qux-hybrid-p384-mlkem768-v1',
    'P-384+ML-KEM-1024':   'qux-hybrid-p384-mlkem1024-v1',
};

const HKDF_INFO = utf8ToBytes('PQC_HYBRID_v1');
const COMBINED_SECRET_BYTES = 32;

function suiteLabel(classicalCurve, pqcLevel) {
    const pqcName = pqcLevel === '5' ? 'ML-KEM-1024' : 'ML-KEM-768';
    const key = `${classicalCurve}+${pqcName}`;
    const label = SUITE_LABELS[key];
    if (!label) throw new Error(`Unsupported hybrid suite: ${key}`);
    return utf8ToBytes(label);
}

function combine(ssClassical, ssPqc, classicalCurve, pqcLevel) {
    const ikm = new Uint8Array(ssClassical.length + ssPqc.length);
    ikm.set(ssClassical);
    ikm.set(ssPqc, ssClassical.length);
    const salt = suiteLabel(classicalCurve, pqcLevel);
    const out = getProvider().hkdfSha3_256(ikm, salt, HKDF_INFO, COMBINED_SECRET_BYTES);
    zeroize(ikm);
    return out;
}

/**
 * Generate a hybrid keypair: a classical ECDH keypair + an ML-KEM keypair.
 *
 * @param {'X25519'|'P-384'} classicalCurve
 * @param {'3'|'5'} pqcLevel
 * @returns {{ classical: {publicKey, secretKey}, pqc: {publicKey, secretKey},
 *            algorithm: {classical: string, pqc: string} }}
 */
export function generateKeyPair(classicalCurve = 'X25519', pqcLevel = '5') {
    checkErrorState();
    const p = getProvider();
    const classical = p.ecdhKeygen(classicalCurve);
    const pqc = p.kemKeygen(pqcLevel);
    return {
        classical,
        pqc,
        algorithm: {
            classical: classicalCurve,
            pqc: pqcLevel === '5' ? 'ML-KEM-1024' : 'ML-KEM-768',
            suite: `${classicalCurve}+${pqcLevel === '5' ? 'ML-KEM-1024' : 'ML-KEM-768'}`,
        },
    };
}

/**
 * Hex-encoded variant of generateKeyPair() for callers that want to
 * round-trip through JSON.
 */
export function generateKeyPairHex(classicalCurve = 'X25519', pqcLevel = '5') {
    const kp = generateKeyPair(classicalCurve, pqcLevel);
    return {
        classical: {
            publicKey: bytesToHex(kp.classical.publicKey),
            secretKey: bytesToHex(kp.classical.secretKey),
        },
        pqc: {
            publicKey: bytesToHex(kp.pqc.publicKey),
            secretKey: bytesToHex(kp.pqc.secretKey),
        },
        algorithm: kp.algorithm,
    };
}

/**
 * Encapsulate a hybrid shared secret to a recipient. Returns the
 * ephemeral classical public key, the PQC ciphertext, and the combined
 * 32-byte shared secret (hex-encoded).
 *
 * @param {string|Uint8Array} classicalPk - recipient's classical public key
 * @param {string|Uint8Array} pqcPk - recipient's ML-KEM public key
 * @param {'X25519'|'P-384'} classicalCurve
 * @param {'3'|'5'} pqcLevel
 */
export function encapsulate(classicalPk, pqcPk, classicalCurve = 'X25519', pqcLevel = '5') {
    checkErrorState();
    const p = getProvider();
    const cPk = typeof classicalPk === 'string' ? hexToBytes(classicalPk) : classicalPk;
    const qPk = typeof pqcPk === 'string' ? hexToBytes(pqcPk) : pqcPk;

    const cOut = p.ecdhEncapsulate(cPk, classicalCurve);
    const qOut = p.kemEncapsulate(qPk, pqcLevel);

    const combined = combine(cOut.sharedSecret, qOut.sharedSecret, classicalCurve, pqcLevel);

    // Burn the per-leg shared secrets — only the combined output matters.
    zeroize(cOut.sharedSecret);
    zeroize(qOut.sharedSecret);

    return {
        classicalEphemeralPublicKey: bytesToHex(cOut.ephemeralPublicKey),
        pqcCiphertext: bytesToHex(qOut.ciphertext),
        sharedSecret: bytesToHex(combined),
        suite: `${classicalCurve}+${pqcLevel === '5' ? 'ML-KEM-1024' : 'ML-KEM-768'}`,
    };
}

/**
 * Decapsulate a hybrid shared secret using the recipient's secret keys.
 *
 * @param {string|Uint8Array} classicalEphemeralPk - sender's ephemeral public key
 * @param {string|Uint8Array} pqcCt - the PQC ciphertext
 * @param {string|Uint8Array} classicalSk - recipient's classical secret key
 * @param {string|Uint8Array} pqcSk - recipient's ML-KEM secret key
 * @param {'X25519'|'P-384'} classicalCurve
 * @param {'3'|'5'} pqcLevel
 * @returns hex-encoded combined shared secret (32 bytes)
 */
export function decapsulate(classicalEphemeralPk, pqcCt, classicalSk, pqcSk,
                            classicalCurve = 'X25519', pqcLevel = '5') {
    checkErrorState();
    const p = getProvider();
    const cEphemPk = typeof classicalEphemeralPk === 'string' ? hexToBytes(classicalEphemeralPk) : classicalEphemeralPk;
    const qCt = typeof pqcCt === 'string' ? hexToBytes(pqcCt) : pqcCt;
    const cSk = typeof classicalSk === 'string' ? hexToBytes(classicalSk) : classicalSk;
    const qSk = typeof pqcSk === 'string' ? hexToBytes(pqcSk) : pqcSk;

    const ssClassical = p.ecdhDecapsulate(cEphemPk, cSk, classicalCurve);
    const ssPqc = p.kemDecapsulate(qCt, qSk, pqcLevel);

    const combined = combine(ssClassical, ssPqc, classicalCurve, pqcLevel);

    zeroize(ssClassical);
    zeroize(ssPqc);

    return bytesToHex(combined);
}

/**
 * Get the suite label string for a hybrid combination — useful for
 * logging, dashboards, and TLS-style negotiation.
 */
export function getSuiteName(classicalCurve, pqcLevel) {
    return `${classicalCurve}+${pqcLevel === '5' ? 'ML-KEM-1024' : 'ML-KEM-768'}`;
}

export default {
    generateKeyPair,
    generateKeyPairHex,
    encapsulate,
    decapsulate,
    getSuiteName,
};
