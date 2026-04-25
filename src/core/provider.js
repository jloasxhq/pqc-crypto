/**
 * @quxtech/pqc-crypto - PqcProvider Abstraction (v2.0)
 * ============================================================================
 * Pluggable provider interface that lets approved-mode crypto operations be
 * delegated to a FIPS-validated backend. v2.0 ships with NobleProvider only
 * (the pure-JS path, NOT FIPS-validated). Future releases will add:
 *   - OpenSslProvider (Node OpenSSL 3.5+ FIPS provider once ML-KEM/ML-DSA
 *     land upstream)
 *   - BoringCryptoProvider (Google's FIPS 140-3 module)
 *   - WolfCryptProvider (WolfCrypt FIPS)
 *   - Pkcs11Provider (HSM delegation via PKCS#11 / softhsm2 / YubiHSM)
 *
 * To swap providers:
 *   import { setProvider } from '@quxtech/pqc-crypto/provider';
 *   import { OpenSslProvider } from '@quxtech/pqc-crypto-openssl';  // future
 *   setProvider(new OpenSslProvider({ fipsMode: true }));
 *
 * The active provider is consulted by every approved-mode entry point.
 * Switching providers mid-process is allowed but resets the FIPS-mode
 * self-test gate.
 * ============================================================================
 */

import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem';
import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import { gcm } from '@noble/ciphers/aes';
import { sha3_256, sha3_512 } from '@noble/hashes/sha3';
import { sha256 } from '@noble/hashes/sha2';
import { hkdf } from '@noble/hashes/hkdf';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { randomBytes } from '@noble/hashes/utils';
import { x25519 } from '@noble/curves/ed25519';
import { p384 } from '@noble/curves/p384';

/**
 * Abstract provider interface. Concrete subclasses MUST override every method.
 * The base implementations throw to surface incomplete subclasses early.
 */
export class PqcProvider {
    constructor() {
        this.name = 'abstract';
        this.isFipsValidated = false;
        this.fipsCertNumber = null;
    }

    // ─── KEM (ML-KEM) ────────────────────────────────────────────────────────
    kemKeygen(_level) { this._unimpl('kemKeygen'); }
    kemEncapsulate(_pk, _level) { this._unimpl('kemEncapsulate'); }
    kemDecapsulate(_ct, _sk, _level) { this._unimpl('kemDecapsulate'); }

    // ─── DSA (ML-DSA) ────────────────────────────────────────────────────────
    dsaKeygen(_level) { this._unimpl('dsaKeygen'); }
    dsaSign(_msg, _sk, _level) { this._unimpl('dsaSign'); }
    dsaVerify(_msg, _sig, _pk, _level) { this._unimpl('dsaVerify'); }

    // ─── ECDH (for hybrid KEM combiner) ──────────────────────────────────────
    ecdhKeygen(_curve) { this._unimpl('ecdhKeygen'); }
    ecdhEncapsulate(_pk, _curve) { this._unimpl('ecdhEncapsulate'); }
    ecdhDecapsulate(_ephemPk, _sk, _curve) { this._unimpl('ecdhDecapsulate'); }

    // ─── Hash ────────────────────────────────────────────────────────────────
    sha3_256(_data) { this._unimpl('sha3_256'); }
    sha3_512(_data) { this._unimpl('sha3_512'); }

    // ─── KDF ─────────────────────────────────────────────────────────────────
    hkdfSha3_256(_ikm, _salt, _info, _length) { this._unimpl('hkdfSha3_256'); }
    pbkdf2Sha256(_passphrase, _salt, _iterations, _length) { this._unimpl('pbkdf2Sha256'); }

    // ─── Symmetric (AES-256-GCM) ─────────────────────────────────────────────
    aesGcmEncrypt(_key, _nonce, _pt, _aad) { this._unimpl('aesGcmEncrypt'); }
    aesGcmDecrypt(_key, _nonce, _ct, _aad) { this._unimpl('aesGcmDecrypt'); }

    // ─── RNG ─────────────────────────────────────────────────────────────────
    randomBytes(_n) { this._unimpl('randomBytes'); }

    _unimpl(method) {
        throw new Error(`PqcProvider.${method}() not implemented in '${this.name}' provider`);
    }
}

/**
 * NobleProvider — default provider using the @noble/* family of pure-JS
 * implementations. NOT FIPS 140-3 validated. Suitable for development,
 * non-production use, and as a fallback when no validated backend is
 * available.
 */
export class NobleProvider extends PqcProvider {
    constructor() {
        super();
        this.name = 'noble';
        this.isFipsValidated = false;
        this.implVersions = {
            'noble-post-quantum': '^0.2.1',
            'noble-hashes': '^1.7.1',
            'noble-ciphers': '^1.2.1',
            'noble-curves': '^1.8.1',
        };
    }

    // ─── KEM ─────────────────────────────────────────────────────────────────
    _kemImpl(level) {
        if (level === '3') return ml_kem768;
        if (level === '5') return ml_kem1024;
        throw new Error(`Unknown KEM security level: ${level}`);
    }
    kemKeygen(level) {
        const seed = this.randomBytes(64);
        const kp = this._kemImpl(level).keygen(seed);
        seed.fill(0);
        return kp;
    }
    kemEncapsulate(pk, level) {
        const out = this._kemImpl(level).encapsulate(pk);
        return { ciphertext: out.cipherText, sharedSecret: out.sharedSecret };
    }
    kemDecapsulate(ct, sk, level) {
        return this._kemImpl(level).decapsulate(ct, sk);
    }

    // ─── DSA ─────────────────────────────────────────────────────────────────
    _dsaImpl(level) {
        if (level === '3') return ml_dsa65;
        if (level === '5') return ml_dsa87;
        throw new Error(`Unknown DSA security level: ${level}`);
    }
    dsaKeygen(level) {
        const seed = this.randomBytes(32);
        const kp = this._dsaImpl(level).keygen(seed);
        seed.fill(0);
        return kp;
    }
    dsaSign(msg, sk, level) { return this._dsaImpl(level).sign(sk, msg); }
    dsaVerify(msg, sig, pk, level) {
        try { return this._dsaImpl(level).verify(pk, msg, sig); }
        catch { return false; }
    }

    // ─── ECDH ────────────────────────────────────────────────────────────────
    ecdhKeygen(curve) {
        if (curve === 'X25519') {
            const sk = this.randomBytes(32);
            const pk = x25519.getPublicKey(sk);
            return { publicKey: pk, secretKey: sk };
        }
        if (curve === 'P-384') {
            const sk = p384.utils.randomPrivateKey();
            const pk = p384.getPublicKey(sk, false); // uncompressed
            return { publicKey: pk, secretKey: sk };
        }
        throw new Error(`Unknown ECDH curve: ${curve}`);
    }
    ecdhEncapsulate(peerPk, curve) {
        // Ephemeral-static ECDH: generate ephemeral keypair, derive shared.
        const e = this.ecdhKeygen(curve);
        let shared;
        if (curve === 'X25519') {
            shared = x25519.getSharedSecret(e.secretKey, peerPk);
        } else if (curve === 'P-384') {
            shared = p384.getSharedSecret(e.secretKey, peerPk).slice(1); // strip 0x04 prefix
        } else {
            throw new Error(`Unknown ECDH curve: ${curve}`);
        }
        e.secretKey.fill(0);
        return { ephemeralPublicKey: e.publicKey, sharedSecret: shared };
    }
    ecdhDecapsulate(ephemPk, sk, curve) {
        if (curve === 'X25519') return x25519.getSharedSecret(sk, ephemPk);
        if (curve === 'P-384') return p384.getSharedSecret(sk, ephemPk).slice(1);
        throw new Error(`Unknown ECDH curve: ${curve}`);
    }

    // ─── Hash ────────────────────────────────────────────────────────────────
    sha3_256(data) { return sha3_256(data); }
    sha3_512(data) { return sha3_512(data); }

    // ─── KDF ─────────────────────────────────────────────────────────────────
    hkdfSha3_256(ikm, salt, info, length) {
        return hkdf(sha3_256, ikm, salt, info, length);
    }
    pbkdf2Sha256(passphrase, salt, iterations, length) {
        return pbkdf2(sha256, passphrase, salt, { c: iterations, dkLen: length });
    }

    // ─── Symmetric ───────────────────────────────────────────────────────────
    aesGcmEncrypt(key, nonce, pt, aad) {
        return gcm(key, nonce, aad).encrypt(pt);
    }
    aesGcmDecrypt(key, nonce, ct, aad) {
        return gcm(key, nonce, aad).decrypt(ct);
    }

    // ─── RNG ─────────────────────────────────────────────────────────────────
    randomBytes(n) {
        return randomBytes(n);
    }
}

// Default provider — used until setProvider() is called.
let activeProvider = new NobleProvider();
let providerSetCallback = null;

/**
 * Get the active provider. All approved-mode entry points consult this.
 */
export function getProvider() {
    return activeProvider;
}

/**
 * Replace the active provider. Resets the FIPS-mode self-test gate (the
 * caller must re-run setFipsMode(true) to re-arm in approved mode).
 *
 * Intended for use by integrators wiring a validated backend at process
 * startup.
 */
export function setProvider(provider) {
    if (!(provider instanceof PqcProvider)) {
        throw new Error('Provider must extend PqcProvider');
    }
    activeProvider = provider;
    if (providerSetCallback) providerSetCallback();
}

/**
 * Internal: register a callback that fires whenever the provider changes.
 * Wired up by fips.js to reset its self-test gate.
 */
export function _onProviderChange(cb) {
    providerSetCallback = cb;
}

export default {
    PqcProvider,
    NobleProvider,
    getProvider,
    setProvider,
};
