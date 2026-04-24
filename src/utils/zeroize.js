/**
 * @quxtech/pqc-crypto - Zeroization Helpers (v2.0)
 * ============================================================================
 * Best-effort zeroization for byte buffers. JavaScript strings are immutable
 * and cannot be zeroized; callers handling secrets MUST keep secret material
 * in Uint8Array form for the entire lifetime if zeroization matters.
 *
 * IMPORTANT CAVEAT: V8 hex strings created via bytesToHex() persist in the
 * heap until garbage-collected and cannot be cleared in-place. For
 * defense-in-depth, prefer the *Bytes / Uint8Array entry points and zero
 * them when finished. See README "Memory hygiene" section for guidance.
 * ============================================================================
 */

/**
 * Zero a Uint8Array in place. Returns the buffer for chaining.
 * No-op on null/undefined. Ignores non-Uint8Array inputs (does not throw).
 */
export function zeroize(buf) {
    if (buf instanceof Uint8Array) {
        buf.fill(0);
    }
    return buf;
}

/**
 * Zero multiple Uint8Array buffers.
 */
export function zeroizeAll(...bufs) {
    for (const b of bufs) zeroize(b);
}

/**
 * Zero a key pair object's secretKey (and optionally publicKey).
 * Returns the same object with its byte buffers zeroed.
 */
export function zeroizeKeyPair(keyPair, alsoPublic = false) {
    if (!keyPair) return keyPair;
    if (keyPair.secretKey instanceof Uint8Array) keyPair.secretKey.fill(0);
    if (alsoPublic && keyPair.publicKey instanceof Uint8Array) keyPair.publicKey.fill(0);
    return keyPair;
}

/**
 * Constant-time byte comparison. Returns true iff a and b are equal.
 * Bails to false on length mismatch (length is typically not secret).
 */
export function constantTimeEqual(a, b) {
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

export default {
    zeroize,
    zeroizeAll,
    zeroizeKeyPair,
    constantTimeEqual,
};
