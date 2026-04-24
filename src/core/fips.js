/**
 * @quxtech/pqc-crypto - FIPS Mode + Module State (v2.0)
 * ============================================================================
 * Manages a process-global FIPS-mode flag that callers can opt into for
 * stricter algorithm gating. Off by default; backwards-compatible with v1.x
 * callers.
 *
 * IMPORTANT: setting FIPS mode does NOT make this library FIPS 140-3
 * validated. Validation requires delegating approved-mode operations to a
 * validated cryptographic backend (e.g., OpenSSL FIPS 3.x provider, BoringCrypto,
 * a PKCS#11 HSM). This flag is a step toward that delegation pattern; it
 * gates non-approved primitives at the API surface so a caller in approved
 * mode cannot accidentally invoke them.
 * ============================================================================
 */

let FIPS_MODE = false;
let SELFTEST_PASSED = false;
let ERROR_STATE = null;
let SELFTEST_RUNNER = null;

/**
 * Register the self-test runner. Wired up by selftest.js to avoid a circular
 * import.
 */
export function _registerSelfTestRunner(fn) {
    SELFTEST_RUNNER = fn;
}

/**
 * Enable FIPS mode. Sticky once enabled — cannot be turned off in-process,
 * matching FIPS 140-3 module-state semantics. Triggers power-on self-tests
 * on first call.
 */
export function setFipsMode(enabled = true) {
    if (FIPS_MODE && !enabled) {
        throw new Error('FIPS mode is sticky and cannot be disabled in-process');
    }
    if (!enabled) {
        FIPS_MODE = false;
        return;
    }
    if (FIPS_MODE) return;
    if (!SELFTEST_RUNNER) {
        throw new Error('Self-test runner not registered (load order error)');
    }
    SELFTEST_RUNNER();
    FIPS_MODE = true;
}

/**
 * Returns whether FIPS mode is currently enabled.
 */
export function isFipsMode() {
    return FIPS_MODE;
}

/**
 * Throws if a non-approved algorithm is invoked while FIPS mode is enabled.
 * @param algorithmName - human-readable algorithm name (e.g., "Keccak-256")
 */
export function assertApprovedAlgorithm(algorithmName) {
    if (FIPS_MODE) {
        throw new Error(`Algorithm '${algorithmName}' is not FIPS 140-3 approved; disabled in FIPS mode`);
    }
}

/**
 * Internal: mark module as having passed self-tests.
 */
export function _markSelfTestPassed() {
    SELFTEST_PASSED = true;
    ERROR_STATE = null;
}

/**
 * Internal: mark module as in error state. Future crypto ops will throw.
 */
export function _enterErrorState(err) {
    ERROR_STATE = err instanceof Error ? err : new Error(String(err));
    SELFTEST_PASSED = false;
    FIPS_MODE = false;
}

/**
 * Throws if the module is in error state. Call at the entry of any
 * approved-mode operation when FIPS mode is enabled.
 */
export function checkErrorState() {
    if (ERROR_STATE) {
        throw new Error(`Cryptographic module in error state: ${ERROR_STATE.message}`);
    }
}

/**
 * Returns the current self-test pass status.
 */
export function isSelfTestPassed() {
    return SELFTEST_PASSED;
}

/**
 * Returns the current error state (or null if healthy).
 */
export function getErrorState() {
    return ERROR_STATE;
}

export default {
    setFipsMode,
    isFipsMode,
    assertApprovedAlgorithm,
    checkErrorState,
    isSelfTestPassed,
    getErrorState,
    _registerSelfTestRunner,
    _markSelfTestPassed,
    _enterErrorState,
};
