/**
 * @quxtech/pqc-crypto - FIPS Mode + Module State (v2.0)
 * ============================================================================
 * Process-global FIPS-mode flag. Off by default; setFipsMode(true) is sticky
 * within a process (matches FIPS 140-3 module-state semantics) and triggers
 * power-on self-tests on first call.
 *
 * IMPORTANT: This library is NOT FIPS 140-3 validated as-shipped. Setting
 * the flag does NOT make it validated; it gates non-approved primitives
 * at the API surface and runs self-tests so callers preparing for a
 * future PqcProvider-backed validated deployment can develop against the
 * approved-mode contract today.
 * ============================================================================
 */

let FIPS_MODE = false;
let SELFTEST_PASSED = false;
let ERROR_STATE = null;
let SELFTEST_RUNNER = null;

export function _registerSelfTestRunner(fn) { SELFTEST_RUNNER = fn; }

export function setFipsMode(enabled = true) {
    if (FIPS_MODE && !enabled) {
        throw new Error('FIPS mode is sticky and cannot be disabled in-process');
    }
    if (!enabled) { FIPS_MODE = false; return; }
    if (FIPS_MODE) return;
    if (!SELFTEST_RUNNER) {
        throw new Error('Self-test runner not registered (load order error)');
    }
    SELFTEST_RUNNER();
    FIPS_MODE = true;
}

export function isFipsMode() { return FIPS_MODE; }

export function assertApprovedAlgorithm(algorithmName) {
    if (FIPS_MODE) {
        throw new Error(`Algorithm '${algorithmName}' is not FIPS 140-3 approved; disabled in FIPS mode`);
    }
}

export function _markSelfTestPassed() { SELFTEST_PASSED = true; ERROR_STATE = null; }
export function _enterErrorState(err) {
    ERROR_STATE = err instanceof Error ? err : new Error(String(err));
    SELFTEST_PASSED = false;
    FIPS_MODE = false;
}

export function checkErrorState() {
    if (ERROR_STATE) throw new Error(`Cryptographic module in error state: ${ERROR_STATE.message}`);
}

export function isSelfTestPassed() { return SELFTEST_PASSED; }
export function getErrorState() { return ERROR_STATE; }

/**
 * Internal: provider-change reset hook. When the active provider is
 * replaced via setProvider(), the FIPS-mode self-test gate must be re-armed
 * because the new provider may have different validation properties.
 */
export function _onProviderReset() {
    SELFTEST_PASSED = false;
    FIPS_MODE = false;
    ERROR_STATE = null;
}

export default {
    setFipsMode, isFipsMode, assertApprovedAlgorithm,
    checkErrorState, isSelfTestPassed, getErrorState,
    _registerSelfTestRunner, _markSelfTestPassed, _enterErrorState, _onProviderReset,
};
