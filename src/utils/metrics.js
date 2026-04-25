/**
 * @quxtech/pqc-crypto - Prometheus Metrics Adapter (v2.0+)
 * ============================================================================
 * Counter / histogram emitter that wraps the public API of
 * @quxtech/pqc-crypto. Drop-in replacement for direct module imports:
 *
 *   // Before
 *   import { kem, dsa, session } from '@quxtech/pqc-crypto';
 *
 *   // After (with metrics)
 *   import { initMetrics, kem, dsa, session } from
 *     '@quxtech/pqc-crypto/metrics';
 *
 *   initMetrics({ vm: process.env.HOSTNAME, app: 'quxpay-middleware' });
 *
 * Counters emitted (label set: vm, app, suite, operation):
 *   - pqc_handshakes_total
 *   - pqc_handshake_errors_total
 *   - pqc_signs_total
 *   - pqc_sign_errors_total
 *   - pqc_verifies_total
 *   - pqc_verify_failures_total       (signature invalid — not error)
 *   - pqc_session_count            (gauge)
 *   - pqc_selftest_failures_total
 *
 * Histograms (latency in ms):
 *   - pqc_handshake_duration_ms
 *   - pqc_sign_duration_ms
 *   - pqc_verify_duration_ms
 *
 * Exposes `register` so the consuming app can attach to its own
 * /metrics endpoint:
 *
 *   import { register } from '@quxtech/pqc-crypto/metrics';
 *   app.get('/metrics', async (_, res) => {
 *     res.setHeader('Content-Type', register.contentType);
 *     res.end(await register.metrics());
 *   });
 *
 * Implementation requires `prom-client` as a peer dep; if absent, the
 * adapter no-ops and forwards all calls unwrapped (zero overhead, zero
 * crash).
 * ============================================================================
 */

import * as kemRaw from '../core/kem.js';
import * as dsaRaw from '../core/dsa.js';
import * as hybridRaw from '../core/hybrid.js';
import * as sessionRaw from '../core/session.js';

// Lazy-load prom-client so absence is not fatal
let promClient = null;
let metrics = null;
let labels = { vm: 'unknown', app: 'unknown' };

async function tryLoadPromClient() {
    if (promClient !== null) return promClient;
    try {
        promClient = await import('prom-client');
    } catch {
        promClient = false; // explicitly disabled
    }
    return promClient;
}

/**
 * Initialize metric registration. Call once at process start.
 *
 * @param {object} opts
 * @param {string} opts.vm        - hostname / VM identifier
 * @param {string} opts.app       - app name (e.g., "quxpay-middleware")
 * @param {object} opts.register  - optional pre-existing prom-client Registry
 */
export async function initMetrics(opts = {}) {
    labels = { vm: opts.vm || process.env.HOSTNAME || 'unknown', app: opts.app || 'unknown' };
    const pc = await tryLoadPromClient();
    if (!pc) return; // no-op mode

    const register = opts.register || pc.register;
    metrics = {
        register,
        handshakes: new pc.Counter({
            name: 'pqc_handshakes_total',
            help: 'PQC handshakes (KEM encap or hybrid encap) initiated',
            labelNames: ['vm', 'app', 'suite'],
            registers: [register],
        }),
        handshakeErrors: new pc.Counter({
            name: 'pqc_handshake_errors_total',
            help: 'PQC handshakes that threw',
            labelNames: ['vm', 'app', 'suite', 'kind'],
            registers: [register],
        }),
        handshakeDuration: new pc.Histogram({
            name: 'pqc_handshake_duration_ms',
            help: 'PQC handshake duration in milliseconds',
            labelNames: ['vm', 'app', 'suite'],
            buckets: [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000],
            registers: [register],
        }),
        signs: new pc.Counter({
            name: 'pqc_signs_total',
            labelNames: ['vm', 'app', 'suite'], help: 'PQC signatures generated',
            registers: [register],
        }),
        signErrors: new pc.Counter({
            name: 'pqc_sign_errors_total',
            labelNames: ['vm', 'app', 'suite'], help: 'PQC sign exceptions',
            registers: [register],
        }),
        signDuration: new pc.Histogram({
            name: 'pqc_sign_duration_ms',
            labelNames: ['vm', 'app', 'suite'], help: 'PQC sign duration ms',
            buckets: [1, 2, 5, 10, 25, 50, 100, 250],
            registers: [register],
        }),
        verifies: new pc.Counter({
            name: 'pqc_verifies_total',
            labelNames: ['vm', 'app', 'suite'], help: 'PQC verifies attempted',
            registers: [register],
        }),
        verifyFailures: new pc.Counter({
            name: 'pqc_verify_failures_total',
            labelNames: ['vm', 'app', 'suite', 'reason'],
            help: 'PQC verifies that returned false (caller-provided bad sig)',
            registers: [register],
        }),
        sessionCount: new pc.Gauge({
            name: 'pqc_session_count',
            labelNames: ['vm', 'app'],
            help: 'Currently-active PQC sessions',
            registers: [register],
        }),
        selftestFailures: new pc.Counter({
            name: 'pqc_selftest_failures_total',
            labelNames: ['vm', 'app'],
            help: 'PQC self-test failures (should always be 0)',
            registers: [register],
        }),
    };
}

function lab(extra = {}) { return { ...labels, ...extra }; }

function timed(hist, lbl, fn) {
    if (!metrics) return fn();
    const t0 = Date.now();
    try {
        return fn();
    } finally {
        hist.labels(lbl).observe(Date.now() - t0);
    }
}

// ─── KEM wrappers ────────────────────────────────────────────────────────────
export const kem = {
    ...kemRaw,
    encapsulate(pk, level = '5') {
        const lbl = lab({ suite: kemRaw.getAlgorithmName(level) });
        try {
            const r = timed(metrics?.handshakeDuration, lbl, () => kemRaw.encapsulate(pk, level));
            metrics?.handshakes.labels(lbl).inc();
            return r;
        } catch (e) {
            metrics?.handshakeErrors.labels({ ...lbl, kind: 'encapsulate' }).inc();
            throw e;
        }
    },
    decapsulate(ct, sk, level = '5') {
        const lbl = lab({ suite: kemRaw.getAlgorithmName(level) });
        try {
            return timed(metrics?.handshakeDuration, lbl, () => kemRaw.decapsulate(ct, sk, level));
        } catch (e) {
            metrics?.handshakeErrors.labels({ ...lbl, kind: 'decapsulate' }).inc();
            throw e;
        }
    },
};

// ─── Hybrid wrappers ─────────────────────────────────────────────────────────
export const hybrid = {
    ...hybridRaw,
    encapsulate(cPk, qPk, curve, level) {
        const suite = hybridRaw.getSuiteName(curve, level);
        const lbl = lab({ suite });
        try {
            const r = timed(metrics?.handshakeDuration, lbl, () =>
                hybridRaw.encapsulate(cPk, qPk, curve, level));
            metrics?.handshakes.labels(lbl).inc();
            return r;
        } catch (e) {
            metrics?.handshakeErrors.labels({ ...lbl, kind: 'hybrid_encapsulate' }).inc();
            throw e;
        }
    },
    decapsulate(...args) {
        const [, , , , curve, level] = args;
        const lbl = lab({ suite: hybridRaw.getSuiteName(curve, level) });
        try {
            return timed(metrics?.handshakeDuration, lbl, () => hybridRaw.decapsulate(...args));
        } catch (e) {
            metrics?.handshakeErrors.labels({ ...lbl, kind: 'hybrid_decapsulate' }).inc();
            throw e;
        }
    },
};

// ─── DSA wrappers ────────────────────────────────────────────────────────────
export const dsa = {
    ...dsaRaw,
    sign(msg, sk, level = '5') {
        const lbl = lab({ suite: dsaRaw.getAlgorithmName(level) });
        try {
            const r = timed(metrics?.signDuration, lbl, () => dsaRaw.sign(msg, sk, level));
            metrics?.signs.labels(lbl).inc();
            return r;
        } catch (e) {
            metrics?.signErrors.labels(lbl).inc();
            throw e;
        }
    },
    verify(msg, sig, pk, level = '5') {
        const lbl = lab({ suite: dsaRaw.getAlgorithmName(level) });
        const ok = dsaRaw.verify(msg, sig, pk, level);
        metrics?.verifies.labels(lbl).inc();
        if (!ok) metrics?.verifyFailures.labels({ ...lbl, reason: 'bad_signature' }).inc();
        return ok;
    },
};

// ─── Session wrappers ────────────────────────────────────────────────────────
export const session = {
    ...sessionRaw,
    async createSession(sid, clientPk, level = '5') {
        const r = await sessionRaw.createSession(sid, clientPk, level);
        if (metrics) metrics.sessionCount.labels(lab()).inc();
        return r;
    },
    async destroySession(sid) {
        await sessionRaw.destroySession(sid);
        if (metrics) metrics.sessionCount.labels(lab()).dec();
    },
};

// ─── Self-test failure recorder ──────────────────────────────────────────────
export function recordSelftestFailure() {
    metrics?.selftestFailures.labels(lab()).inc();
}

/**
 * Express handler for /metrics — call as `app.get('/metrics', metricsHandler)`.
 * No-op if metrics not initialized.
 */
export function metricsHandler(req, res) {
    if (!metrics) {
        res.statusCode = 503;
        res.end('# metrics adapter not initialized\n');
        return;
    }
    Promise.resolve(metrics.register.metrics()).then(text => {
        res.setHeader('Content-Type', metrics.register.contentType);
        res.end(text);
    });
}

export const register = new Proxy({}, {
    get(_, key) { return metrics?.register?.[key]; },
});

export default { initMetrics, kem, dsa, hybrid, session, metricsHandler, register, recordSelftestFailure };
