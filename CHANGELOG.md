# Changelog

## 2.0.1 (2026-04-24)

Patch release: optional Prometheus metrics adapter.

### New features

#### Prometheus metrics adapter (`metrics` module, `./metrics` export)

Drop-in observability layer that wraps the public `kem`, `dsa`,
`hybrid`, and `session` calls and emits Prometheus counters/histograms.

- New entry point: `import { initMetrics, metricsHandler, kem, dsa,
  hybrid, session, register } from '@quxtech/pqc-crypto/metrics';`.
- Counters: `pqc_handshakes_total`, `pqc_handshake_errors_total`,
  `pqc_signs_total`, `pqc_sign_errors_total`, `pqc_verifies_total`,
  `pqc_verify_failures_total`, `pqc_selftest_failures_total`. Gauge:
  `pqc_session_count`. Histograms (ms):
  `pqc_handshake_duration_ms`, `pqc_sign_duration_ms`,
  `pqc_verify_duration_ms`. Label set: `vm`, `app`, `suite`.
- `prom-client` is declared as an OPTIONAL `peerDependency`. If absent
  the adapter no-ops gracefully (zero overhead, zero crash) and
  forwards every call to the underlying primitive unwrapped.
- `register` is exported as a Proxy onto the active prom-client
  Registry so consumers can attach to their own `/metrics` endpoint.
- Top-level helpers `initMetrics` and `metricsHandler` are also
  re-exported from the package root for convenience.

### No breaking changes

All v2.0.0 APIs are unchanged. `@noble/*` dependency versions are
unchanged. Existing consumers that do not import `./metrics` see no
behavioral difference.

## 2.0.0 (2026-04-24)

This is a major release that lands the full FIPS 140-3 readiness
roadmap (audit dated 2026-04-24): hybrid KEM, PqcProvider abstraction,
expanded NIST KAT vectors, CycloneDX SBOM with ed25519 signature, and
reproducible-build documentation.

### Breaking changes

- `keys.serializeKeys` now writes v2 envelopes using PBKDF2-HMAC-SHA-256
  (NIST SP 800-132, 600,000 iterations). v1 envelopes (HKDF-SHA3-256)
  remain readable by `deserializeKeys`; v2 envelopes are NOT readable
  by v1.x consumers.
- `kem.generateKeyPair` and `dsa.generateKeyPair` run a pair-wise
  consistency check after keygen (FIPS 140-3 conditional self-test).
  Failed keys are zeroized and the function throws.
- `hash.keccak256` and `hash.keccak512` throw if `setFipsMode(true)`
  was called.
- All cryptographic primitives now route through the active
  `PqcProvider`. Default behavior is unchanged (NobleProvider mirrors
  v1 semantics), but call paths are different — any direct `import`
  of `@noble/post-quantum` from consumer code is now optional.

### New features

#### Hybrid KEM (`hybrid` module, `./hybrid` export)

NIST SP 800-56C Rev 2 combiner over classical ECDH + ML-KEM.

- Suites: `X25519+ML-KEM-768`, `X25519+ML-KEM-1024`,
  `P-384+ML-KEM-768`, `P-384+ML-KEM-1024`.
- API: `hybrid.generateKeyPair(curve, level)`,
  `hybrid.encapsulate(classicalPk, pqcPk, curve, level)`,
  `hybrid.decapsulate(classicalEphemPk, pqcCt, classicalSk, pqcSk,
  curve, level)`.
- Combiner: HKDF-SHA3-256 over `ss_classical || ss_pqc` with
  per-suite domain separation.

#### PqcProvider abstraction (`provider` module, `./provider` export)

Pluggable backend interface for delegating approved-mode operations
to a future FIPS-validated module.

- `PqcProvider` abstract base class + `NobleProvider` default
  implementation (current pure-JS path, NOT FIPS-validated).
- API: `getProvider()`, `setProvider(provider)`.
- Roadmap: `OpenSslProvider` (Node OpenSSL 3.5+ FIPS), `BoringCryptoProvider`,
  `WolfCryptProvider`, `Pkcs11Provider` (HSM / softhsm2 / YubiHSM).
- Switching providers resets the FIPS-mode self-test gate.

#### Expanded self-tests + NIST KAT vectors

Test vectors shipped under `test/vectors/`:
- `sha3.json` — NIST FIPS 202 sample vectors for SHA3-256 / SHA3-512.
- `hkdf.json` — RFC 5869 Appendix A test vectors (HKDF-SHA-256).
- `pbkdf2.json` — RFC 7914 §11 test vectors (PBKDF2-HMAC-SHA-256).
- `aes-gcm.json` — self-consistency vectors with deterministic inputs.
- `pqc.json` — ML-KEM / ML-DSA zero-seed regression checks.

`runSelfTests()` (or `selftest.runSelfTests()`) executes all KATs +
pair-wise consistency for ML-KEM/ML-DSA + hybrid KEM round-trip +
provider self-attestation. Failures place the module in a sticky
error state and disable approved-mode operations.

#### Opt-in FIPS mode (`fips` module, `./fips` export)

- `setFipsMode(true)` / `isFipsMode()` — process-global, sticky-on
  flag that runs power-on self-tests and gates non-approved primitives
  (Keccak) at the API surface.

#### Memory hygiene helpers (`zeroize` module, `./zeroize` export)

- `zeroize(buf)`, `zeroizeAll(...bufs)`, `zeroizeKeyPair(kp, alsoPublic?)`,
  `constantTimeEqual(a, b)`.
- `keys.clearKeys()` now zeros both secret AND public-key buffers.

### Supply chain

- CycloneDX 1.5 SBOM committed at `bom.json` (5 components: this package
  + its 4 @noble/* direct dependencies + transitives).
- ed25519 signature at `bom.json.sig`; public key at `bom-pubkey.pem`
  (and `bom-pubkey.hex`). Signing key was generated single-purpose
  for this release.
- Reproducible-build instructions documented in `BUILD.md`.
- All dependencies pinned to exact versions (no `^`, no `~`).
- `repository`, `bugs`, and `homepage` fields populated in
  `package.json`.

### Internal

- Refactored `kem`, `dsa`, `symmetric`, `keys`, and `hash` modules to
  call into `getProvider()` for all crypto primitives. Direct @noble/*
  imports are confined to `core/provider.js` and `core/selftest.js`.
- `setProvider()` resets the FIPS self-test gate via the
  `_onProviderChange` hook.

### Roadmap (still deferred)

- v2.x: full NIST CAVP/ACVP vector packs as a build step
  (`npm run fetch-vectors`).
- v2.x: bit-identical reproducible builds via SOURCE_DATE_EPOCH.
- v3.0: actual FIPS-validated provider implementations (OpenSslProvider
  once OpenSSL 3.5+ FIPS provider gains ML-KEM/ML-DSA; BoringCryptoProvider;
  Pkcs11Provider for HSM delegation).
- Vault-backed signing key storage (currently single-purpose key shipped
  in repo).

## 1.0.0 (2026-04-02)

- Initial release. ML-KEM-768/1024 and ML-DSA-65/87 wrappers,
  AES-256-GCM, HKDF-SHA3-256, session management, VoIP module,
  Keccak hashes.
