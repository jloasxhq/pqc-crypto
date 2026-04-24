# Changelog

## 2.0.0 (2026-04-24)

### Breaking changes

- `keys.serializeKeys` now writes v2 envelopes (`version: 2`) using
  PBKDF2-HMAC-SHA-256 with 600,000 iterations (NIST SP 800-132).
  Previous v1 envelopes (HKDF-SHA3-256 passphrase wrap) remain
  readable by `deserializeKeys`, but a v2 envelope cannot be loaded
  by v1.x consumers.
- `kem.generateKeyPair` and `dsa.generateKeyPair` now run a pair-wise
  consistency check (FIPS 140-3 conditional self-test on asymmetric
  keypair generation). On failure the keypair is zeroized and the
  function throws.
- `hash.keccak256` and `hash.keccak512` throw if `setFipsMode(true)`
  was called (Keccak uses different padding than SHA-3 and is not
  FIPS 202 approved).

### New features

- `setFipsMode(enabled)` / `isFipsMode()` — process-global, sticky-on
  FIPS-mode flag. First-time enable triggers power-on self-tests.
- `runSelfTests()` — manual entry point for power-on self-tests,
  including SHA-3 KAT, HKDF / AES-GCM round-trip, ML-KEM / ML-DSA
  pair-wise consistency with negative tests.
- New module `fips` — exports `setFipsMode`, `isFipsMode`,
  `assertApprovedAlgorithm`, `checkErrorState`, `isSelfTestPassed`,
  `getErrorState`.
- New module `selftest` — `runSelfTests()`.
- New module `zeroize` — `zeroize(buf)`, `zeroizeAll(...bufs)`,
  `zeroizeKeyPair(kp, alsoPublic?)`, `constantTimeEqual(a, b)`.
- `keys.clearKeys()` now zeros both secret AND public-key buffers
  (defense in depth).
- `getAlgorithmInfo()` now reports `library`, `fipsValidated: false`,
  `fipsModeEnabled`, and the KDF in use.

### Internal

- Added `pair-wise consistency probes` for ML-DSA negative tests
  (sign valid message, verify rejects tampered message).
- All approved-mode entry points now call `checkErrorState()` first;
  any prior self-test failure halts subsequent crypto operations.

### Provenance

- Source is now mirrored to QUX Gitea at `quxadmin/pqc-crypto`.
- `package.json` populates `repository`, `bugs`, and `homepage`
  fields (previously empty).

### Roadmap (deferred)

- v2.1: hybrid KEM (ML-KEM + X25519, ML-KEM + ECDH-P384) per
  NIST SP 800-56C Rev 2 combiner.
- v3.0: `PqcProvider` interface with pluggable backends
  (NobleProvider default, OpenSslProvider, BoringCryptoProvider,
  Pkcs11Provider).
- v2.x: full NIST CAVP / ACVP test vectors for SHA-3, ML-KEM,
  ML-DSA, AES-GCM, HKDF, PBKDF2.
- Signed SBOM (CycloneDX).

## 1.0.0 (2026-04-02)

- Initial release. ML-KEM-768/1024 and ML-DSA-65/87 wrappers,
  AES-256-GCM, HKDF-SHA3-256, session management, VoIP module,
  Keccak hashes.
