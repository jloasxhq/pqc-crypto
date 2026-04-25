# @quxtech/pqc-crypto

Post-quantum cryptography library implementing the NIST-finalized
ML-KEM (FIPS 203) and ML-DSA (FIPS 204) standards, with AES-256-GCM
authenticated encryption and SHA-3 hashing (FIPS 202).

## ⚠️ Validation status

**This library is NOT FIPS 140-3 validated.**

The cryptographic primitives are implemented in pure TypeScript via the
`@noble/*` family (Cure53-audited). NIST-published *algorithm specifications*
(FIPS 203/204/202, SP 800-132) are followed; *cryptographic-module
validation* is a separate process and is not in scope for v2.x.

If you require FIPS 140-3 validation, future major versions will introduce
a `PqcProvider` abstraction that delegates approved-mode operations to a
validated backend (OpenSSL FIPS 3.x, BoringCrypto, PKCS#11 HSM). Until
then, treat this library as "FIPS-aligned but not FIPS-validated."

## v2.0 highlights

- **Opt-in FIPS mode** — `setFipsMode(true)` runs power-on self-tests and
  blocks non-approved primitives (Keccak) at the API surface.
- **Self-tests** — SHA-3 KAT (NIST FIPS 202 sample vectors), HKDF / AES-GCM
  round-trip self-consistency, ML-KEM / ML-DSA pair-wise consistency with
  negative tests. Run automatically on first `setFipsMode(true)`, or
  manually via `runSelfTests()`.
- **Pair-wise consistency on every keygen** — ML-KEM and ML-DSA
  `generateKeyPair(...)` always run a sign/verify or encap/decap probe
  against the freshly generated key. Failed keys are zeroized and never
  returned.
- **PBKDF2-HMAC-SHA-256 envelope** — `keys.serializeKeys/deserializeKeys`
  now use NIST SP 800-132 PBKDF2 (600,000 iterations) for passphrase-
  derived AES-GCM key wrapping, replacing v1's HKDF passphrase wrap.
  v1 envelopes remain readable.
- **Best-effort zeroization helpers** — new `zeroize` module + improved
  `clearKeys()` that scrubs both secret and public-key buffers. **Note:**
  hex strings created by `bytesToHex(...)` are immutable in V8 and cannot
  be wiped; for real secrets stay in `Uint8Array` paths.

## Breaking changes vs 1.x

| Area | v1 | v2 |
|---|---|---|
| `keys.serializeKeys` envelope KDF | HKDF-SHA3-256 | PBKDF2-HMAC-SHA-256 (600k iterations) |
| `keys.deserializeKeys` | reads v1 envelopes only | reads both v1 and v2 envelopes |
| `kem.generateKeyPair` / `dsa.generateKeyPair` | no consistency check | runs pair-wise probe; throws on failure |
| `hash.keccak256` / `keccak512` | callable freely | throw if `setFipsMode(true)` was called |

If you currently call `serializeKeys` and then store the output to disk,
**downgrading from v2 to v1 is one-way breaking**: v1 cannot read v2
envelopes. Plan accordingly.

## Install (private QUX registry)

`.npmrc`:
```
@quxtech:registry=https://npm.qux.tv:4873/
```

Then:
```bash
npm install @quxtech/pqc-crypto@^2.0.0
```

## Quick start

```js
import { kem, dsa, symmetric, keys, getAlgorithmInfo, setFipsMode } from '@quxtech/pqc-crypto';

// Optional: enable FIPS mode (runs power-on self-tests, gates Keccak)
setFipsMode(true);

// Generate a server keyset
const k = keys.generateServerKeys('5'); // ML-KEM-1024 + ML-DSA-87

// KEM handshake (server side)
const clientKem = kem.generateKeyPairHex('5');
const { ciphertext, sharedSecret } = kem.encapsulate(clientKem.publicKey, '5');

// Sign + verify
const sig = dsa.sign('hello world', k.dsa.secretKey, '5');
const ok = dsa.verify('hello world', sig, k.dsa.publicKey, '5');

// Persist the keyset
const envelope = keys.serializeKeys(k, 'a-strong-passphrase'); // v2 envelope
// ... write envelope JSON to disk ...

// Load it back later
const k2 = keys.deserializeKeys(envelope, 'a-strong-passphrase');

console.log(getAlgorithmInfo('5'));
```

## Memory hygiene

JavaScript strings are immutable. Once you call `bytesToHex(secretKey)` the
hex string lives in V8's heap until garbage collection — and even then
the underlying buffer may be reused without zeroing. For applications
where this matters:

1. Stay in `Uint8Array` paths whenever possible.
2. Call `keys.clearKeys()` when the server is shutting down or rotating;
   it scrubs both secret and public-key buffers.
3. Use the `zeroize.zeroize(buf)` / `zeroizeAll(...bufs)` helpers on
   intermediates.
4. Run application processes short-lived; rely on the process boundary as
   the security domain rather than expecting in-process zeroization to
   protect against heap-dump attackers.

For stricter guarantees, use a future `PqcProvider` HSM backend.

## Security policy

See [SECURITY.md](SECURITY.md) for vulnerability disclosure.

## License

MIT.

## v2.0 update — hybrid KEM, provider abstraction, signed SBOM

This release lands the full FIPS readiness roadmap. See `CHANGELOG.md`
for the full list. Highlights:

- `hybrid` module — NIST SP 800-56C Rev 2 combiner over X25519/P-384 + ML-KEM
- `provider` module — `PqcProvider` interface, `NobleProvider` default
- Expanded NIST KAT vectors at `test/vectors/` (SHA-3, HKDF, PBKDF2)
- CycloneDX SBOM (`bom.json`) signed with ed25519 (`bom.json.sig`,
  `bom-pubkey.pem`)
- Reproducible-build documentation in `BUILD.md`
