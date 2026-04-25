# Reproducible build

This document records the build inputs and outputs for v2.0.0 so that an
auditor (or future-you) can re-derive the published tarball bit-for-bit
and verify the signed SBOM.

## Source

Source is mirrored to QUX Gitea at `quxadmin/pqc-crypto`. The v2.0.0
release tag points at the canonical commit. Re-clone:

```bash
git clone http://10.10.0.10:3000/quxadmin/pqc-crypto.git
cd pqc-crypto
git checkout v2.0.0
```

## Toolchain

- Node 20.x or 22.x (built and tested on Node 22.22.1).
- `npm` 10.x.
- All dependencies are pinned to **exact** versions in `package.json`
  (no `^`, no `~`). `package-lock.json` records full integrity hashes.

```
@noble/ciphers       1.2.1
@noble/hashes        1.7.1
@noble/post-quantum  0.2.1
@noble/curves        1.8.1
```

## Build steps

```bash
# 1. Install dependencies (deterministic given the lockfile)
npm ci

# 2. Run self-tests (uses the active provider — defaults to NobleProvider)
npm run selftest

# 3. Pack the release tarball
npm pack

# Output: quxtech-pqc-crypto-2.0.0.tgz
```

The tarball contains exactly the paths listed under `files` in
`package.json`:

```
package.json
README.md
SECURITY.md
CHANGELOG.md
BUILD.md
LICENSE
bom.json
bom.json.sig
bom-pubkey.pem
src/...
test/vectors/...
```

## Verifying the signed SBOM

The SBOM (`bom.json`) is signed with a single-purpose ed25519 key created
for this release. The public key is committed to the repo at
`bom-pubkey.pem` (and `bom-pubkey.hex` for raw use).

```bash
# Verify with @noble/curves
node -e "
const { ed25519 } = require('@noble/curves/ed25519');
const { hexToBytes } = require('@noble/hashes/utils');
const fs = require('fs');
const bom = fs.readFileSync('bom.json');
const sig = hexToBytes(fs.readFileSync('bom.json.sig', 'utf-8').trim());
const pk  = hexToBytes(fs.readFileSync('bom-pubkey.hex', 'utf-8').trim());
console.log('SBOM signature valid:', ed25519.verify(sig, bom, pk));
"
```

## Verifying the registry tarball

The Verdaccio registry stores the tarball at:

```
https://npm.qux.tv:4873/@quxtech/pqc-crypto/-/pqc-crypto-2.0.0.tgz
```

After download, compare hashes against the manifest:

```bash
# Manifest reports SHA-1 (npm convention) and SHA-512 (RFC 6234)
curl -sk https://npm.qux.tv:4873/@quxtech/pqc-crypto | jq '.versions["2.0.0"].dist'
sha1sum pqc-crypto-2.0.0.tgz
node -e "const h=require('crypto').createHash('sha512'); h.update(require('fs').readFileSync('pqc-crypto-2.0.0.tgz')); console.log('sha512-' + h.digest('base64'))"
```

## Reproducibility caveats

- `npm pack` includes mtime metadata in the tar header — to get a
  byte-identical tarball, either set `SOURCE_DATE_EPOCH` (npm respects
  it as of npm 10.x) or compare unpacked content hashes only.
- The `bom.json` `metadata.timestamp` field changes each build. If a
  bit-identical SBOM is required, set `SOURCE_DATE_EPOCH` and pass it
  through to the SBOM generator.
- The `bom.json` `serialNumber` is a fresh UUID per build by design;
  this is part of the CycloneDX spec.

For an auditor, content reproducibility (every committed file's SHA-256
matches) plus signature verification (SBOM signature checks) is
sufficient. Bit-identical tarball reproducibility is on the v2.x
roadmap.
