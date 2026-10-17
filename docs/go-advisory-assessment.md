# GO-2026-5932 assessment — 2026-10-17

This advisory remains in the existing Caddy dependency's module metadata. The
image gate blocks it; there are no advisory exceptions. The current upstream
binary was rebuilt with symbols retained so the binary scanner can inspect its
packages, without adding any Go source, local module graph or runtime patches.

The new binary `govulncheck` result reports **zero reachable vulnerabilities and
zero vulnerabilities in imported packages**, with one advisory in a required
module. Trivy still reports that module-level advisory in both backend and Caddy
images. This is evidence about exposure, not removal of the advisory or a waiver
of the all-findings image gate. Current binary hashes and raw scanner output are
in the [recheck record](security-recheck-2026-10-17.json).

The [Go vulnerability database](https://pkg.go.dev/vuln/GO-2026-5932) marks the
unmaintained `golang.org/x/crypto/openpgp` family unsafe by design, across all
versions, with no fixed version. Upgrading `x/crypto` cannot resolve that record.
The build uses `x/crypto v0.58.0` and the maintained Go 1.26.9 toolchain.

`go mod why -m golang.org/x/crypto` establishes a real dependency through Caddy's
standard TLS module and `cryptobyte`. Other imported packages include bcrypt,
Argon2, ChaCha20-Poly1305, OCSP and SSH. Removing the entire module would break
supported functionality. No module rename, metadata stripping, private crypto
fork or general advisory exclusion was used to create a clean-looking result.

Historical validation (not a current release exemption):

- `go list -mod=readonly -deps .` enumerated 1,080 packages for Linux/amd64 and
  1,078 for Linux/arm64. None was in the affected OpenPGP family.
- Source and binary `govulncheck` reported zero reachable vulnerabilities and
  zero vulnerabilities in imported packages, with this one module-level record.
- The previous package guard rejected a fixture importing OpenPGP. That guard
  and its local module graph have been removed, rather than pretending it still
  validates the current dependency.
- Raw Trivy reports remain unfiltered. `scripts/check-image-findings.js` now
  rejects this advisory as well as all other fixed or unfixed findings.

CatWAF remains a Node.js application using its original upstream Caddy/Coraza
integration. No private cryptography fork, renamed module, metadata stripping
or scanner suppression is used to hide the outstanding dependency advisory.
