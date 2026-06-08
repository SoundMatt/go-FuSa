# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.9.x   | Yes       |
| < 0.9   | No        |

## Reporting a Vulnerability

go-FuSa is a static analysis and evidence-generation tool. Its attack surface is
limited to:

- **Input parsing** — `.fusa.json`, `go.mod`, `go.sum`, JSON test output
- **File-system traversal** — scanning the project root passed via `--dir`

### How to report

Do **not** open a public GitHub issue for security vulnerabilities.

Send a report to **matt@jellybaby.com** with:

1. A description of the vulnerability
2. Steps to reproduce (ideally a minimal proof of concept)
3. The go-FuSa version (`gofusa version`)
4. Your assessment of severity and exploitability

You will receive an acknowledgement within **72 hours** and a resolution
timeline within **7 days**.

## Scope

| In scope | Out of scope |
|----------|-------------|
| Command injection via crafted `--dir`, `--output`, or `--output-dir` arguments | Vulnerabilities in Go itself |
| Malicious `.fusa.json` or `go.mod` causing unexpected behaviour | Third-party CI runners that invoke go-FuSa |
| Path traversal during file scanning | |
| Denial-of-service via deeply nested or malformed input | |

## Security Considerations for Safety Projects

go-FuSa output may be used in safety cases. Consider the following:

- **Integrity** — Evidence files include SHA-256 hashes but are not
  cryptographically signed. Use `cosign` or similar for a tamper-evident chain
  of custody in regulated environments.
- **Isolation** — Run `gofusa` in CI with minimal permissions. It requires read
  access to the project source and write access to the output directory only.
- **Supply chain** — Install from the module proxy with checksum verification
  enabled (`GONOSUMCHECK` unset), or pin a specific version and its hash in
  your project safety plan.
