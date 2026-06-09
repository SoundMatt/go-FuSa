# Contributing to go-FuSa

Thank you for your interest in contributing.

## Developer Certificate of Origin (DCO)

All contributions must be signed off under the
[Developer Certificate of Origin v1.1](https://developercertificate.org).
The DCO is a lightweight way to certify that you wrote or have the right to
submit the code you are contributing.

Add a `Signed-off-by` trailer to every commit:

```
git commit -s -m "feat: add awesome thing"
```

This produces:

```
feat: add awesome thing

Signed-off-by: Your Name <your@email.com>
```

If you forget to sign off, amend the commit:

```
git commit --amend -s
```

A GitHub Actions check (`DCO`) verifies every commit in a PR. PRs without
sign-offs will not be merged.

## Copyright

By contributing you agree that your contributions are licensed under the
[Mozilla Public License v2.0](LICENSE) and that copyright in go-FuSa remains
with Matt Jones. The DCO sign-off transfers no copyright — it only affirms you
have the right to contribute under the existing license.

## Coding style

- `gofmt` — run `gofmt -w ./...` before pushing.
- `go vet` — must pass with zero warnings.
- `golangci-lint run` — must pass (config in `.golangci.yml`).
- Tests — new code should be accompanied by tests covering the public API.
  Run `go test -race -count=1 ./...` locally.

## Pull requests

1. Fork the repo, create a branch from `main`.
2. Make your changes with signed-off commits.
3. `go test -race -count=1 ./...` must pass.
4. Open a PR targeting `main`.

## Project structure

| Directory | What it contains |
|---|---|
| `.` | `fusa` package — core types, sentinel errors, `Version` constant |
| `config/` | Project configuration load/save/validate |
| `engine/` | Rule interface, registry, FUSA001–005 built-in rules |
| `report/` | Text, JSON, and HTML compliance report renderers |
| `template/` | Safety plan, test evidence, HARA, SVP, SCMP, SQAP document generators |
| `lint/` | Safety-oriented coding rules (error handling, panic, unsafe, globals) |
| `analyze/` | Static analysis passes (goroutine leaks, races, blocking calls, ANA001–009) |
| `trace/` | Requirements traceability engine and coverage mapping |
| `verify/` | Test evidence collection and verification bundle generation |
| `release/` | SBOM (SPDX 3.0.1), build provenance, artifact signing |
| `qualify/` | Tool qualification suite and evidence report |
| `runtime/` | Runtime safety patterns (watchdog, heartbeat, safe-state, diagnostic manager) |
| `safetycase/` | Safety case assembly — evidence collection, GSN diagram, compliance mapping |
| `fmea/` | dFMEA generation from exported functions (JSON + CSV) |
| `boundary/` | Component boundary diagram generation (Mermaid + DOT) |
| `auditpack/` | Evidence bundle ZIP with SHA-256 manifest for auditor submission |
| `cyber/` | Cybersecurity static analysis — 20 CWE-mapped rules (CYBER001–020) |
| `iec62443/` | IEC 62443 industrial cybersecurity compliance checks |
| `slsa/` | SLSA L2/L3 supply-chain checks |
| `tara/` | Threat Analysis and Risk Assessment — ISO 21434 Ch. 9, STRIDE/CWE mapping |
| `vuln/` | Dependency vulnerability scanner — OSV API + govulncheck |
| `sarif/` | SARIF 2.1.0 renderer for GitHub Code Scanning |
| `badge/` | SVG status badge generator |
| `diff/` | Report diff engine — introduced/resolved/unchanged findings |
| `comp/` | Cyclomatic complexity analysis — COMP001 (DO-178C §6.3.4) |
| `coupling/` | Data/control coupling detection — COUP001/COUP002 (DO-178C §6.4.4.3) |
| `coverage/` | Structural coverage from `coverage.out` — statement, decision, MC/DC |
| `pr/` | Problem report log — CRUD + PR001 rule (DO-178C §11.17) |
| `sci/` | Software Configuration Index with SHA-256 (DO-178C §11.16) |
| `do178/` | DO-178C Annex A 38-objective gap assessment |
| `sas/` | Software Accomplishment Summary (DO-178C §11.20) |
| `testutil/` | Test harness helpers |
| `cmd/gofusa` | CLI entry point — all subcommands |

## Running tests

```bash
# Standard suite
go test -race -count=1 ./...

# Short (skips long-running integration tests)
go test -race -count=1 -short ./...
```

## Commit message style

```
type(scope): short summary

Body explaining *why*, not what. Reference relevant ROADMAP.md items.

Signed-off-by: Your Name <your@email.com>
```

Types: `feat`, `fix`, `docs`, `test`, `chore`, `refactor`.
Scope examples: `lint`, `analyze`, `trace`, `verify`, `release`, `qualify`, `cli`, `runtime`.
