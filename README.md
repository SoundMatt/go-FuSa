# go-FuSa

A functional safety enablement toolkit for Go projects. go-FuSa provides static checks,
coding rules, traceability helpers, CI evidence bundles, reproducible build metadata,
runtime safety patterns, and tool qualification support to help teams build safety cases
for ISO 26262, IEC 61508, ISO 21434, and DO-178C.

[![CI](https://github.com/SoundMatt/go-FuSa/actions/workflows/ci.yml/badge.svg)](https://github.com/SoundMatt/go-FuSa/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/SoundMatt/go-FuSa.svg)](https://pkg.go.dev/github.com/SoundMatt/go-FuSa)

> **Not a certification product.** go-FuSa is an engineering accelerator that reduces
> the cost of producing functional safety evidence throughout the SDLC.

## Packages

| Package | Description |
|---|---|
| `.` | `fusa` — core types, sentinel errors, and `Version` constant |
| `config/` | Project configuration (`gofusa init`, `.fusa.json`) |
| `engine/` | Rule registration, execution engine, FUSA001–005 built-in rules |
| `report/` | Text and JSON compliance report renderers |
| `template/` | Safety plan, test evidence, and HARA document generators |
| `lint/` | Safety-oriented coding rules (error handling, panic, unsafe, globals) |
| `analyze/` | Static analysis passes (goroutine leaks, race patterns, blocking calls) |
| `trace/` | Requirements traceability engine and coverage mapping |
| `verify/` | Test evidence collection and verification bundle generation |
| `release/` | SBOM generation, build provenance, artifact signing |
| `qualify/` | Tool qualification suite — self-test framework and evidence report |
| `runtime/` | Reusable safety patterns — watchdog, heartbeat, safe-state transitions |
| `testutil/` | Test harness helpers |
| `cmd/gofusa` | CLI — `init`, `check`, `report`, `trace`, `verify`, `release`, `qualify` |

## Install

```bash
go install github.com/SoundMatt/go-FuSa/cmd/gofusa@latest
```

## Quick start

```bash
# Initialise a project
gofusa init

# Run all safety checks
gofusa check

# Show the requirements traceability matrix
gofusa trace

# Run tests and save a test evidence bundle
gofusa verify

# Generate SBOM and build provenance
gofusa release

# Run the tool qualification suite
gofusa qualify

# Generate a full compliance report
gofusa report
```

## Docker quick start

No local Go installation required:

```bash
# Pull the official image
docker pull ghcr.io/soundmatt/go-fusa:latest

# Run checks against the current directory
docker run --rm -v "$(pwd)":/project ghcr.io/soundmatt/go-fusa check

# Generate all release evidence
docker run --rm -v "$(pwd)":/project ghcr.io/soundmatt/go-fusa release
```

Build from source:

```bash
docker build -t go-fusa .
docker run --rm -v "$(pwd)":/project go-fusa check
```

See [docker-compose.yml](docker-compose.yml) for a full-pipeline example.

## Standards coverage

| Standard | Scope |
|---|---|
| ISO 26262 | Automotive functional safety (ASIL A–D) |
| IEC 61508 | General functional safety (SIL 1–4) |
| ISO 21434 | Automotive cybersecurity (evidence hooks) |
| DO-178C | Aerospace software (process alignment) |

## Tool qualification

go-FuSa includes a built-in qualification suite that validates every engine rule
against known-good and known-bad synthetic projects, producing a cryptographically
hashed evidence report:

```bash
gofusa qualify
# writes qualify-report.json with SHA-256 integrity hash
```

This report can be submitted as tool confidence evidence in regulated environments.
See [docs/qualification.md](docs/qualification.md) for guidance.

## Target users

System architects, functional safety engineers, requirements engineers, platform/application/
middleware/embedded developers, verification and test automation engineers, integration and
DevOps engineers, cybersecurity engineers, quality engineers, and assessors.

See [ROADMAP.md](ROADMAP.md) for the full feature roadmap.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions require a DCO sign-off.

## License

Mozilla Public License v2.0. See [LICENSE](LICENSE).
