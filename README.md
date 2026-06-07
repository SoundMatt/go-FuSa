# go-FuSa

A functional safety enablement toolkit for Go projects. go-FuSa provides static checks,
coding rules, traceability helpers, CI evidence bundles, reproducible build metadata, and
documentation templates to support ISO 26262 and IEC 61508 safety cases.

[![CI](https://github.com/SoundMatt/go-FuSa/actions/workflows/ci.yml/badge.svg)](https://github.com/SoundMatt/go-FuSa/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/SoundMatt/go-FuSa.svg)](https://pkg.go.dev/github.com/SoundMatt/go-FuSa)

> **Not a certification product.** go-FuSa is an engineering accelerator that reduces
> the cost of producing functional safety evidence throughout the SDLC.

## Packages

| Package | Description |
|---|---|
| `cmd/gofusa` | CLI — `init`, `check`, `report`, `lint`, `analyze`, `trace`, `verify`, `release` |
| `lint/` | Safety-oriented coding rules (error handling, panic, unsafe, globals) |
| `analyze/` | Static analysis passes (goroutine leaks, race patterns, blocking calls) |
| `trace/` | Requirements traceability engine and coverage mapping |
| `verify/` | Test evidence collection and verification bundle generation |
| `release/` | SBOM generation, build provenance, artifact signing |
| `runtime/` | Reusable safety patterns — watchdog, heartbeat, safe-state transitions |
| `testutil/` | Test harness helpers |

## Install

```bash
go get github.com/SoundMatt/go-FuSa
```

Install the CLI:

```bash
go install github.com/SoundMatt/go-FuSa/cmd/gofusa@latest
```

## Quick start

```bash
# Initialise a project
gofusa init

# Check coding standard compliance
gofusa lint ./...

# Run static analysis
gofusa analyze ./...

# Generate a compliance report
gofusa report
```

## Standards coverage

| Standard | Scope |
|---|---|
| ISO 26262 | Automotive functional safety (ASIL A–D) |
| IEC 61508 | General functional safety (SIL 1–4) |
| ISO 21434 | Automotive cybersecurity (evidence hooks) |
| DO-178C | Aerospace software (process alignment) |

## Target users

System architects, functional safety engineers, requirements engineers, platform/application/
middleware/embedded developers, verification and test automation engineers, integration and
DevOps engineers, cybersecurity engineers, quality engineers, and assessors.

See [ROADMAP.md](ROADMAP.md) for the full feature roadmap.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions require a DCO sign-off.

## License

Mozilla Public License v2.0. See [LICENSE](LICENSE).
