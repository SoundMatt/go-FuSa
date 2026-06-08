# go-FuSa Roadmap

## Vision

go-FuSa is the functional safety enablement layer for Go-based systems.
It provides safety-oriented coding standards, static analysis, traceability,
evidence generation, runtime safety patterns, and compliance tooling that
help organizations build safety cases for ISO 26262, IEC 61508, ISO 21434,
DO-178C-inspired processes, and related standards.

It is **NOT** a certification product.
It is an engineering accelerator that reduces the cost of producing
functional safety evidence throughout the SDLC.

---

## v0.1 — Foundation

**Goal:** Create the safety foundation.

Features:
- CLI framework (`gofusa`)
- Project configuration
- Report generation
- CI integration
- Rule engine
- Documentation templates

Deliverables: `gofusa init`, `gofusa report`, `gofusa check`

---

## v0.2 — Coding Standard ✅

**Goal:** Safety-oriented Go coding guidelines.

Features:
- Error handling enforcement
- Panic detection
- Recover policy checks
- Unsafe package inventory
- Reflection inventory
- Global state detection

Deliverables: `gofusa lint`

---

## v0.3 — Static Analysis ✅

**Goal:** Detect safety risks automatically.

Features:
- Custom `go/analysis` engine
- Race-prone pattern detection
- Goroutine leak detection
- Blocking call detection
- Resource lifecycle analysis

Deliverables: `gofusa analyze`

---

## v0.4 — Traceability

**Goal:** Requirements → Code → Tests

Features:
- Requirement registry
- Requirement tags
- Traceability graph
- Coverage mapping

Deliverables: `gofusa trace`

---

## v0.5 — Test Evidence

**Goal:** Verification evidence generation.

Features:
- Coverage collection
- Test metadata
- Requirement verification mapping
- Evidence bundle generation

Deliverables: `gofusa verify`

---

## v0.6 — Release Evidence

**Goal:** Audit-ready releases.

Features:
- SBOM generation
- Build provenance
- Dependency inventory
- Artifact signatures

Deliverables: `gofusa release`

---

## v0.7 — Safety Patterns

**Goal:** Reusable runtime safety mechanisms.

Features:
- Watchdog framework
- Heartbeat framework
- Safe-state transitions
- Diagnostic manager
- Fault monitor

Deliverables: `go-fusa/runtime`

---

## v0.8 — Docker Quickstart

**Goal:** Zero-install evaluation and CI integration via container.

Features:
- Official Docker image (`ghcr.io/soundmatt/go-fusa`)
- Multi-stage build: minimal runtime image (~10 MB)
- `docker run` one-liners for `init`, `check`, `trace`, `verify`, `release`
- `docker-compose` example for full pipeline
- GitHub Actions step using the container image
- Volume-mount pattern for scanning a host project

Deliverables: `Dockerfile`, `docker-compose.yml`, updated `README.md`, GitHub Actions example

---

## v0.9 — Tool Qualification ✅

**Goal:** Support use in regulated environments.

Features:
- Qualification guide
- Validation suite
- Tool confidence evidence
- Self-test framework

Deliverables: Tool Qualification Kit

---

## v0.10 — Gap Closure ✅

**Goal:** Close audit gaps identified in v0.9 self-qualification.

Features:
- `gofusa lint` and `gofusa analyze` as dedicated CLI subcommands
- `gofusa template` standalone document generator
- `--strict` flag on `gofusa check` (WARNING-or-above exits non-zero)
- Per-rule severity overrides in `.fusa.json` (`rules.severity` map)
- SPDX 3.0.1 JSON-LD SBOM output
- Artifact manifest (`artifact-manifest.json`) with SHA-256 hashes
- DCO CI enforcement on all PRs
- Fuzz tests across parser-heavy packages

Deliverables: `gofusa lint`, `gofusa analyze`, `gofusa template`, `--strict`, SPDX 3.0.1 SBOM, artifact manifest

---

## v0.11 — Safety Case Generation

**Goal:** Automated evidence assembly.

Features:
- Safety case templates
- Goal Structuring Notation (GSN)
- Compliance report generation

Deliverables: `gofusa safety-case`

---

## v1.0 — Enterprise Ready

**Goal:** Production adoption.

Features:
- Policy engine
- Organization-wide dashboards
- Multi-repository aggregation
- REST API
- Web UI

Deliverables: Enterprise-grade OSS release

---

## Future / Advanced Capabilities

| Version | Capability |
|---|---|
| v1.1 | Runtime Monitoring — health telemetry, safety KPI collection, fleet reporting |
| v1.2 | Timing Analysis — WCET approximation, scheduler analysis, latency monitoring |
| v1.3 | Formal Methods — TLA+ integration, model checking support |
| v1.4 | AI-Assisted Safety Reviews — requirement quality, hazard and architecture review assistance |
| v1.5 | Digital Thread Integration — DOORS, Polarion, Jama, Codebeamer |

---

## Long-Term Goal

A developer should be able to run:

```
gofusa release
```

and automatically produce:

- Safety coding compliance report
- Static analysis results
- Requirement traceability matrix
- Test coverage report
- Verification evidence
- SBOM
- Build provenance
- Release signatures
- Audit package

suitable as the foundation of an ISO 26262 or IEC 61508 safety case.

This is the equivalent of what SonarQube, Coverity, VectorCAST, Polarion, and
various qualification tools collectively provide today, but as an open-source
Go-native ecosystem.
