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

## v0.11 — Safety Case Generation ✅

**Goal:** Automated evidence assembly.

Features:
- Safety case assembly from existing evidence files
- Goal Structuring Notation (GSN) diagram output (Mermaid)
- Compliance clause mapping for ISO 26262, IEC 61508, ISO 21434, generic
- Gap detection — identifies absent evidence items
- Markdown + JSON + Mermaid output formats

Deliverables: `gofusa safety-case`

---

## v0.12 — Safety Analysis Generation ✅

**Goal:** Automatically derive safety analysis artefacts from code structure and requirements.

Features:
- **dFMEA generation** — parse function signatures, error paths, goroutine interactions, and
  requirement annotations to produce a Design Failure Mode and Effects Analysis table;
  each row maps a code item to its potential failure mode, effect, severity, detection
  control, and linked requirement/test evidence
- **Boundary diagram generation** — derive component boundary diagrams from Go package
  structure, exported interfaces, and `//fusa:req` annotations; output in Mermaid and
  DOT formats; shows trust boundaries, data flows, and external interfaces for ISO 21434
  threat modelling and ISO 26262 system design reviews
- FMEA worksheet export (CSV + JSON) suitable for import into DOORS, Polarion, or Excel
- Boundary diagram annotations in `.fusa.json` to label trust levels and interface types
- Engine rules flagging code paths with no FMEA entry and interface functions missing
  boundary annotations

Deliverables: `gofusa fmea`, `gofusa boundary`, FMEA worksheet, Mermaid/DOT boundary diagrams

---

## v0.13 — Audit Package & Vulnerability Scan ✅

**Goal:** Close the "evidence is present but incomplete" problem auditors always flag; add ISO 21434 cybersecurity evidence.

Features:
- **Vulnerability scan** — query go.mod dependencies against the OSV database (`api.osv.dev/v1/querybatch`); zero external deps; `VULN001` engine rule; ISO 21434 §8.5 compliance reference
- **Audit pack** — bundle all evidence artifacts into a single `audit-pack.zip` with SHA-256 manifest for auditor submission; `AUDITPACK001` engine rule
- **HTML report** — self-contained HTML page with findings table, evidence status cards, and PASS/WARN/FAIL badge; `gofusa report --format html`
- **Requirement quality rules** — `TRACE003` (test gap detection: req with no `//fusa:test`) + `TRACE004` (req missing text field); `gofusa trace --gaps` exit-1 gap report
- **`gofusa release --full`** — single command produces SBOM, provenance, dFMEA, boundary diagram, vulnerability scan, and audit pack

Deliverables: `gofusa vuln`, `gofusa audit-pack`, `gofusa report --format html`, `gofusa trace --gaps`, `gofusa release --full`

---

## v0.14 — Cybersecurity Analysis Rules ✅

**Goal:** CWE-mapped, ISO 21434-aligned static analysis for Go security weaknesses, inspired by Contrast Security scan rules, SEI CERT C, and MISRA-C:2023.

Features:
- **CYBER001** Weak hash (MD5/SHA-1) — CWE-327, ISO 21434 §8.5
- **CYBER002** Weak cipher (DES/3DES/RC4) — CWE-327, MISRA Dir 4.8
- **CYBER003** Insecure random (math/rand) — CWE-330, CERT MSC50
- **CYBER004** Unsafe pointer usage — CWE-242, MISRA Rule 11.3
- **CYBER005** Command injection (exec with variable cmd) — CWE-78
- **CYBER006** Hardcoded credential — CWE-798, ERROR severity
- **CYBER007** TLS certificate bypass (InsecureSkipVerify) — CWE-295, ISO 21434 §10.4, ERROR severity
- **CYBER008** HTTP server without timeouts — CWE-400
- **CYBER009** Integer narrowing conversion — CWE-190, MISRA Rule 10.3
- **CYBER010** String concatenation in OS path / DB query — CWE-22 / CWE-89

Deliverables: `cyber` package with 10 rules; 82.3% overall coverage; 20/20 packages pass

---

## v0.15 — Cybersecurity Deep Dive ✅

**Goal:** Complete the gosec rule set, add industry standards (IEC 62443, SLSA), integrate security evidence across dFMEA/TARA/requirements, and add govulncheck call-graph analysis.

Features:
- **CYBER011–020** — gosec-inspired rules: SSRF (CWE-918), pprof exposure (CWE-200), zip slip (CWE-23), TLS min version (CWE-326), SQL via fmt.Sprintf (CWE-89), permissive dir/file modes (CWE-732), path from request (CWE-22), TOCTOU (CWE-362), predictable temp file (CWE-377)
- **IEC 62443** — Security Level compliance checks (SL 1–4), SECURITY.md policy, incident response plan
- **SLSA L2/L3** — provenance field checks (vcsRevision, builder), CODEOWNERS/branch-protection evidence
- **govulncheck integration** — call-graph analysis wrapper; falls back to OSV API when binary absent
- **TARA generation** — `tara.Scan` + `tara.Render` (JSON/Markdown); `TARA001` engine rule; full ISO 21434 Ch. 9 metadata for CYBER001–020
- **CYBER→dFMEA enrichment** — `fmea.EnrichWithCyber` cross-references findings by file path
- **`//fusa:sec-test` annotation** — new trace tag kind; `SecTestedRequirements` in coverage summary
- **`gofusa cyber`** subcommand — runs CYBER rules, writes cyber-report.json
- **`gofusa tara`** subcommand — generates tara.json and tara.md
- **`gofusa fmea --cyber`** flag — enriches FMEA with security context
- **`gofusa release --full`** now additionally generates cyber-report.json, tara.json, tara.md

Deliverables: 23/23 packages pass; 0 lint issues; 152 requirements (REQ-CYBER011–020, REQ-IEC62443-001–004, REQ-SLSA001–003, REQ-VULN006, REQ-TARA001–005, REQ-FMEA006, REQ-TRACE005, REQ-CLI018–020)

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
- Design FMEA worksheet (derived from code + requirements)
- Component boundary diagrams (Mermaid / DOT)
- SBOM
- Build provenance
- Release signatures
- Audit package

suitable as the foundation of an ISO 26262 or IEC 61508 safety case.

This is the equivalent of what SonarQube, Coverity, VectorCAST, Polarion, and
various qualification tools collectively provide today, but as an open-source
Go-native ecosystem.
