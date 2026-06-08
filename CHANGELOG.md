# Changelog

All notable changes to this project are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Dates reference the merged commit timestamp.

## [Unreleased]

## [0.11.0] — 2026-06-08

### Added
- `safetycase` package — assembles structured safety case from evidence files (REQ-SC001–005)
- `safetycase.Build` — reads check-report.json, .fusa-reqs.json, .fusa-evidence.json, qualify-report.json, sbom.json, provenance.json; reports gaps for absent items
- `safetycase.Render` — Markdown (`text`), JSON, and Mermaid GSN diagram (`mermaid`) formats
- Compliance clause mappings for ISO 26262, IEC 61508, ISO 21434, and generic standards
- `SAFETYCASE001` engine rule — INFO finding when safety-case.json is absent
- `gofusa safety-case` CLI command — writes safety-case.json, safety-case.md, safety-case.mermaid (REQ-CLI012)
- 7 new requirements (REQ-CLI012, REQ-SAFETYCASE001, REQ-SC001–005), total 84

## [0.10.0] — 2026-06-08

### Added
- `gofusa lint` subcommand — runs only LINT* rules via the new `engine.RunFilter` predicate API (REQ-CLI008)
- `gofusa analyze` subcommand — runs only ANA* rules (REQ-CLI009)
- `gofusa template` subcommand — standalone safety document template generator (REQ-CLI010)
- `--strict` flag on `gofusa check` (and lint/analyze) — exits non-zero on any WARNING or ERROR finding (REQ-CLI011)
- `Config.Rules.Severity` map — per-rule severity overrides in `.fusa.json` (REQ-CFG008)
- `engine.Registry.RunFilter` — filtered rule execution with a `keep func(Rule) bool` predicate (REQ-ENG007)
- `release.ToSPDX31` — converts SBOM to SPDX 3.0.1 JSON-LD format; `gofusa release` now writes SPDX 3.0.1 SBOMs (REQ-RELEASE007)
- `release.BuildManifest` — SHA-256 artifact manifest (`artifact-manifest.json`) generated alongside SBOM and provenance (REQ-RELEASE008)
- DCO CI job — validates `Signed-off-by` on every PR commit
- Fuzz tests in `config`, `release`, `lint`, `analyze`, `trace`, and `verify` packages
- 8 new requirements (REQ-CLI008–011, REQ-CFG008, REQ-ENG007, REQ-RELEASE007–008), total 77

## [0.9.0] — 2026-06-07

### Added
- `qualify` package: built-in tool qualification suite with 44 test cases (positive and negative per rule), SHA-256-hashed `qualify-report.json`
- `QUALIFY001` engine rule checking for `qualify-report.json` presence
- `gofusa qualify` CLI command
- Docker multi-stage build (`Dockerfile`), `.dockerignore`, `docker-compose.yml`, CI Docker build job
- 68-requirement traceability (expanded from 22); all 68 requirements have `//fusa:req` and `//fusa:test` annotations
- `docs/qualification.md` — tool qualification guide for ISO 26262-8 / IEC 61508-6 / TCL1–TCL3
- `docs/tool-safety-manual.md` — this project's tool safety manual for auditor use
- `CHANGELOG.md` — this file
- `SECURITY.md` — vulnerability disclosure policy
- `Makefile` — developer workflow targets
- `sbom.json` and `provenance.json` committed in-tree; tool now passes its own RELEASE001/002 checks
- End-to-end integration test (`TestPipeline_EndToEnd`) exercising the full `init → check → trace → verify → release → qualify` pipeline
- `REQ-E2E001` system-level requirement for full-pipeline execution

## [0.7.0] — 2026-06-07

### Added
- `runtime` package: watchdog timer, heartbeat monitor, safe-state transition framework, diagnostic manager, fault monitor
- Runtime safety patterns usable as library code in safety-critical Go applications

## [0.6.0] — 2026-06-07

### Added
- `release` package: SBOM generation (parses `go.mod`/`go.sum`), build provenance record (platform + Go runtime snapshot), artifact SHA-256 hashing
- `RELEASE001` (missing `sbom.json`), `RELEASE002` (missing `provenance.json`) engine rules
- `gofusa release` CLI command

## [0.5.0] — 2026-06-07

### Added
- `verify` package: `go test -json -count=1 ./...` runner, structured test evidence bundle with per-test result detail
- `VERIFY001` (missing evidence bundle), `VERIFY002` (failed tests) engine rules
- `gofusa verify` CLI command

## [0.4.0] — 2026-06-07

### Added
- `trace` package: requirements traceability engine scanning `//fusa:req` and `//fusa:test` source annotations
- `TRACE001` (missing `.fusa-reqs.json`), `TRACE002` (unimplemented requirements) engine rules
- `gofusa trace` CLI command
- `.fusa-reqs.json` requirement registry format

## [0.3.0] — 2026-06-07

### Added
- `analyze` package: AST-based goroutine and concurrency safety analysis
- `ANA001` (unguarded goroutine), `ANA002` (goroutine in loop), `ANA003` (sleep in goroutine), `ANA004` (defer in loop) rules

## [0.2.0] — 2026-06-07

### Added
- `lint` package: safety-oriented Go coding standard checks
- `LINT001` (blank-identifier error discard), `LINT002` (panic call), `LINT003` (recover inventory), `LINT004` (unsafe import), `LINT005` (reflect import), `LINT006` (package-level var) rules

## [0.1.0] — 2026-06-07

### Added
- `fusa` root package: `Finding`, `Severity`, `Location` types; `ErrNoConfig`, `ErrInvalidConfig`, `ErrCheckFailed` sentinels
- `config` package: `.fusa.json` schema, `Load`, `Save`, `Validate`, `Default`; multi-standard support (ISO 26262, IEC 61508, ISO 21434, DO-178C, generic)
- `engine` package: rule registry, deterministic ordering, context-aware runner, exclusion support
- `report` package: text and JSON rendering, `RenderToFile`
- `cmd/gofusa`: CLI entry point; `init`, `check`, `report`, `version`, `help` commands
- `FUSA001`–`FUSA005` project-structure rules (`.fusa.json`, `go.mod`, `LICENSE`, `README.md`, CI config)
- `testutil` package: `MinimalProject()` fixture, `ProjectDir()` helper
- CI matrix: ubuntu / macOS / Windows × Go 1.22 / 1.23, race detector, golangci-lint, DCO sign-off check
