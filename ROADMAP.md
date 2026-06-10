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

## v0.4 ✅ — Traceability

**Goal:** Requirements → Code → Tests

Features:
- Requirement registry
- Requirement tags
- Traceability graph
- Coverage mapping

Deliverables: `gofusa trace`

---

## v0.5 ✅ — Test Evidence

**Goal:** Verification evidence generation.

Features:
- Coverage collection
- Test metadata
- Requirement verification mapping
- Evidence bundle generation

Deliverables: `gofusa verify`

---

## v0.6 ✅ — Release Evidence

**Goal:** Audit-ready releases.

Features:
- SBOM generation
- Build provenance
- Dependency inventory
- Artifact signatures

Deliverables: `gofusa release`

---

## v0.7 ✅ — Safety Patterns

**Goal:** Reusable runtime safety mechanisms.

Features:
- Watchdog framework
- Heartbeat framework
- Safe-state transitions
- Diagnostic manager
- Fault monitor

Deliverables: `go-fusa/runtime`

---

## v0.25 — x-FuSa Spec v1.9 conformance ✅

**Goal:** Adopt x-FuSa spec v1.9. All four SHOULD→MUST promotions (`category`, `remediation`,
`fingerprint`, `capabilities`) were already implemented in v0.24. Only change: bump
`fusa.SpecVersion` `"1.8"` → `"1.9"` so every emitted document declares the correct
`schemaVersion`. Remaining ▫️ items (trace/qualify/sbom/pack common header, `.fusa.json` full
schema, OCI image labels, `endLine/endColumn`, verify items) are SHOULD/MAY and carried forward.

### Version bump
- `fusa.SpecVersion` → `"1.9"` (propagates to `schemaVersion` in every emitted document).

Deliverables: `fusa.go` SpecVersion bump; version bump to 0.25.0

---

## v0.24 — x-FuSa Spec v1.8: Exit Codes & Canonical Gap-Report JSON ✅

**Goal:** Implement x-FuSa spec v1.8 compliance across the CLI and all gap-report packages,
making gofusa pipelines machine-readable by downstream tooling.

Features:

### Spec-correct exit codes (§2.3)
- `fusa.ExitOK` (0), `ExitGateFail` (1), `ExitUsage` (2), `ExitRuntime` (3) constants in `fusa.go`.
- All ~40 `cmd_*.go` files updated; a new `parseFlags()` helper centralises flag-parse error handling.
- Previously every failure returned bare `1`, preventing CI pipelines from distinguishing gate failures
  from bad arguments.

### Canonical §9.3 gap-report JSON
- New `gapreport/` package emits the shared schema:
  `{schemaVersion, kind, tool, toolVersion, language, generatedAt, projectRoot, standard, objectives[], summary}`.
- Status vocabulary: `satisfied` / `partial` / `gap` / `skip`.
- `iso26262`, `iec61508`, `do178`, `iso21434`, and `unece` `Render()` functions delegate to `gapreport`
  instead of encoding their private structs; all JSON output now shares one parseable shape regardless
  of the standard assessed.

### New files
- `gapreport/gapreport.go` — canonical report builder and renderer.
- `cmd/gofusa/helpers.go` — `parseFlags()`, `usageErrorf()`, `runtimeErrorf()`.
- `cmd/gofusa/cmd_capabilities.go` — `gofusa capabilities` command.
- `report/summary.go` — shared summary-rendering helpers.

### Version bump
- `fusa.Version` → `"0.24.0"`.

Deliverables: `gapreport/` package; `cmd/gofusa/helpers.go`; `cmd/gofusa/cmd_capabilities.go`;
`report/summary.go`; exit-code constants in `fusa.go`; version bump to 0.24.0

---

## v0.23 — Gap Fill: Mutation Testing, DOORS/Polarion Import/Export, ISO 21434, UN R.155, Workflow CI & Docs ✅

**Goal:** Close remaining evidence gaps by adding mutation-testing MC/DC evidence, DOORS and Polarion
requirements exchange, ISO 21434 and UN R.155 compliance gap reports, three new CI workflow files,
comprehensive command and standard reference documentation, and a full test-coverage pass lifting
overall coverage above 80 %.

Features:

### Evidence quality
- **`gofusa coverage --mutate`** — mutation testing via `go-mutesting`; produces `MutationReport`
  with per-package killed/survived/score; sets `MCDCEvidence` string when score ≥ 80 % (DO-178C Level A).

### Requirements exchange
- **`trace.ParseDOORS` / `ExportDOORS`** — ReqIF XML round-trip for IBM DOORS / DOORS Next.
- **`trace.ParsePolarion` / `ExportPolarion`** — Polarion XML round-trip.
- **`gofusa req import/export --format doors|polarion`** — CLI wiring for both formats.

### ISO 21434 & UN R.155
- **`iso21434/` package** — `Assess(root, calStr)` with 14 automatable + 7 MANUAL objectives,
  CAL 1–4 levels, engine rule ISO21434001.
- **`unece/` package** — UN R.155 Annex 5 threat categories (6 automatable, 3 MANUAL), engine rule
  UNECE001, `gofusa unece` command.
- **`gofusa iso21434`** command — writes `iso21434-gap-report.json`.
- **`safetycase` iso21434 mappings** — 10 clause entries added.

### CI workflows
- **`.github/workflows/codeql.yml`** — weekly CodeQL analysis on Go source (security-extended queries).
- **`.github/workflows/ci.yml`** — `sarif:` job added; `concurrency:` cancel-in-progress block added.
- **`.github/workflows/release.yml`** — cross-platform binary build (linux/darwin/windows) + GitHub
  Release creation on `v*` tags.

### Documentation
- **`docs/commands/`** — check, lint, analyze, trace, release reference pages.
- **`docs/standards/`** — iso26262, iec61508, do178c, iso21434, iec62443, misra-c reference pages.

### Coverage improvements
- Targeted tests for COUP003, IEC61508001, ISO26262001–003, `runCoupling`, `runGovulncheck`,
  `runTraceSecTested`, `isNolinted`, `BuildFromFile`, `vcsInfo`, `isRequestDerived`, `isTempPath`,
  `runSas`, `moduleFromRoot`, `countRequirements`, `runReqShow/Export`, `runReport`.
- Overall coverage raised to ≥ 80 %.

### Version bump
- `fusa.Version` → `"0.23.0"`.

Deliverables: `coverage.RunMutation`; `trace/reqxml.go`; `iso21434/` package; `unece/` package;
`cmd_iso21434.go`; `cmd_unece.go`; `.github/workflows/codeql.yml`; `.github/workflows/release.yml`;
`docs/commands/` (5 files); `docs/standards/` (6 files); version bump to 0.23.0

---

## v0.22 — SPDX 2.x Support, Evidence Gap Coverage & ASIL Integrity Checks ✅

**Goal:** Broaden SBOM output to cover SPDX 2.2 and 2.3 alongside the existing 3.0.1 support;
close evidence gaps across ISO 26262, IEC 61508, and DO-178C gap reports by mapping previously
MANUAL objectives to machine-checkable evidence files; and add engine rules that detect ASIL
inconsistencies and qualification depth issues at `gofusa check` time.

Features:

### SBOM / SPDX

- **SPDX 2.2 and 2.3** — `release.ToSPDX22` / `release.ToSPDX23` produce standard JSON SBOMs
  with `SPDXID`, `spdxVersion`, `creationInfo`, `packages`, and `relationships`.
- **`gofusa release --spdx-version`** flag — selects `2.2`, `2.3`, or `3.0.1` (default: `3.0.1`).

### Coupling report

- **`gofusa coupling`** command — analyses the project tree and writes `coupling-report.json`
  containing dated data-coupling and control-coupling findings.
- **`coupling.SaveReport`** — serialisation helper for programmatic report generation.
- **COUP003** engine rule — INFO when DO-178C project lacks `coupling-report.json`.

### Traceability

- **`trace.Requirement.ASIL`** field — optional `asil` tag on `.fusa-reqs.json` requirements.

### HARA integrity

- **HARA005** engine rule — WARNING when the highest hazard ASIL in `.fusa-hara.json` exceeds
  the project ASIL in `.fusa.json`.

### ISO 26262 gap-report

- Obj 7.3 → `.fusa-hara.json` (was `HARA.md`).
- New obj 10.4 — SCI (`sci.json`), ASIL-B/C/D.
- New obj 11.3 — coupling evidence (`coupling-report.json`), ASIL-C/D.
- **ISO26262002** — INFO when ISO 26262 requirements lack `asil` tags.
- **ISO26262003** — WARNING when `qualify-report.json` contains failures.

### IEC 61508 gap-report

- Obj 1.3 → `.fusa-hara.json` (was MANUAL).
- Obj 4.2 → `fmea.json` (was MANUAL).
- New obj 5.4 — SCI (`sci.json`), SIL-2/3/4.

### DO-178C gap-report

- A-2.2 — LLR detection from `.fusa-reqs.json` (was MANUAL).
- A-6.2 → `check-report.json` (was MANUAL).
- A-6.3 → `coupling-report.json` (was MANUAL).
- `check` function field in `allObjectives` is now invoked during `Assess()`.

Deliverables: `release.ToSPDX22/ToSPDX23`; `cmd_coupling.go`; `coupling.SaveReport`;
COUP003, HARA005, ISO26262002, ISO26262003; updated iso26262/iec61508/do178 objectives;
version bump to 0.22.0

---

## v0.21 — HARA Package, ISO 26262 Clause Mapping & Project Safety Case ✅

**Goal:** Elevate go-FuSa's ISO 26262 support from gap-assessment to full HARA-backed hazard
management; expand the safety-case compliance mapping to cover Parts 4, 5, 6, and 8 in detail;
and apply go-FuSa to its own development by adding `.fusa.json` (ISO26262, ASIL-B) and
`.fusa-hara.json` documenting tool-failure hazards.

Features:

### `hara/` package

- **Structured HARA data model** (`.fusa-hara.json`) — `OperationalSituation`, `Hazard`,
  `RiskRating`, `SafetyGoal`, and `HARA` types with full JSON round-trip.
- **`DetermineASIL`** — complete ISO 26262-3:2018 Table 4 lookup covering all 48 S×E×C
  combinations for S1–S3 and E1–E4 (S0 and E0 always return QM).
- **`Load` / `Save`** — read/write `.fusa-hara.json` with graceful missing-file handling.
- **`Validate`** — returns `ValidationFinding` list for incomplete risk ratings (HARA002),
  hazards without safety goals (HARA003), unknown goal references, and goals missing ASIL
  (HARA004).
- **`Render`** — text/markdown and JSON output including a Gaps section when `Validate`
  returns findings.
- **Engine rules:** HARA001 (no HARA file — INFO normally, WARNING for ISO26262/IEC61508
  projects), HARA002 (incomplete S/E/C), HARA003 (hazard has no safety goal), HARA004
  (safety goal has no ASIL).

### `gofusa hara` CLI

- **`gofusa hara show`** — render `.fusa-hara.json` as text, markdown, or JSON; exits 0 even
  with gaps (gaps appear in the output).
- **`gofusa hara init`** — create a starter `.fusa-hara.json` with one example hazard/goal;
  refuses to overwrite an existing file.
- **`gofusa hara asil`** — derive ASIL from `-s`, `-e`, `-c` flags using Table 4.

### ISO 26262 safety-case clause mapping

`safetycase.mappingsFor("iso26262")` expanded from 5 sparse entries to 15 entries covering:
- Part 4 §7 (technical safety requirements), §8 (system design / safety mechanisms), §9
  (system integration and testing)
- Part 5 §7 (hardware design — informative for SW-only projects)
- Part 6 §6 (SW safety requirements), §7 (SW architectural design), §8 (SW unit design/
  implementation), §9 (SW unit verification), §10 (SW integration and testing), §11 (SW
  functional safety testing), §12 (coding guidelines / dependent failure analysis)
- Part 8 §7 (configuration management), §8 (change management), §11 (tool qualification)

### go-FuSa project files

- **`.fusa.json`** — updated to `standard: "ISO26262"`, `asil: "ASIL-B"` (go-FuSa itself is
  a safety-tool and is treated as ASIL-B per its own HARA).
- **`.fusa-hara.json`** — five tool-failure hazards documented: H-001 false negative (ASIL-C),
  H-002 wrong ASIL determination (ASIL-B), H-003 silent failure exit 0 (ASIL-A), H-004
  evidence integrity violation (ASIL-A), H-005 config silently disables checks (ASIL-B).

Deliverables: `hara/` package; `cmd_hara.go`; expanded `safetycase/mappingsFor`; `.fusa.json`;
`.fusa-hara.json`; version bump to 0.21.0

---

## v0.20 ✅ — Multi-Standard Depth, Evidence Quality & Developer Workflow

**Goal:** Bring ISO 26262 and IEC 61508 to feature parity with the DO-178C evidence pipeline;
upgrade the evidence bundle to auditor-ready HTML; close the MC/DC verification gap for
DO-178C Level A; and deliver the three most-requested developer workflow features: finding
disposition tracking, change impact analysis, requirements import/export, safety metrics
trending, and MISRA C:2023 alignment reporting.

Features:

### Standard parity

- **`gofusa iso26262`** — ISO 26262 gap assessment covering ASIL decomposition evidence,
  FMEA-to-hazard linkage checks, and safety plan completeness (analogous to `gofusa do178`).
  Includes an ASIL allocation table derived from `.fusa.json` and engine rules flagging
  missing safety goals, unlinked hazards, and absent confirmation measures (Part 2 §6).
- **`gofusa iec61508`** — IEC 61508 gap assessment: SIL allocation verification, functional
  safety assessment checklist (Parts 1–3), and evidence index for the Safety Requirements
  Specification and Software Safety Requirements. Mirrors the 38-objective structure of
  `gofusa do178`.
- **Safety plan templates** — ISO 26262 FMEA worksheet, Hazard and Risk Analysis (HARA)
  template, and IEC 61508 Functional Safety Plan added to `gofusa template`.

### Evidence quality

- **HTML evidence bundle** — `gofusa release --full` produces a self-contained `evidence.html`
  with navigable sections for each evidence type (findings, traceability, coverage, SBOM,
  vulnerability scan, SCI). Suitable for direct auditor submission without additional tooling.
- **`gofusa coverage --mutate`** — mutation testing integration via `go-mutesting` (or
  equivalent) to produce MC/DC-equivalent kill-rate evidence for DO-178C Level A. Reports
  mutation score per function alongside the structural coverage report.

### Developer workflow

- **`gofusa disposition`** — finding disposition log (`.fusa-dispositions.json`). Record
  accepted findings with rationale, reviewer, and date; `gofusa check` cross-references
  open findings against the log and marks each as `fixed`, `accepted`, or `open`. Engine
  rule DISP001 fires when ERROR-severity findings have no disposition entry. Closes the most
  common audit gap: evidence that every finding was reviewed before release.
- **`gofusa impact`** — change impact analysis. Given a git diff or two commit SHAs, reports
  which requirements are affected by changed files, which tests should be re-run, and which
  evidence artefacts are stale. Maps to DO-178C §7.2 (regression analysis) and ISO 26262-8
  §7 (configuration management). Unique to go-FuSa — no other open-source Go tool provides
  this.
- **`gofusa req import/export`** — requirements round-trip for CSV, DOORS XML, and Polarion
  XML. `gofusa req import --format csv requirements.csv` populates `.fusa-reqs.json`;
  `gofusa req export --format csv` produces a spreadsheet-ready file. Removes the primary
  onboarding friction for teams migrating from document-centric toolchains.
- **`gofusa metrics`** — safety metrics trending. Appends a timestamped snapshot (finding
  counts by severity, coverage %, requirement density, untraced count, annotation density)
  to `.fusa-metrics.json`. `gofusa metrics --format text` renders a trend table. Gives
  auditors the "show me the trend" evidence without external tooling.
- **`gofusa misra`** — MISRA C:2023 alignment report. Maps each MISRA C rule to its Go-
  language equivalent (existing go-FuSa rule, built-in `go vet` check, or documented
  inapplicable/N/A), and generates a gap report. Addresses the single most-asked question
  from automotive teams migrating codebases from C/C++.

Deliverables: `iso26262/`, `iec61508/`, `disposition/`, `impact/`, `metrics/`, `misra/`
packages; `cmd_iso26262`, `cmd_iec61508`, `cmd_disposition`, `cmd_impact`, `cmd_metrics`,
`cmd_misra`; `req import/export` subcommands; `evidence.html` in `gofusa release --full`;
`--mutate` flag on `gofusa coverage`; ISO 26262 + IEC 61508 plan templates; DISP001 engine rule

---

## v0.19 — Requirement Coverage Assessment ✅

**Goal:** Quantify how well requirements are traced into source code and surface actionable
metrics and CI gates for DO-178C §6.4.4 traceability objectives.

Features:
- **`ScanFuncCoverage`** — new exported function: walks non-test Go files, counts exported
  functions, and reports what fraction live in files with `//fusa:req` annotations.
- **TRACE006** — aggregate WARNING when fewer than 80% of requirements have `//fusa:req`
  implementation annotations. Complements the per-requirement TRACE002.
- **TRACE007** — aggregate INFO when exported-function annotation density falls below 80%.
- **`gofusa trace --req-coverage N`** — CI gate reporting both metrics (requirement traceability
  and function annotation density) and exiting 1 if either falls below N%.

Deliverables: `trace.ScanFuncCoverage`, `trace.FuncCoverage`, TRACE006, TRACE007,
`--req-coverage` flag, `DefaultReqCoverageThreshold`, `DefaultFuncAnnotationThreshold`

---

## v0.18 — DO-178C Deep Coverage ✅

**Goal:** Close the gap between go-FuSa's evidence pipeline and a complete DO-178C submission
package. Adds five new evidence-generating commands, four new analysis rules, and the
infrastructure to assess Annex A compliance automatically.

Features:
- **`comp/` package + COMP001** — cyclomatic complexity rule (V(G)). Flags functions > threshold.
- **`coupling/` package + COUP001/COUP002** — data coupling (exported vars) and control coupling
  (func/interface parameters). DO-178C §6.4.4.3.
- **ANA009** — dead code after unconditional `return`/`break`/`continue`/`panic`. DO-178C §6.4.4.2.
- **TRACE005** — verification independence: same file annotates both req and test.
- **`sci/` package + `gofusa sci`** — Software Configuration Index with SHA-256 (DO-178C §11.16).
- **`coverage/` package + `gofusa coverage`** — structural coverage report from `coverage.out`
  (statement + estimated decision + MC/DC requirement flag). DO-178C §6.4.4.
- **`pr/` package + `gofusa pr`** — problem report CRUD log + PR001 engine rule. DO-178C §11.17.
- **`do178/` package + `gofusa do178`** — 38-objective Annex A gap assessment (PASS/GAP/MANUAL/N/A).
- **`sas/` package + `gofusa sas`** — Software Accomplishment Summary (DO-178C §11.20).
- **Plan templates** — SVP, SCMP, SQAP added to `gofusa template`; `--type all` now generates all four.

Deliverables: `comp/`, `coupling/`, `coverage/`, `pr/`, `sci/`, `do178/`, `sas/` packages;
`cmd_do178`, `cmd_sas`, `cmd_sci`, `cmd_coverage`, `cmd_pr`; ANA009; COUP001/COUP002; TRACE005

---

## v0.17 — Developer Workflow Integration ✅

**Goal:** Make go-FuSa a daily-driver tool with richer output formats, CI regression gates,
and developer-facing commands.

Features:
- **SARIF output** — `gofusa check --format sarif` for GitHub Advanced Security / Code Scanning
- **SVG badge** — `gofusa badge` generates a Shields.io-style status badge from a JSON report
- **Diff command** — `gofusa diff baseline.json current.json` categorises new/resolved/unchanged
  findings; exits 1 on regressions (CI gate)
- **`--sec-tested` gate** — `gofusa trace --sec-tested 80` enforces ≥80% requirements have tests
- **`gofusa req`** — inspect requirements and their impl/test annotation locations
- **`gofusa fix`** — surfaces auto-fixable findings with per-finding remediation guidance
- **`gofusa hooks`** — install/remove a `gofusa check --strict` pre-commit git hook
- **`gofusa sign`** — HMAC-SHA256 sign and verify release artifacts; `--keygen` for key generation
- **ANA005–ANA008** — four new static analysis rules: context propagation, error wrapping,
  nil dereference risk, and goroutine/package-level variable races

Deliverables: `sarif/`, `badge/`, `diff/` packages; `cmd_diff`, `cmd_badge`, `cmd_req`,
`cmd_fix`, `cmd_hooks`, `cmd_sign`; `analyze/rules_005_008.go`

---

## v0.16 — Docker Quickstart ✅

**Goal:** Zero-install evaluation and CI integration via container.

Features:
- Official Docker image (`ghcr.io/soundmatt/go-fusa`) published to GHCR on every tag
- Multi-stage build: minimal Alpine runtime image (~10 MB)
- `docker run` one-liners for `check`, `trace`, `verify`, `release`, `cyber`
- `docker-compose.yml` for the full evidence-generation pipeline
- GitHub Actions usage example (`.github/gofusa-example.yml`)
- Volume-mount pattern for scanning a host project (`-v "$(pwd)":/project`)
- Automated publish workflow (`.github/workflows/docker-publish.yml`) triggered on `v*` tags

Deliverables: `Dockerfile`, `docker-compose.yml`, `docker-publish.yml`, `gofusa-example.yml`, updated `README.md`

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
