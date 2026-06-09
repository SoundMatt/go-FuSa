# Changelog

All notable changes to this project are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Dates reference the merged commit timestamp.

## [Unreleased]

## [0.21.0] — 2026-06-09

### Added
- **`hara/` package + `gofusa hara show|init|asil`** — structured Hazard Analysis and Risk
  Assessment backed by `.fusa-hara.json`. Types: `OperationalSituation`, `Hazard`, `RiskRating`,
  `SafetyGoal`, `HARA`. `DetermineASIL(S, E, C)` implements the full ISO 26262-3:2018 Table 4
  (48 combinations, S1–S3 × E1–E4 × C0–C3). `Validate` returns gap findings for incomplete risk
  ratings, hazards without safety goals, unknown goal references, and goals missing ASIL.
  `Render` produces text/markdown and JSON output including a Gaps section.
- **Engine rules HARA001–HARA004** — HARA001 fires INFO when `.fusa-hara.json` is absent
  (upgraded to WARNING for `ISO26262` or `IEC61508` projects). HARA002: hazard has incomplete
  S/E/C. HARA003: hazard has no linked safety goal. HARA004: safety goal has no ASIL.
- **`gofusa hara asil`** — derives ASIL from `-s`, `-e`, `-c` flags using Table 4.
  Example: `gofusa hara asil -s S2 -e E4 -c C2` → `ASIL-C`.
- **ISO 26262 safety-case clause mapping** — `safetycase.mappingsFor("iso26262")` expanded from
  5 sparse entries to 15 entries covering: Part 4 §7/§8/§9 (system), Part 5 §7 (HW, informative
  for SW-only), Part 6 §6/§7/§8/§9/§10/§11/§12 (software), Part 8 §7/§8/§11 (supporting
  processes). Each entry references the evidence IDs that satisfy the clause.
- **go-FuSa project safety files** — `.fusa.json` updated to `standard: "ISO26262"`,
  `asil: "ASIL-B"`. New `.fusa-hara.json` documents five tool-failure hazards: H-001 false
  negative (ASIL-C), H-002 wrong ASIL determination (ASIL-B), H-003 silent exit-0 failure
  (ASIL-A), H-004 evidence integrity violation (ASIL-A), H-005 config suppresses checks (ASIL-B).
- **Requirements coverage** — `//fusa:req` annotation added to every previously-unannotated
  exported function across 14 packages (config, coupling, cyber, engine, iec62443, pr, qualify,
  release, report, testutil, trace, verify, and hara).
- **Test coverage** — total 80.8% → 81.8%. Key gains: `trace` 80.5% → 88.2%
  (`renderText` all branches, TRACE005 same-file/different-file paths); `impact` 78.1% → 95.3%
  (`appendUniq` 0%→100%, `Analyse` uncovered branches); `vuln` 65.4% → 75.5%
  (`countModDeps` and `moduleFromRoot` 0%→100% via internal tests).
- **Version bump** — `fusa.Version` → `"0.21.0"`.

## [0.20.0] — 2026-06-09

### Added
- **`iso26262/` package + `gofusa iso26262`** — ISO 26262 Part 6/7/8/9/10/11 compliance gap
  report. `Assess(projectRoot, project, asil)` maps 19 objectives across Parts 6-11 to evidence
  files and returns PASS/GAP/MANUAL/N/A per objective. Supports ASIL-A through ASIL-D.
  Engine rule `ISO26262001` fires INFO when `iso26262-gap-report.json` is absent.
- **`iec61508/` package + `gofusa iec61508`** — IEC 61508 Parts 1-3 compliance gap report.
  `Assess(projectRoot, project, sil)` maps 26 objectives to evidence files. Supports SIL-1
  through SIL-4. Engine rule `IEC61508001` fires INFO when `iec61508-gap-report.json` is absent.
- **`disposition/` package + `gofusa disposition add|list|show`** — finding disposition log
  (`.fusa-dispositions.json`). Records accepted or scheduled-fix decisions for ERROR findings
  with reviewer attribution. Engine rule `DISP001` fires WARNING for each undispositioned ERROR
  finding in `check-report.json`.
- **`impact/` package + `gofusa impact`** — change impact analysis. Runs `git diff` to discover
  changed files, cross-references requirement annotations (`//fusa:req`) to find impacted
  requirements, identifies test files that need re-running, and checks whether evidence
  artefacts (`.fusa-evidence.json`, `coverage-report.json`, etc.) are stale relative to
  changed source files.
- **`metrics/` package + `gofusa metrics record|show`** — safety metrics time series stored in
  `.fusa-metrics.json`. `Collect` reads `check-report.json`, `.fusa-reqs.json`, and
  `coverage-report.json` to build a point-in-time snapshot. `Render` produces a text table
  or JSON time series.
- **`misra/` package + `gofusa misra`** — static MISRA C:2023 to Go / go-FuSa rule coverage
  mapping. Provides 90+ rules mapped to `go vet / compiler`, go-FuSa rules (LINT001, LINT004,
  ANA009, CYBER001-CYBER009, COMP001), `N/A — Go type system prevents this`, or `manual review`.
- **`gofusa req import/export`** — CSV import/export for `.fusa-reqs.json`. `import` merges
  new requirements from a CSV (columns: id, title, text, standard, level) skipping duplicates.
  `export` writes all requirements to CSV (stdout or file). Uses only stdlib `encoding/csv`.
- **`report.RenderEvidenceHTML`** — self-contained HTML evidence bundle generator. Reads up to
  16 evidence files across 8 sections (Findings, Traceability, Coverage, SBOM, Vulnerability
  Scan, SCI, Problem Reports, Qualification), shows PASS/WARN/FAIL badge based on
  `check-report.json`, and includes key metrics per section. Generated automatically by
  `gofusa release --full` as `evidence.html`.
- **Template additions** — `gofusa template --type iec61508-fsp` generates an IEC 61508
  Functional Safety Plan (`IEC61508-FSP.md`). `--type iso26262-fmea` generates an ISO 26262
  FMEA worksheet (`ISO26262-FMEA.md`). Both are included in `--type all`.
- **Version bump** — `fusa.Version` → `"0.20.0"`.

## [0.19.0] — 2026-06-09

### Added
- **`ScanFuncCoverage` + TRACE006 + TRACE007** — requirement coverage assessment (DO-178C §6.4.4).
  - `trace.ScanFuncCoverage(root, tags)` walks non-test Go files and returns exported-function
    annotation density: how many exported functions live in files with at least one `//fusa:req`
    annotation.
  - `TRACE006` — fires a WARNING when aggregate requirement-to-source traceability falls below
    80% (i.e., fewer than 80% of requirements in `.fusa-reqs.json` have any `//fusa:req` tag).
    Complements the per-requirement TRACE002.
  - `TRACE007` — fires an INFO when exported-function annotation density falls below 80%
    (i.e., fewer than 80% of exported functions are in files with `//fusa:req` annotations).
  - `gofusa trace --req-coverage N` — CI gate reporting both metrics and exiting 1 if either
    falls below N% when data exists. Mirrors the existing `--sec-tested` gate.
- `DefaultReqCoverageThreshold = 80` and `DefaultFuncAnnotationThreshold = 80` constants
  exported from the `trace` package.

## [0.18.0] — 2026-06-08

### Added
- **`comp/` package + COMP001** — cyclomatic complexity rule (V(G) = 1 + branches).
  Flags functions with complexity > 10 (configurable via `DefaultThreshold`). Maps to
  DO-178C §6.3.4 / DAL-A ≤ 4, DAL-B ≤ 10 guidance.
- **`coupling/` package + COUP001/COUP002** — data/control coupling detection.
  COUP001 flags exported mutable package-level variables (data coupling).
  COUP002 flags exported functions accepting `func`/`interface` parameters (control coupling).
  Both map to DO-178C §6.4.4.3.
- **ANA009** — dead code after unconditional `return`/`break`/`continue`/`panic` within the
  same block. DO-178C §6.4.4.2 prohibits deactivated code at DAL-A/B.
- **TRACE005** — verification independence: same source file has both a `//fusa:req` and
  `//fusa:test` annotation for the same requirement (DO-178C §6.4.2).
- **`sci/` package + `gofusa sci`** — Software Configuration Index (DO-178C §11.16).
  Scans 26 standard lifecycle data items, computes SHA-256 checksums, outputs JSON or
  Markdown.
- **`coverage/` package + `gofusa coverage`** — structural coverage report from a Go
  `coverage.out` profile. Reports statement coverage, estimated decision coverage (block-level
  proxy), and MC/DC requirement flag per DAL. Maps to DO-178C §6.4.4 / Annex A Table A-7.
- **`pr/` package + `gofusa pr init/add/list/close`** — problem report log (DO-178C §11.17).
  JSON log stored in `.fusa-problems.json`. Engine rule PR001 reports missing log (INFO) or
  open critical PRs (ERROR).
- **`do178/` package + `gofusa do178`** — DO-178C Annex A gap report. Maps evidence files to
  38 objectives across Tables A-1 through A-11; status is PASS/GAP/MANUAL/N/A. Exits 1 when
  any GAPs remain.
- **`sas/` package + `gofusa sas`** — Software Accomplishment Summary (DO-178C §11.20).
  Checks 20 evidence items, generates Markdown or JSON; exits 1 when evidence is incomplete.
- **DO-178C plan templates** (`gofusa template --type svp/scmp/sqap`) — SVP, SCMP, and SQAP
  document templates added alongside the existing SDP; `--type all` now generates all four.

## [0.17.0] — 2026-06-08

### Added
- **`sarif/` package + `gofusa check --format sarif`** — SARIF 2.1.0 output for GitHub
  Advanced Security / Code Scanning integration. Maps ERROR→`error`, WARNING→`warning`,
  INFO→`note`.
- **`badge/` package + `gofusa badge` command** — generates a Shields.io-style flat SVG
  status badge from a JSON check report. Three states: passing (green), warnings (yellow),
  failing (red).
- **`diff/` package + `gofusa diff` command** — compares two `gofusa check --format json`
  reports and categorises findings as introduced, resolved, or unchanged. Exits 1 if new
  findings were introduced; suitable as a CI regression gate.
- **`gofusa trace --sec-tested N`** — exits 1 if fewer than N% of requirements have
  `//fusa:test` annotations; enforces a quantitative test-coverage gate.
- **`gofusa req` command** — shows requirements from `.fusa-reqs.json` with their source
  (`//fusa:req`) and test (`//fusa:test`) location listings.
- **`gofusa fix` command** — lists auto-fixable findings from `gofusa check` with their
  remediation guidance; also writes a full JSON report with `--report`.
- **`gofusa hooks install/remove/show`** — installs or removes a `gofusa check --strict`
  pre-commit hook in `.git/hooks/pre-commit`.
- **`gofusa sign` command** — HMAC-SHA256 sign/verify for release artifacts; `--keygen`
  generates a new random key.
- **ANA005** — `context.Background()`/`context.TODO()` called inside a function that
  already accepts a `context.Context` parameter (context propagation dropped).
- **ANA006** — `fmt.Errorf` called without `%w`; error chain is lost for `errors.Is/As`.
- **ANA007** — value from a two-result function call used on the next line without an
  intervening `err != nil` check (nil dereference risk).
- **ANA008** — goroutine function literal accesses a package-level variable without
  synchronisation (data race risk).

## [0.16.0] — 2026-06-08

### Added
- **Docker publish workflow** (`.github/workflows/docker-publish.yml`) — builds and pushes
  `ghcr.io/soundmatt/go-fusa` to GitHub Container Registry on every `v*` tag; produces
  semver tags (`0.16.0`, `0.16`) and `latest`.
- **GitHub Actions usage example** (`.github/gofusa-example.yml`) — drop-in workflow snippet
  for projects that want to run `gofusa check`, `trace`, `release`, and `cyber` via the
  published container image, with evidence artifact upload.
- **`.fusa-iec62443.json`** — declares IEC 62443 Security Level 2 for the project itself
  (satisfies IEC62443-001 engine rule).
- **`.github/CODEOWNERS`** — documents review ownership (satisfies SLSA003 rule).
- **`INCIDENT-RESPONSE.md`** — IEC 62443-4-2 CR 6.2.1 incident response plan.
- **`provenance.json` `builder` field** — added SLSA L2 builder identification.

### Fixed
- `trace.ScanTags(".")` — relative root `"."` caused the entire source tree to be skipped
  because `d.Name() == "."` matched the hidden-directory guard; fixed by exempting the
  root path from the check. This was producing 304 false TRACE002/TRACE003 findings on
  `gofusa check --dir .`.
- CYBER005 `//nolint` suppression — `cyber.isNolinted()` helper now honours inline
  `//nolint:CYBER005` (or comma-separated `//nolint:gosec,CYBER005`) comments; files now
  parsed with `parser.ParseComments`.
- CYBER016/017 — all `os.MkdirAll` calls tightened to `0o750`; all `os.WriteFile` /
  `os.OpenFile` calls tightened to `0o640` across CLI commands, test helpers, and
  production packages.
- CYBER019 — TOCTOU in `auditpack.Pack` eliminated by removing the `os.Stat` pre-check;
  files are now opened and hashed in a single step.
- CYBER009 — `atomic.Int32` narrowing conversion in `runtime` tests replaced with
  `atomic.Int64`.
- Windows runner notice — CI matrix pinned to `windows-2025` (was `windows-latest`).

### Changed
- `gofusa check --dir .` now correctly reports Traced: 150, Tested: 124 (was 0/0).
- Self-check result: **0 findings** (was 361 — 0 errors, 203 warnings, 158 infos).

## [0.15.0] — 2026-06-08

### Added
- `cyber` package — 10 additional gosec-inspired rules (CYBER011–020, REQ-CYBER011–020):
  - **CYBER011** — SSRF: `http.Get/Post/Head/NewRequest` with variable URL (CWE-918) → WARNING
  - **CYBER012** — pprof endpoint exposed: `net/http/pprof` import (CWE-200, gosec G108) → WARNING
  - **CYBER013** — Zip slip: archive entry `.Name` passed to `os.Create/OpenFile/filepath.Join` (CWE-23, gosec G110) → ERROR
  - **CYBER014** — TLS minimum version: `tls.Config{MinVersion: tls.VersionTLS10/11}` (CWE-326, gosec G112) → WARNING
  - **CYBER015** — SQL injection via `fmt.Sprintf`: `db.Query(fmt.Sprintf(...))` (CWE-89, gosec G201/G202) → ERROR
  - **CYBER016** — Permissive directory mode: `os.Mkdir/MkdirAll` with mode > 0750 (CWE-732, gosec G301/G302) → WARNING
  - **CYBER017** — Permissive file mode: `os.OpenFile/WriteFile` with mode > 0640 (CWE-732, gosec G304/G306) → WARNING
  - **CYBER018** — Path from HTTP request: `http.ServeFile`/`os.Open` with `r.URL.Path` (CWE-22) → ERROR
  - **CYBER019** — TOCTOU: function with both `os.Stat` and `os.Open/Create/Remove/Rename` (CWE-362) → WARNING
  - **CYBER020** — Predictable temp file: `os.Create(filepath.Join(os.TempDir(),...))` (CWE-377) → WARNING
- `cyber.Scan` — public function running all CYBER rules via `engine.Default.RunFilter`
- `iec62443` package — IEC 62443 industrial cybersecurity compliance checks (REQ-IEC62443-001–004):
  - **IEC62443-001** — Missing `.fusa-iec62443.json` configuration file → INFO
  - **IEC62443-002** — `target_sl` not in 1–4 → WARNING
  - **IEC62443-003** — No SECURITY.md or equivalent security policy document → INFO
  - **IEC62443-004** — No incident response plan document → INFO
  - `LoadConfig` — parses `.fusa-iec62443.json` (target_sl, component_type, zone_conduit, security_reqs_doc, incident_resp_doc)
- `slsa` package — SLSA L2/L3 supply-chain compliance rules (REQ-SLSA001–003):
  - **SLSA001** — `provenance.json` missing `vcsRevision` field (SLSA L2) → INFO
  - **SLSA002** — `provenance.json` missing `builder` field (SLSA L2) → INFO
  - **SLSA003** — No CODEOWNERS or branch-protection configuration (SLSA L3) → INFO
- `tara` package — Threat Analysis and Risk Assessment per ISO 21434 Chapter 9 (REQ-TARA001–005):
  - `tara.Scan` — maps CYBER findings to `ThreatEntry` with STRIDE, CWE, attack vector, likelihood, impact, IEC 62443 SL, control, residual risk; unknown rules produce default entries
  - `tara.Render` — JSON and Markdown table formats for safety case evidence
  - `TARA001` engine rule — INFO finding when `tara.json` is absent
  - `ruleMeta` map — full metadata for all CYBER001–020 rules
- `vuln.ScanWithGovulncheck` — uses govulncheck call-graph analysis when binary available, falls back to OSV API scan; reduces false positives by flagging only reachable call paths (REQ-VULN006)
- `fmea.EnrichWithCyber` — cross-references CYBER findings into FMEA entries by file path; escalates severity to High for ERROR-level findings (REQ-FMEA006)
- `trace.KindSecTest` — `//fusa:sec-test REQ-ID` annotation; counted as `SecTestedRequirements` in coverage report (REQ-TRACE005)
- `gofusa cyber` CLI subcommand — runs CYBER rules, prints summary, writes `cyber-report.json` (REQ-CLI018)
- `gofusa tara` CLI subcommand — runs CYBER rules and generates `tara.json` + `tara.md` (REQ-CLI019)
- `gofusa fmea --cyber` flag — enriches FMEA entries with CYBER findings (REQ-CLI020)
- `gofusa release --full` now additionally generates `cyber-report.json`, `tara.json`, and `tara.md`
- 28 new requirements (REQ-CYBER011–020, REQ-IEC62443-001–004, REQ-SLSA001–003, REQ-VULN006, REQ-TARA001–005, REQ-FMEA006, REQ-TRACE005, REQ-CLI018–020), total 152

## [0.14.0] — 2026-06-08

### Added
- `cyber` package — 10 cybersecurity static analysis rules mapped to CWE, ISO 21434, SEI CERT C, and MISRA-C:2023 (REQ-CYBER001–010)
  - **CYBER001** — `crypto/md5` or `crypto/sha1` import (CWE-327, ISO 21434 §8.5) → WARNING
  - **CYBER002** — `crypto/des` or `crypto/rc4` import (CWE-327, MISRA Dir 4.8) → WARNING
  - **CYBER003** — `math/rand` import for pseudo-random source (CWE-330, CERT MSC50) → INFO
  - **CYBER004** — `unsafe` package import bypasses type safety (CWE-242, MISRA Rule 11.3) → WARNING
  - **CYBER005** — `exec.Command`/`exec.CommandContext` with non-literal command name (CWE-78, Contrast ProcessControl) → WARNING
  - **CYBER006** — variable/constant with credential-suggestive name assigned a string literal (CWE-798) → ERROR
  - **CYBER007** — `InsecureSkipVerify: true` in TLS config (CWE-295, ISO 21434 §10.4) → ERROR
  - **CYBER008** — `http.ListenAndServe`/`ListenAndServeTLS` without timeouts (CWE-400) → WARNING
  - **CYBER009** — explicit narrowing integer conversion on non-literal (CWE-190, MISRA Rule 10.3) → INFO
  - **CYBER010** — string concatenation as first argument to OS path or DB query function (CWE-22 path traversal, CWE-89 SQL injection) → WARNING
- `FuzzCyberScan` fuzz target for AST parsing robustness
- All 10 rules auto-registered via `init()` and activated by blank-importing `cyber` in `main.go`
- 10 new requirements (REQ-CYBER001–010), total 124

## [0.13.0] — 2026-06-08

### Added
- `vuln` package — dependency vulnerability scanner against the OSV database (ISO 21434 §8.5, REQ-VULN001–005)
  - `vuln.Scan` — reads go.mod, POSTs batch query to `api.osv.dev/v1/querybatch`, returns one `Finding` per vulnerable (module, version) pair
  - `vuln.ParseGoMod` — parses block and single-line require forms; strips `// indirect` comments; zero external deps
  - `vuln.Render` — JSON (default) and text formats
  - `VULN001` engine rule — INFO finding when vuln.json is absent, description references ISO 21434 §8.5
  - `FuzzParseGoMod` fuzz target
- `auditpack` package — bundles all evidence artifacts into a ZIP for auditors (REQ-AUDIT001–004)
  - `auditpack.Pack` — collects 16 standard evidence files, computes SHA-256 per file, writes AUDIT-MANIFEST.json inside the archive
  - `AUDITPACK001` engine rule — INFO finding when audit-pack.zip is absent
- `report.RenderHTML` — self-contained HTML report with findings table, evidence status cards, and PASS/WARN/FAIL badge (REQ-HTML001–003)
  - Wired into `gofusa report --format html`
- `TRACE003` engine rule — INFO finding for every requirement with no `//fusa:test` tag (test coverage gap) (REQ-REQQ002)
- `TRACE004` engine rule — WARNING finding for every requirement missing its `text` field (REQ-REQQ003)
- `gofusa vuln` CLI command — scans deps and writes vuln.json (REQ-CLI015)
- `gofusa audit-pack` CLI command — bundles evidence into audit-pack.zip (REQ-CLI016)
- `gofusa trace --gaps` flag — lists requirements with no test tag; exits 1 when gaps exist (REQ-CLI017)
- `gofusa release --full` flag — runs fmea, boundary, vuln scan, and audit-pack in addition to SBOM/provenance
- 18 new requirements (REQ-VULN001–005, REQ-AUDIT001–004, REQ-HTML001–003, REQ-REQQ001–003, REQ-CLI015–017), total 114

## [0.12.0] — 2026-06-08

### Added
- `fmea` package — dFMEA generation from Go source: parses exported functions, derives failure modes, effects, and severities from return types, goroutine usage, and `//fusa:req` annotations (REQ-FMEA001–005)
- `fmea.Scan` — walks project root, produces one `Entry` per exported function with component, failure modes, effects, severity (high/medium/low), and detection control
- `fmea.Render` — JSON (indented) and CSV formats; CSV is import-ready for DOORS, Polarion, or Excel
- `FMEA001` engine rule — INFO finding when fmea.json is absent
- `boundary` package — component boundary diagram generation from Go package structure: builds package dependency graph using go/ast imports (REQ-BOUNDARY001–005)
- `boundary.Scan` — derives package nodes (with exported API surface) and directed import edges; skips vendor, testdata, hidden dirs
- `boundary.Render` — Mermaid flowchart LR and Graphviz DOT formats
- `BOUNDARY001` engine rule — INFO finding when boundary.mermaid is absent
- `gofusa fmea` CLI command — writes fmea.json + fmea.csv (REQ-CLI013)
- `gofusa boundary` CLI command — writes boundary.mermaid + boundary.dot (REQ-CLI014)
- 12 new requirements (REQ-FMEA001–005, REQ-BOUNDARY001–005, REQ-CLI013–014), total 96

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
