# Changelog

All notable changes to this project are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Dates reference the merged commit timestamp.

## [Unreleased]

## v0.42.0 — 2026-07-28 (x-FuSa spec §1.6.2 attestation carry-forward MUST)

### Fixed
- **§1.6.2 attestation is no longer silently wiped on every regeneration**
  of `fmea.json`/`tara.json`/`safety-case.json`/`sas.json` (x-FuSa spec
  v1.15.0 §1.6.2, now a MUST). `gofusa fmea`/`tara`/`safety-case`/`sas`
  each unconditionally overwrote their output with a brand-new report
  built from scratch, none of which loaded the existing file first or
  copied forward its `attestation` field — a hand-added, valid, reviewed
  attestation was discarded the moment the command was re-run, even when
  nothing about the artifact's substantive content had changed
  (go-FuSa#57). Each command now calls the new `carryForwardAttestation`
  helper (`cmd/gofusa/helpers.go`) to load the prior saved output file's
  `attestation` field and carry it forward onto the freshly-built result
  before writing. Staleness continues to fall out automatically: a
  carried-forward `contentHash` that no longer matches the freshly
  computed content hash means `stubcheck.AttestationSuppresses` treats it
  as not currently suppressing (via `fusa.AttestationValid`), never that
  it vanished outright.

## v0.41.0 — 2026-07-28 (tara: closed impact/risk enums per x-FuSa spec v1.14.1)

### Fixed
- **`tara.json`'s `impact`/`risk` fields now use the x-FuSa spec §9.2 closed
  enums** instead of the non-conformant `high|medium|low` vocabulary
  (spec v1.14.1, "Closed enums (MUST — clarifies a gap found during
  rollout)"). `impact.{safety,financial,operational,privacy}` never used
  anything but `high`/`medium`/`low` — never `critical`/`negligible` —
  despite the spec explicitly prohibiting that vocabulary for these four
  fields; `risk` never used anything but `high`/`medium`, never
  `critical`/`low` (go-FuSa#58). `deriveSFOP` now maps onto
  `critical`/`major`/`moderate`/`negligible` via the new
  `legacyImpactToSFOP` (a `high` rating escalates to `critical` for the
  most severe IEC 62443 security-level-3 rules, `major` otherwise); `risk`
  is now looked up from the x-FuSa spec's own published risk combination
  table (highest SFOP impact axis × `attackFeasibility`) via the new
  `riskTable`, replacing the prior "worse of the two inputs" heuristic that
  couldn't produce `critical`/`negligible` by construction. Regenerated
  `tara.json`: `risk` now includes `critical` (2 threats) alongside
  `medium`/`low`; `impact.safety` includes `critical` alongside `moderate`.

## v0.37.0 — 2026-07-28 (x-FuSa spec §1.6.1 conformance fixes: content-quality scope + FUSA-STUB001 disposition)

### Fixed
- **FUSA-STUB001/002 no longer run inside `check`** (x-FuSa spec §1.6.1
  "Who runs this (MUST)"): the two content-quality rules were registered on
  `engine.Default` and therefore executed as part of `gofusa check` (and
  `report`/`fix`/`qualify`, which also drive `engine.Default`), reading
  `fmea.json`/`.fusa-hara.json`/`tara.json`/`safety-case.json`/`sas.json`
  off disk and surfacing findings inside `check`'s own finding list —
  exactly what §1.6.1 says must not happen. Detection now runs only inside
  each artifact-producing command's own `gateContentQuality` gate
  (`gofusa hara`/`fmea`/`tara`/`safety-case`/`sas`), over the content that
  command itself just built or loaded. `stubcheck`'s engine-rule glue
  (`rulePlaceholder`/`ruleBlanketFallback`/`loadArtifacts`) is removed; the
  per-artifact field extractors (`HaraFields`, `FmeaFields`, …) are
  unchanged.
- **FUSA-STUB001 is now disposition-suppressible**, as the rule's own doc
  comments and the x-FuSa spec §1.6.1 rule A already claimed ("never via
  attestation" implies a disposition path exists) but no code actually
  checked: `gateContentQuality` now loads `.fusa-dispositions.json` and
  skips escalating a FUSA-STUB001 match to a gate failure when the project
  has a disposition entry for ruleID `FUSA-STUB001` (`gofusa disposition
  add --rule FUSA-STUB001 ...`) — the same mechanism `check`'s own
  ERROR-finding review workflow uses. FUSA-STUB002 is unaffected: it
  continues to be suppressed only by a valid §1.6.2 attestation, never by
  disposition.

## v0.42.0 — 2026-07-28 (hara: risk.asil cross-validation + canonical standard id)

### Fixed
- **HARA008: `risk.asil` is now cross-validated against `DetermineASIL(S,E,C)`**
  (x-FuSa spec §1.2.5 MUST — ASIL determination). Previously a hazard's
  stored `risk.asil` was accepted verbatim: `DetermineASIL` was only ever
  used as a *fallback* for an empty value, so a hand-edited or
  copy-pasted hazard could claim any ASIL regardless of its own S/E/C
  inputs, with zero findings/gaps from either `gofusa hara show` or
  `check`. The new `hara.ValidateASIL` (wrapped by the new engine rule
  `HARA008`, and folded into `hara.Validate`'s own gap list so `hara show`
  surfaces it directly) flags a hazard whose declared `risk.asil` disagrees
  with the ISO 26262-3:2018 Table 4 value for its own severity/exposure/
  controllability — skipping hazards with an incomplete S/E/C rating
  (HARA002's job) or no `risk.asil` set yet.
- **`standard` now uses the x-FuSa spec §2.4.1 canonical lowercase id**
  (`iso26262`, not `"ISO 26262"`) in `.fusa-hara.json`: `hara init`'s
  default `--standard` flag value changed from `"ISO 26262"` to
  `"iso26262"`, the repo's own checked-in `.fusa-hara.json` was
  normalised, and `hara.Load` now transparently normalises a legacy
  display-string value (`"ISO 26262"`, `"IEC 61508"`, …) onto its
  canonical id for backward compatibility with hand-authored files
  predating this convention — an unrecognised id is still passed through
  verbatim, never rejected.

## v0.36.0 — 2026-07-28 (x-FuSa spec v1.13.0/v1.14.0 — evidence-artifact schema conformance + content-quality baseline)

### Added
- **§9.2/§9.3 evidence-artifact schema conformance** for `hara`/`fmea`/`tara`/
  `safety-case`/`sas`/`sci`:
  - `hara`: `.fusa-hara.json` `safetyGoals[].fssrRefs` is now a `[]string`
    (MUST, ≥1 entry), replacing the prior singular `fssrRef` string. New
    engine rules `HARA006` (missing `fssrRefs`) and `HARA007` (a `fssrRefs`
    id with no matching entry in `.fusa-reqs.json`). `hara show --format
    json` now emits the §9.2 `hara-report` document (common header +
    verbatim content + a `completeness` block) instead of the bare input
    file. `hara init` now scaffolds **empty** collections — never a dummy
    example hazard/safety-goal (§1.6 rule 1).
  - `fmea`: `entries[].failureMode`/`effect`/`cause` (singular strings, per
    §9.2) alongside the existing `failureModes`/`effects` arrays;
    `entries[].item`, `actionPriority`, `mitigations`; a `summary` block
    with `componentsAnalyzed`/`componentsInProject`/`coveragePct` +
    `--min-coverage N`.
  - `tara`: `threats[]` is now the canonical top-level key (was `entries`);
    `impact` is now an SFOP object (safety/financial/operational/privacy,
    ISO 21434 Clause 15.7) instead of one generic string; new
    `attackFeasibility`/`risk`/`treatment`/`location` fields; a `summary`
    block with `assetsAnalyzed`/`assetsInProject`/`coveragePct`/
    `assetInventoryMethod` + `--min-coverage N`.
  - `safety-case`: `nodes[]`/`edges[]`/`completeness` — a real GSN (Goal
    Structuring Notation v3) argument graph (goal/strategy/solution/
    context/assumption/justification node types, `supportedBy`/
    `inContextOf` edges) derived from the same evidence collection as
    before.
  - `sas`: `checklist[]` (`item`/`clause`/`present`/`evidence`) + `summary`
    (`total`/`present`); `sas`'s `sas.md` companion is now always written
    alongside whichever format `--format`/`--output` produced.
  - `sci`: `artifacts[]` (`file`/`hash`/`version`), `hash` correctly
    `sha256:`-prefixed (§2.7 — the existing `items[].sha256` field was
    already bare-hex-correct; no bug there).
  - All six now carry the §3.1 common header (`schemaVersion`/`kind`/
    `tool`/`toolVersion`/`language`/`generatedAt`).
- **§1.6.1 content-quality detection** (new `stubcheck` package): rule A
  `FUSA-STUB001` (placeholder/template text — bracket-wrapped instructional
  text or a deny-listed substring — always an `ERROR`, disposition-
  suppressible only) and rule B `FUSA-STUB002` (a qualitative field's
  distinct-value ratio below 10% across ≥10 entries — a `WARNING` by
  default, advisory). Both run as `check` engine rules across every present
  evidence artifact, and as an immediate gate on each artifact command
  itself (see `--strict`/`--require-attestation` below).
- **§1.6.2 attestation**: `fusa.Attestation` (`status`/
  `implementationAuthor`/`independentReviewer`/`reviewedAt`/`contentHash`)
  on every schema above; `fusa.AttestationValid` enforces independence
  (reviewer ≠ author) and non-staleness (hash match) fail-safe.
  `fusa.CanonicalizeJSON` implements RFC 8785 (JSON Canonicalization
  Scheme) for `contentHash`. A valid, non-stale, independent `"reviewed"`
  attestation suppresses `FUSA-STUB002` for that artifact; `FUSA-STUB001`
  is never suppressed by attestation. `gofusa fmea|hara|tara|safety-case|
  sas` all gained `--strict`/`--require-attestation`, escalating an
  unsuppressed `FUSA-STUB002` finding to exit 1.
- `fmea`/`tara --min-coverage N`: `fmea.CountProjectFunctions`/
  `tara.CountProjectFiles` provide an honestly-documented, independent
  coverage denominator (see each `Summary.*Method` field for the exact
  methodology and its limitations) rather than a denominator that always
  trivially equals the numerator.

### Fixed
- `.fusa-hara.json`'s committed safety goals used the pre-spec singular
  `fssrRef` (a space-joined string of multiple ids) — migrated to the
  spec's `fssrRefs` array.

### Added
- `docker-publish.yml` now notifies `SoundMatt/FuSaOps` via `repository_dispatch`
  (`xfusa-released`) after a successful image push, so FuSaOps rebuilds its
  bundled image promptly instead of waiting for its weekly cron. Requires a
  `FUSAOPS_DISPATCH_TOKEN` secret in this repo; falls back silently
  (`continue-on-error`) to the weekly rebuild if it's not set.

### Fixed (issue #49)
- **`.fusa.json` didn't accept x-FuSa spec §1.2.1's documented shape.**
  `config.Config` only read/wrote go-FuSa's own proprietary shape
  (top-level `"version"`, `"standard"`/`"asil"`/`"sil"` nested under
  `"project"`) and `Validate` hard-rejected any config missing the
  non-spec `"version"` field — so a fully spec-compliant `.fusa.json`
  written by another x-FuSa tool (`configVersion`, top-level `"standard"`/
  `"asil"`) made `check`/`report`/etc. fail outright instead of reading the
  shared config. `Config` now also carries the spec's top-level
  `configVersion`/`standard`/`asil`/`sil`/`dal` fields and accepts the
  spec's legacy flat `"project": "name"` string; `Load`/`Save` normalise
  between the two shapes (case-insensitively canonicalising the standard
  id), and `Validate` no longer requires go-FuSa's own `"version"` field
  when `configVersion` is present. `init`'s output now satisfies both
  shapes at once.

### Fixed (issue #50)
- **`init` never created `.fusa-reqs.json`.** Every other x-FuSa tool
  creates both `.fusa.json` and `.fusa-reqs.json` (with
  `{"requirements": []}`) on `init`, per spec §9.1. `init` now creates
  whichever of the two targets is missing and leaves an existing one
  untouched (rather than failing outright the moment `.fusa.json` alone
  already exists), only reporting an error when both already exist.

### Fixed (issue #51)
- **`qualify`'s JSON output had no spec-required `results[].result` enum.**
  Each case in `qualify --output`'s report carried only
  `results[].passed:bool`; x-FuSa spec §6 requires a
  `results[].result: "PASS"|"FAIL"|"SKIP"|"ERROR"` string. `qualify.Result`
  now carries both — `Result` is the new spec field (`ERROR` for
  infrastructure failures, `FAIL` for an expectation mismatch, `PASS`
  otherwise); `Passed` is kept for existing callers and CLI output.

### Fixed (issue #52)
- **`audit-pack` wrote `AUDIT-MANIFEST.json` instead of the spec-required
  lowercase `manifest.json`.** ZIP entry names are case-sensitive, so
  consumers looking for the spec's documented `manifest.json` (§8 MUST)
  never found it. Renamed the manifest entry `auditpack.Pack` writes to
  `manifest.json` (exported as `auditpack.ManifestFile`).

## v0.34.0 — 2026-07-27

### Fixed (issue #45)
- **`assess`/`sci`/`sas` builders reported false gaps for freshly-scaffolded
  projects.** `gofusa init`/`gofusa template` default their output directory
  to `docs/safety/`, but `iso26262.Assess`, `iec61508.Assess`, `do178.Assess`,
  `sci.Build`, and `sas.Build` only ever checked for `SAFETY_PLAN.md`,
  `SVP.md`, `SCMP.md`, and `SQAP.md` at the bare project root — the same
  inconsistency `iec62443.go`'s `SECURITY.md`/`INCIDENT-RESPONSE.md` checks
  had already been fixed for. Added `fusa.ResolveDoc`, a shared helper that
  checks the project-root path first and falls back to `docs/safety/<name>`
  for the known scaffold filenames, and wired it into all five builders.

### Added
- **`fusa.ResolveDoc(projectRoot, name string) string`** — new exported
  helper (REQ-DOC001) resolving a scaffolded safety document's on-disk path,
  used by the fix above.

### Requirement registry sync
- **Closed a 142-ID / 727-occurrence orphan-tag gap.** A repo-wide
  `gofusa trace` audit found that entire subsystems — `sas/`, `sci/`,
  `hara/`, `gapreport/`, `badge/`, `metrics/`, `disposition/`, `impact/`,
  `analyze` rules ANA005-009, `coupling`, and ~40 `REQ-CLI-*`
  CLI-subcommand tags — carried real `//fusa:req`/`//fusa:test`
  annotations that were never registered in `.fusa-reqs.json`, so
  `gofusa trace`'s own orphan-tag detection (TRACE009) was firing over
  500 warnings against go-FuSa's own source. Registered all 142 requirement
  IDs with title/text/standard derived from each implementation's doc
  comment (or, where none existed, its CLI `--help` usage text), then
  added the handful of missing test tags surfaced once those requirements
  became visible to the coverage gate.
- Fixed a handful of ID inconsistencies uncovered along the way: five
  test-side tags (`REQ-CLI-AUDIT001`, `REQ-CLI-AUDITPACK001`,
  `REQ-CLI-BOUNDARY001`, `REQ-CLI-LINT001`, `REQ-CLI-VERSION001`)
  duplicated already-registered IDs and were consolidated onto them;
  three `gofusa trace --sec-tested` tests were retagged from
  `REQ-CLI-TRACE003` (`--req-coverage`) to the correct `REQ-CLI-TRACE001`
  (`--sec-tested`); `runCheck`/`runInit`/`runReport`/`runVerify` gained the
  top-level `//fusa:req` tag their tests already assumed existed.
- Six synthetic fixture IDs (`REQ-001`, `REQ-002`, `REQ-003`, `REQ-H`,
  `REQ-M`, `REQ-L`) used as sample data inside test-only Go source
  fixtures were rewritten from raw string literals to string
  concatenation, so they no longer get picked up by go-FuSa's own
  self-trace of this repo.

### Requirements
- `.fusa-reqs.json`: 233 → 363 requirements.


### Fixed (issue #43)
- **Stale Dockerfile OCI labels** — the custom `io.x-fusa.spec-version` label
  was hardcoded to `"1.9"` (four spec versions behind the current
  `fusa.SpecVersion` of `1.10.12`), and `org.opencontainers.image.version`
  was hardcoded to `"0.25.1"`. Both are now `ARG`-driven (`VERSION`,
  `SPEC_VERSION`) with sane defaults for a plain local `docker build`.
  `.github/workflows/docker-publish.yml` now derives `SPEC_VERSION` by
  grepping `fusa.go`'s `SpecVersion` constant at build time and `VERSION`
  from the pushed tag, and passes both via `--build-arg`, so these labels
  can no longer silently drift from the source of truth. (The standard
  `org.opencontainers.image.version` label is also overwritten at publish
  time by `docker/metadata-action`, so the previously *published* image was
  unaffected — only local builds and the raw label value in this file were
  stale.)

### Added (issue #43)
- **README package table** — the `cmd/gofusa` row now lists all 43
  subcommands; previously it omitted `hara`, `iso26262`, `iec61508`,
  `disposition`, `impact`, `metrics`, `misra`, `capabilities`, and `version`.
- **README Quick Start** — added `gofusa version` and `gofusa capabilities`
  examples; these two commands had zero README mentions before this release.

### Documented (issue #43)
- **CHANGELOG.md** — backfilled 5 entries for tagged/released versions that
  had no changelog coverage: `v0.29.1`, `v0.25.1`, `v0.25.0`, `v0.24.0`, and
  `v0.8.0`, each inserted in its correct chronological slot with content
  derived from the actual commit history and GitHub release notes.

## v0.33.4 — 2026-07-27

### Fixed (function-tag coverage retrofit)
- Closed the remaining `--func-coverage` gaps found after v0.33.3: raised
  function-tag coverage from 93% (234/251) to 100% (251/251) by tagging the
  last 17 untagged exported functions with `//fusa:req`:
  `coverage.RunMutation` (REQ-COV016); `engine.Registry.Register`,
  `engine.Registry.Rules`, `engine.Result.HasWarnings`, `engine.Registry.Run`
  (REQ-ENG008..011); `fusa.DeriveCategory` (REQ-CAT001) and
  `fusa.ComputeFingerprint` (REQ-FP001); `qualify.Report.HasFailures`
  (REQ-QUALIFY009); `runtime.DiagManager.Record`, `.Diagnostics`, `.Clear`,
  `.Count` (REQ-RUNTIME016..019); `runtime.FaultMonitor.Reset`, `.Count`
  (REQ-RUNTIME020/021); `runtime.StateManager.State`, `.Transition`
  (REQ-RUNTIME022/023); and `trace.ScanTags` (REQ-TRACE011). All 17 new
  requirements are registered in `.fusa-reqs.json` and tagged with
  `//fusa:test` on the pre-existing tests that already exercised them.

## v0.33.3 — 2026-07-27

### Added
- **`gofusa trace --func-coverage N`** (x-FuSa spec §1.4.1 item 2): gates on the
  percentage of exported top-level functions/methods (non-test `.go` files) that
  carry a `//fusa:req` tag directly above them in their doc comment — function-level
  placement, not merely file co-location like `--req-coverage`'s metric 2. `N=0`
  disables the gate (mirrors `--req-coverage`'s pattern exactly). Trivial
  `fmt.Stringer`/`error`-shim methods (`String()`/`Error()`), boilerplate field
  getters (`return recv.field`), and constant-returning interface boilerplate
  (`return "RULE001"`) are excluded from both the numerator and denominator.
  New `trace.ScanFuncTagCoverage`.
- **Dangling `//fusa:test` tag detection (TRACE009)** (x-FuSa spec §1.4.1 item 3): a
  `//fusa:test <ID>` tag whose ID does not exist in `.fusa-reqs.json` now produces a
  WARNING finding (category `requirement`), the same treatment a malformed
  annotation already gets under §1.4.

### Fixed (traceability retrofit — issue #41)
- Added `//fusa:req`/`//fusa:test` tags closing real gaps found by the new
  `--func-coverage` gate: `runtime/heartbeat.go` (`Start`, `Stop`, `Beat`,
  `IsRunning` — REQ-RUNTIME010..013), `runtime/watchdog.go` (`Start`, `Stop`,
  `Kick`, `IsRunning` — REQ-RUNTIME006..009), `runtime/faultmonitor.go`
  (`SetThreshold`, `Record` — REQ-RUNTIME014/015), and `trace/reqxml.go`'s
  DOORS/Codebeamer/Jama/Polarion `Parse*`/`Export*` functions (REQ-REQXML001..008).
  All new requirements are registered in `.fusa-reqs.json` and their existing
  test coverage tagged with `//fusa:test`.
- Added missing `//fusa:req` tags for two previously-untagged v0.30.0 conformance
  fixes: `cmd/gofusa/cmd_capabilities.go`'s canonical `Standards` array
  (REQ-CAP-STD001) and `lint`/`analyze`'s `locationEnd` project-relative path
  helper (REQ-LOC-REL001).
- Added `//fusa:test` tags to existing-but-untested requirements found via
  `gofusa trace --gaps`: REQ-CAP-STD001, REQ-ISO21434-002, REQ-ISO21434-003,
  REQ-LOC-REL001, REQ-UNECE-002, REQ-UNECE-003.

## v0.33.2 — 2026-07-27

### Fixed
- **Doc version check** — `README.md` and `docs/tool-safety-manual.md` still referenced
  `0.33.0` after the v0.33.1 bump, failing CI's version-consistency gate. Both now
  reference `0.33.2`.

## v0.33.1 — 2026-07-27

### Fixed
- **SpecVersion updated** to `"1.10.12"` in `fusa.go` (was `"1.10.4"`); aligns with the
  current x-FuSa spec revision emitted in SBOM, provenance, and manifest headers.

### Added (coverage)
- `cyber/cyber_gap_test.go`: tests for `isNolinted()` covering all three suppression
  comment forms (`//nolint:RULE`, `//nolint:A,RULE`, `//fusa:ignore RULE`) and the
  negative (wrong-rule) case. Coverage: 30% → 90%.
- `cyber/cyber_gosec_gap_test.go`: tests for `isRequestDerived()` (RawPath, FormValue,
  PostFormValue, URL.Query().Get, generic URL field) and `isTempPath()` (filepath.Join
  with literal `/tmp`, filepath.Join with os.TempDir, non-temp variable path).
  `isRequestDerived`: 36.4% → 100%; `isTempPath`: 47.1% → 58.8%.
- `release/release_gap_test.go`: tests for `vcsInfo()` via `BuildProvenance` in both
  a real git repo (success path) and a non-git temp dir (error path). Coverage: 33.3% → 88.9%.
- `report/report_html_gap_test.go`: tests for `moduleFromRoot()` (go.mod present, no
  module directive) and `countRequirements()` (valid JSON, invalid JSON).
  Both functions: 37.5%/42.9% → 100%.
- `iso26262/iso26262_gap_test.go`: tests for `mapToCanonical()` (Pass, Manual) and
  `statusIcon()` (Pass, NA, Manual) in ISO 26262 text and JSON output.
  Both functions: 50% → 83–100%.
- `iec61508/iec61508_gap_test.go`: equivalent gap tests for IEC 61508.
  Both functions: 50% → 83–100%.
- `iec62443/iec62443_gap_test.go`: tests for `statusIcon()` (PASS case) in IEC 62443
  text output. Coverage: 60% → 80%.
- `cmd/gofusa/cmd_release_gap_test.go`: tests for `runRelease()` with `--spdx-version 3.0.1`,
  `--builder` flag, and missing go.mod error path. Coverage: 66.7% → 74.7%.

## v0.33.0 — 2026-07-26

### Added
- **Maximize test coverage and requirement annotations** (audit-driven):
  - `cmd/gofusa/cmd_v032_test.go`: CLI-level tests for `runTraceHLRLLR` (P0 — REQ-TRACE008),
    `runCoverage --mcdc` (P2 — REQ-COV015), and `runQualify` new flags (P2 — REQ-QUALIFY007/008).
  - `trace/trace_test.go`: `TestRender_Markdown_HLRLLRSummary` covers the HLR/LLR summary
    section of `renderMarkdown` introduced in v0.32.0.
  - `coverage/coverage_test.go`: `TestRenderText_DALD_ReqHelperNoBranch` exercises the `false`
    branch of the unexported `req()` helper.
  - `verify/verify_test.go`: `//fusa:test REQ-VERIFY006` and `//fusa:test REQ-VERIFY007`
    annotations added to `TestSaveAndLoad_Roundtrip`.
  - `qualify/qualify_test.go`: `//fusa:test REQ-QUALIFY005` on `TestSaveAndLoad_Roundtrip`,
    `//fusa:test REQ-QUALIFY006` on `TestBuiltinCases_NonEmpty`.
- **Four new requirements registered** in `.fusa-reqs.json`:
  REQ-VERIFY006 (`verify.Save`), REQ-VERIFY007 (`verify.Load`),
  REQ-QUALIFY005 (`qualify.Load`), REQ-QUALIFY006 (`qualify.BuiltinCases`).

## v0.32.0 — 2026-07-26

### Added
- **Feature 1 — HLR/LLR hierarchical traceability** (`trace` package): `Requirement.ParentID`
  field; `HLRLLRSummary` struct; `ComputeHLRLLR()` function; engine rule TRACE008 that detects
  orphaned LLRs (missing/invalid parentId) and uncovered HLRs (no LLR children). Severity is
  WARNING by default, ERROR when project ASIL is ASIL-D. CLI `--strict-hlr-llr` flag gates on
  any violation regardless of ASIL. Renderers (text/json/markdown) now show HLR/LLR summary.
  Two TRACE008 qualification cases added to the builtin suite (REQ-TRACE008).
- **Feature 2 — Tool qualification display** (`qualify` package): `Report` gains
  `QualificationMethod`, `QualificationRecordUri`, `QualifierIdentity` fields and a
  `QualificationBadge()` method. CLI flags `--qualification-method`, `--qualifier`,
  `--record-uri`. Badge shown in `gofusa qualify` output (REQ-QUALIFY007).
- **Feature 3 — MC/DC coverage measurement** (`coverage` package): `MCDCCondition`,
  `MCDCRecord`, `MCDCFunctionResult`, `MCDCReport` types; `ParseMCDC()` and `ParseMCDCFile()`
  functions parse LLVM coverage JSON exports. A condition is covered when
  `covered_true_count > 0 && covered_false_count > 0`. CLI flags `--mcdc`, `--mcdc-file`,
  `--mcdc-threshold` added to `gofusa coverage`. Gate fails when coverage falls below
  threshold (REQ-COV015).
- **Feature 4 — V&V independence declaration** (`qualify` package): `Report` gains
  `ImplementationAuthor`, `IndependentReviewer`, `IndependentTestExecutor`, `AchievableASIL`
  fields and `IndependenceStatus()` method. CLI flags `--implementation-author`,
  `--independent-reviewer`, `--independent-test-executor`, `--achievable-asil`.
  Independence status shown in `gofusa qualify` output (REQ-QUALIFY008).
- Seven new requirements added to `.fusa-reqs.json`:
  REQ-TRACE008, REQ-QUALIFY007, REQ-QUALIFY008, REQ-COV001, REQ-COV002, REQ-COV003, REQ-COV015.

## v0.31.0 — 2026-07-25

- Fix SpecVersion constant from "1.9" to "1.10.4"
- Auto-detect CI builder field in provenance.json; add --builder flag

## [0.29.1] — 2026-06-12

### Fixed
- Removed a stray duplicate `cmd/gofusa/conform_test 2.go` (an editor-created
  exact copy of `conform_test.go`) that had been committed by mistake.
- Added `.claude/` (AI session state) and `cmd/gofusa/safety-case.json`
  (generated evidence artifact) to `.gitignore`.

## [0.30.0] — 2026-06-12

### Fixed
- **§4 MUST: `location.file` is now project-relative** — `locationEnd()` in `lint` and `analyze` now
  applies `filepath.Rel(projectRoot, filename)` + `filepath.ToSlash()` before storing in
  `Location.File`. Previously the absolute path from the AST file set was passed through unchanged,
  making fingerprints (§4.2) machine-specific and breaking cross-environment baseline diffing.
  Affects all LINT and ANA rule findings.
- **§2.4.1 MUST: `capabilities.Standards` canonical SLSA ID** — `cmd/gofusa/cmd_capabilities.go`
  now emits `"slsa"` instead of `"slsa-v1.0"` in the `standards` array. The `Commands` and
  `Formats` maps were already correct; only `Standards` was wrong.

## [0.29.0] — 2026-06-12

### Fixed
- **§2.2 `--output` no-stdout invariant** — six gap-report commands (`slsa`, `iec62443`,
  `iso26262`, `iso21434`, `iec61508`, `unece`) were writing a summary line to stdout even
  when `--output <file>` was given. That summary now goes to stderr so stdout is clean for
  pipeline consumption.

### Added
- **§2.2/§2.9 conformance test suite** (`cmd/gofusa/conform_test.go`) — 14 tests covering:
  - §2.2: stdout is empty for every `--output`-capable tool (check, report, lint, trace,
    comp, slsa, iec62443, iso26262, iso21434, iec61508, unece)
  - §2.9: ruleId/severity/category are identical across JSON and SARIF output; ruleIds are
    present in text output

## [0.28.0] — 2026-06-12

### Fixed
- **SLSA canonical standard ID** — `gofusa slsa` JSON output now emits `"standard": "slsa"` instead of
  `"standard": "slsa-v1.0"`, conforming to §2.4.1 of the x-FuSa spec.

### Added
- **`endLine`/`endColumn`** on all lint and analyze findings (§4 MAY). The `Location` struct already
  carried these fields; `lint` and `analyze` now populate them from the AST node's `End()` position
  so that tooling (IDEs, SARIF viewers) can highlight the full span of a finding.

## [0.27.0] — 2026-06-12

### Added
- **`gofusa comp`** — cyclomatic complexity gate command (DO-178C §6.3.4).
  `comp.Assess` walks all non-test Go source files and returns per-function
  complexity results. `comp.ThresholdForDAL` maps DO-178C DAL-A/B/C/D to
  thresholds (4/10/15/20). Exits 0 (no exceedances), 1 (gate fail), 2 (bad flag).
  `--dal` selects a DAL threshold; `--threshold` overrides it.
- **Markdown report format** (`--format md`/`markdown`) for `gofusa check`,
  `gofusa report`, and `gofusa trace`. Produces GitHub/Confluence-compatible
  Markdown with a summary table and findings/requirements table.
- **`sil` and `dal` JSON fields** in `report.Report` for IEC 61508 and DO-178C
  projects respectively, distinct from the existing `asil` field (ISO 26262).
  `gofusa check` and `gofusa report` now populate the correct field based on
  the configured standard.
- **7 new requirements** — REQ-COMP-ASSESS001–002, REQ-CLI-COMP-001,
  REQ-REPORT-MD001, REQ-REPORT-SIL001, REQ-TRACE-MD001 added to `.fusa-reqs.json`.

## [0.26.0] — 2026-06-12

### Added
- **`gofusa slsa`** — standalone SLSA v1.0 supply-chain integrity gap report command.
  `slsa.Assess` evaluates 10 objectives across L1–L4 (provenance, SBOM, CODEOWNERS, SHA256SUMS,
  audit-pack). `slsa.Render` emits §9.3-canonical JSON or human-readable text.
  Exits 0 (no gaps), 1 (gaps found), 2 (bad flag/level), 3 (I/O error).
- **`gofusa iec62443`** — standalone IEC 62443-4-2 IACS cybersecurity gap report command.
  `iec62443.Assess` evaluates 12 Component Requirement objectives across SL-1–SL-4 (SECURITY.md,
  cyber-report, provenance builder field, incident-response plan, boundary diagram, audit-pack).
  `iec62443.Render` emits §9.3-canonical JSON or human-readable text.
- **10 new requirements** — REQ-SLSA-ASSESS001–004, REQ-CLI-SLSA-001,
  REQ-IEC62443-ASSESS001–004, REQ-CLI-IEC62443-001 added to `.fusa-reqs.json`.

## [0.25.1] — 2026-06-10

### Added
- Test suite expansion to raise overall coverage from 81.5% to ≥85%: targeted
  error-path tests for `cmd/gofusa` (render-failure/bad-format paths,
  `os.Create` error paths, no-dir tests exercising the `os.Getwd()` branch
  across 16 commands), a new `gapreport_test.go` (100% coverage), and
  additional branch-coverage tests for `auditpack`, `comp`, `coupling`,
  `qualify`, `coverage`, `disposition`, and `metrics`.
- `//fusa:req` annotations added to `gapreport`, `cmd_capabilities.go`, and
  `helpers.go`.

## [0.25.0] — 2026-06-10

### Changed
- **x-FuSa spec v1.9 conformance** — `fusa.SpecVersion` bumped `"1.8"` →
  `"1.9"`, which propagates automatically to the `schemaVersion` field on
  every emitted document (check report, gap reports, SBOM/provenance/manifest,
  audit-pack, capabilities). Spec v1.9 promotes four SHOULD→MUST fields
  (`category`, `remediation`, `fingerprint`, `capabilities`); go-FuSa already
  implemented all four as of v0.24.0, so this is a mechanical version bump
  with no behavioral change.
- `fusa.Version` bumped `0.24.0` → `0.25.0`.

## [0.24.0] — 2026-06-10

### Added
- **x-FuSa spec v1.8 exit codes (§2.3)** — all ~40 `cmd_*.go` files now return
  the spec-mandated codes (`ExitOK`=0, `ExitGateFail`=1, `ExitUsage`=2,
  `ExitRuntime`=3) via new constants in `fusa.go` and a `parseFlags()` helper
  in `cmd/gofusa/helpers.go`. Previously every failure returned bare `1`,
  making it impossible for CI pipelines to distinguish a gate failure from a
  bad flag.
- **Canonical §9.3 gap-report JSON** — `iso26262`, `iec61508`, `do178`,
  `iso21434`, and `unece` `Render()` functions now delegate to the new
  `gapreport/` package instead of encoding private structs, so every gap
  report shares one schema: `{schemaVersion, kind, tool, toolVersion,
  language, generatedAt, projectRoot, standard, objectives[], summary}` with
  status values `satisfied`/`partial`/`gap`/`skip`.
- `cmd_capabilities.go` and `report/summary.go` added.

## [0.23.0] — 2026-06-09

### Added
- **`iso21434/` package + `gofusa iso21434`** — ISO 21434:2021 cybersecurity gap assessment for
  CAL 1–4. Evaluates 14 automatable objectives (§6.1, §8.3, §9.1–9.6, §10.1, §10.3, §10.4, §11.1,
  Annex A.1/A.2) plus 7 manual items. Exits 1 when gaps exist. Rule `ISO21434001` fires INFO when
  `tara.json` is absent from an ISO 21434 project.
- **`unece/` package + `gofusa unece`** — UN R.155 Annex 5 threat-category coverage assessment.
  Evaluates TC-1 through TC-9 evidence files; TC-7 to TC-9 are MANUAL. Rule `UNECE001` fires
  WARNING when `tara.json` is absent from an ISO 21434 project.
- **`coverage.RunMutation` + `gofusa coverage --mutate`** — mutation testing via `go-mutesting`
  (optional binary). Returns a `MutationReport` with mutant/killed/survived counts and score.
  A score ≥ 80% sets `MCDCEvidence` to the DO-178C AC §2.3.1(b) justification string.
- **DOORS/Polarion XML import/export** — `trace.ParseDOORS`, `trace.ExportDOORS`,
  `trace.ParsePolarion`, `trace.ExportPolarion` add ReqIF and Polarion work-item XML support to
  `gofusa trace import/export`.
- **`safetycase` ISO 21434 + UN R.155 mappings** — `iso21434` and `unece155` evidence entries added
  to the safety case compliance map.
- **CI: CodeQL workflow** — `.github/workflows/codeql.yml` runs on push/PR to main and weekly,
  using `security-extended+security-and-quality` query suite.
- **CI: SARIF upload job** — `sarif:` job in `ci.yml` builds gofusa, runs `check --format sarif`,
  and uploads to GitHub Code Scanning via `codeql-action/upload-sarif@v3`.
- **CI: Release workflow** — `.github/workflows/release.yml` builds cross-platform binaries
  (linux/amd64, darwin/arm64, windows/amd64) and publishes a GitHub Release on `v*` tags.
- **CI: Concurrency cancel** — `ci.yml` now cancels in-progress runs for the same branch.
- **Documentation** — `docs/commands/check.md`, `lint.md`, `analyze.md`, `trace.md`, `release.md`
  and `docs/standards/iso26262.md`, `iec61508.md`, `do178c.md`, `iso21434.md`, `iec62443.md`,
  `misra-c.md` added.

## [0.22.0] — 2026-06-09

### Added
- **SPDX 2.2 and 2.3 SBOM support** — `release.ToSPDX22` and `release.ToSPDX23` produce
  JSON-format SBOM documents with standard `SPDXID`/`spdxVersion`/`creationInfo`/`packages`/
  `relationships` fields. `gofusa release --spdx-version 2.2|2.3|3.0.1` selects the format;
  default remains 3.0.1.
- **`gofusa coupling` command** — generates `coupling-report.json` from live data/control
  coupling analysis of the project source tree. Useful for DO-178C §6.4.4.3 evidence.
- **`coupling.SaveReport`** — serialises coupling findings to a versioned JSON report with
  `generatedAt`, `projectRoot`, `dataCoupling`, and `controlCoupling` fields.
- **COUP003 engine rule** — fires INFO when a DO-178C project lacks `coupling-report.json`,
  prompting teams to run `gofusa coupling` before the evidence bundle is assembled.
- **`trace.Requirement.ASIL` field** — requirements in `.fusa-reqs.json` now accept an
  optional `asil` field (e.g. `"ASIL-B"`, `"SIL-2"`) for ASIL-tagged requirement tracking.
- **HARA005 engine rule** — fires WARNING when the highest hazard ASIL in `.fusa-hara.json`
  exceeds the project ASIL declared in `.fusa.json`, preventing accidental ASIL under-allocation.
- **ISO 26262 gap-assessment improvements:**
  - Obj 7.3 now checks `.fusa-hara.json` (structured HARA) instead of `HARA.md`.
  - New obj 10.4 — SCI (`sci.json`) evidence check, required for ASIL-B/C/D.
  - New obj 11.3 — coupling evidence (`coupling-report.json`) check, required for ASIL-C/D.
  - **ISO26262002 engine rule** — fires INFO when an ISO 26262 project has requirements
    without an `asil` field in `.fusa-reqs.json`.
  - **ISO26262003 engine rule** — fires WARNING when `qualify-report.json` has failures,
    indicating the tool qualification depth is insufficient.
- **IEC 61508 gap-assessment improvements:**
  - Obj 1.3 now resolves via `.fusa-hara.json` (was MANUAL).
  - Obj 4.2 now resolves via `fmea.json` (was MANUAL).
  - New obj 5.4 — SCI (`sci.json`) evidence check, required for SIL-2/3/4.
- **DO-178C gap-assessment improvements:**
  - A-2.2 LLR detection — checks `.fusa-reqs.json` for requirements tagged `level: LLR`
    (was always MANUAL).
  - A-6.2 now maps to `check-report.json` (was MANUAL).
  - A-6.3 now maps to `coupling-report.json` (was MANUAL).
  - The `check` function field in `allObjectives` is now invoked during `Assess()`.

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

## [0.8.0] — 2026-06-07

Tagged from the same squash-merged commit as v0.9.0 (`feat: v0.8 Docker + v0.9
Tool Qualification + full auditor evidence package`), which bundled the
Docker deliverable below alongside v0.9.0's tool-qualification suite.

### Added
- Docker multi-stage build (`Dockerfile`), `.dockerignore`, `docker-compose.yml`, CI Docker build job
- `docs/release-process.md` — release process documentation
- `.github/PULL_REQUEST_TEMPLATE.md` and issue templates
- `CHANGELOG.md`, `SECURITY.md`, `Makefile` added to the repo
- `sbom.json` and `provenance.json` committed in-tree; tool now passes its own RELEASE001/002 checks

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
