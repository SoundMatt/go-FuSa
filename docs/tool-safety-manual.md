# go-FuSa Tool Safety Manual

**Version:** 0.24.0  
**Module:** `github.com/SoundMatt/go-FuSa`  
**License:** Mozilla Public License 2.0  
**Standards addressed:** ISO 26262, IEC 61508, ISO 21434, DO-178C

---

## 1. Purpose

This document is the Tool Safety Manual for go-FuSa. It is intended for:

- Engineering teams qualifying go-FuSa for use in safety-critical Go projects
- Auditors assessing compliance with ISO 26262-8 (software tools), IEC 61508-3, or equivalent standards
- CI architects integrating go-FuSa into a regulated software development lifecycle

## 2. Tool Overview

go-FuSa is a functional safety enablement toolkit for Go projects. It is **not** a
certification product — it is an engineering accelerator that reduces the cost of
producing functional safety evidence throughout the SDLC.

Capabilities:

| Capability | Rules | Command |
|---|---|---|
| Project structure checks | FUSA001–005 | `gofusa check` |
| Safety coding standard analysis | LINT001–006 | `gofusa lint` |
| Static analysis (goroutines, context, error chains) | ANA001–009 | `gofusa analyze` |
| Requirements traceability and coverage | TRACE001–007 | `gofusa trace` |
| Test evidence collection | VERIFY001–002 | `gofusa verify` |
| Release artifact generation (SBOM SPDX 2.2/2.3/3.0.1, provenance, signing) | RELEASE001–002 | `gofusa release` |
| Tool qualification suite | QUALIFY001 | `gofusa qualify` |
| Safety case assembly (GSN, compliance mapping) | SAFETYCASE001 | `gofusa safety-case` |
| dFMEA generation from source | FMEA001 | `gofusa fmea` |
| Component boundary diagrams | BOUNDARY001 | `gofusa boundary` |
| Dependency vulnerability scan (OSV / govulncheck) | VULN001 | `gofusa vuln` |
| Evidence bundle for auditors | AUDITPACK001 | `gofusa audit-pack` |
| Cybersecurity static analysis (CWE-mapped) | CYBER001–020 | `gofusa cyber` |
| Threat Analysis and Risk Assessment (ISO 21434) | TARA001 | `gofusa tara` |
| IEC 62443 Security Level compliance | IEC62443-001–004 | `gofusa check` |
| SLSA L2/L3 supply-chain checks | SLSA001–003 | `gofusa check` |
| DO-178C Annex A gap report | — | `gofusa do178` |
| Software Accomplishment Summary (DO-178C §11.20) | — | `gofusa sas` |
| Software Configuration Index (DO-178C §11.16) | — | `gofusa sci` |
| Structural coverage report (DO-178C §6.4.4) | — | `gofusa coverage` |
| Problem report log (DO-178C §11.17) | PR001 | `gofusa pr` |
| Cyclomatic complexity (DO-178C §6.3.4) | COMP001 | `gofusa check` |
| Data/control coupling report generation | COUP001–003 | `gofusa coupling` |
| ISO 26262 Part 6 compliance gap report | ISO26262001 | `gofusa iso26262` |
| IEC 61508 Parts 1-3 compliance gap report | IEC61508001 | `gofusa iec61508` |
| Hazard Analysis and Risk Assessment (HARA) | HARA001–005 | `gofusa hara` |
| Finding disposition log | DISP001 | `gofusa disposition` |
| Change impact analysis | — | `gofusa impact` |
| Safety metrics trending | — | `gofusa metrics` |
| MISRA C:2023 alignment report | — | `gofusa misra` |
| ISO 21434 CAL-level gap report | ISO21434001 | `gofusa iso21434` |
| UN R.155 Annex 5 threat-category coverage | UNECE001 | `gofusa unece` |

## 3. Tool Classification

### ISO 26262-8 / IEC 61508-3 Assessment

go-FuSa is a **software development support tool**. Its potential impact on the
software under development:

- **Indirect** — it reports findings but does not modify, compile, or link the target software
- **No direct output** is incorporated into the safety-critical binary

| Criterion | Assessment |
|---|---|
| Tool output directly in safety-critical code? | No |
| Tool failure could cause an undetected error in the target? | Possible (false negative) |
| Recommended TCL (ISO 26262-8 Table 4) | **TCL2** |

### TCL Guidance

| TCL | When applicable | Required evidence |
|---|---|---|
| TCL1 | Informational use only; all findings reviewed by a qualified engineer | Usage record |
| TCL2 | Recommended for most regulated projects | This manual + `qualify-report.json` |
| TCL3 | Mandated only if the project safety plan requires it | Full validation package |

## 4. Installation

### Prerequisites

- Go 1.22 or later
- No external runtime dependencies (zero-dep design — enforced by `TestNoExternalDependencies`)

### Install from source

```
go install github.com/SoundMatt/go-FuSa/cmd/gofusa@latest
```

### Verify

```
gofusa version
```

### Docker (zero-install)

```
docker run --rm -v "$(pwd)":/project ghcr.io/soundmatt/go-fusa:latest check
```

## 5. Configuration Reference

go-FuSa is configured by a `.fusa.json` file in the project root, created by
`gofusa init`.

| Field | Type | Default | Description |
|---|---|---|---|
| `version` | string | `"1"` | Schema version |
| `project.name` | string | directory name | Project display name |
| `project.module` | string | from `go.mod` | Go module path |
| `project.standard` | string | `"generic"` | Safety standard: `ISO26262`, `IEC61508`, `ISO21434`, `DO178C`, `generic` |
| `project.asil` | string | `""` | ASIL / SIL level (informational, e.g. `"B"`, `"2"`) |
| `report.format` | string | `"text"` | Output format: `text` or `json` |
| `rules.exclude` | []string | `[]` | Rule IDs to suppress (must be justified in safety plan) |

### Example

```json
{
  "version": "1",
  "project": {
    "name": "my-safety-project",
    "module": "github.com/org/my-safety-project",
    "standard": "ISO26262",
    "asil": "B"
  },
  "report": {
    "format": "text"
  },
  "rules": {
    "exclude": []
  }
}
```

## 6. CLI Command Reference

### `gofusa init`

```
gofusa init [--dir <path>] [--standard <std>] [--module <mod>] [--name <name>] [--docs]
```

Creates `.fusa.json` in the project root. Does not overwrite an existing file.

### `gofusa check`

```
gofusa check [--dir <path>] [--format text|json] [--output <file>]
```

Runs all registered rules and reports findings.  
Exit 0 = no ERROR-severity findings. Exit 1 = one or more ERRORs.

### `gofusa trace`

```
gofusa trace [--dir <path>]
```

Scans source files for `//fusa:req <ID>` (implementation) and
`//fusa:test <ID>` (test) annotations. Reports each requirement as one of:
`[traced+tested]`, `[traced]`, `[tested]`, or `[untraced]`.

### `gofusa verify`

```
gofusa verify [--dir <path>] [--output <file>]
```

Runs `go test -json -count=1 ./...` and saves a structured evidence bundle to
`.fusa-evidence.json`.

### `gofusa release`

```
gofusa release [--dir <path>] [--output-dir <dir>]
```

Generates `sbom.json` (parsed from `go.mod`/`go.sum`) and `provenance.json`
(build environment snapshot) in the project root.

### `gofusa qualify`

```
gofusa qualify [--output <file>]
```

Runs the built-in qualification suite (positive and negative per rule)
and writes an integrity-hashed report to `qualify-report.json`.

### `gofusa iso26262`

```
gofusa iso26262 [--dir <path>] [--asil ASIL-A|ASIL-B|ASIL-C|ASIL-D] [--format text|json] [--output <file>]
```

Runs a 19-objective ISO 26262 Part 6–11 compliance gap assessment against evidence files in
the project root. Each objective is rated PASS / GAP / MANUAL / N/A.

### `gofusa iec61508`

```
gofusa iec61508 [--dir <path>] [--sil SIL-1|SIL-2|SIL-3|SIL-4] [--format text|json] [--output <file>]
```

Runs a 26-objective IEC 61508 Parts 1-3 compliance gap assessment.

### `gofusa hara`

```
gofusa hara [--dir <path>] <show|init|asil>
gofusa hara show [--format text|json|markdown] [--output <file>]
gofusa hara init [--project <name>] [--standard <std>]
gofusa hara asil -s <S0-S3> -e <E0-E4> -c <C0-C3>
```

Manages `.fusa-hara.json`. `init` creates a starter file; `show` renders the HARA with gap
analysis; `asil` derives ASIL from ISO 26262-3:2018 Table 4 (e.g. `S2 E4 C2 → ASIL-C`).

### `gofusa disposition`

```
gofusa disposition [--dir <path>] <add|list|show>
gofusa disposition add --rule <ID> --action accept|fix --rationale "<text>" [--reviewer <name>]
gofusa disposition list [--format text|json]
gofusa disposition show --rule <ID>
```

Maintains `.fusa-dispositions.json`. Documents decisions for ERROR findings so `gofusa check`
can suppress DISP001 for findings that have been reviewed and accepted.

### `gofusa impact`

```
gofusa impact [--dir <path>] [--from <ref>] [--to <ref>] [--format text|json] [--output <file>]
```

Runs a change impact analysis. Reports which requirements and tests are affected by changed
files, and which evidence artefacts are stale relative to source changes.

### `gofusa metrics`

```
gofusa metrics [--dir <path>] <record|show>
gofusa metrics record
gofusa metrics show [--format text|json]
```

Appends a timestamped snapshot to `.fusa-metrics.json` and renders a trend table.

### `gofusa misra`

```
gofusa misra [--format text|json] [--output <file>]
```

Generates a static MISRA C:2023 to Go / go-FuSa rule alignment report mapping 90+ rules to
`go vet / compiler`, go-FuSa rule IDs, `N/A — Go type system prevents this`, or `manual review`.

### `gofusa version`

Prints the tool version string.

## 7. Rule Reference

Findings carry one of three severities:

| Severity | Meaning | Default pipeline response |
|---|---|---|
| **ERROR** | Baseline safety requirement not met | Fail the pipeline (`gofusa check` exits 1) |
| **WARNING** | Potential safety concern; engineering judgement required | Review and document rationale; do not ship without disposition |
| **INFO** | Observation relevant to completeness or future hardening | Review; document acceptance if relevant |

### FUSA — Project Structure Rules

| Rule | Severity | Trigger | Remediation |
|---|---|---|---|
| `FUSA001` | ERROR | `.fusa.json` not found | Run `gofusa init` |
| `FUSA002` | ERROR | `go.mod` not found | Add a `go.mod` file |
| `FUSA003` | WARNING | `LICENSE` not found | Add a license file |
| `FUSA004` | WARNING | `README.md` not found | Add a README |
| `FUSA005` | WARNING | No CI configuration found (`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, etc.) | Add a CI pipeline definition |

### LINT — Safety Coding Standard Rules

These rules scan all non-test, non-vendor, non-generated `.go` files.

| Rule | Severity | Trigger | Remediation |
|---|---|---|---|
| `LINT001` | WARNING | Error discarded via blank identifier (`_, err = f()`) | Propagate or wrap the error |
| `LINT002` | WARNING | `panic()` call detected | Replace with explicit error return; document in safety plan if retained |
| `LINT003` | INFO | `recover()` call detected | Verify recovery is intentional and documented |
| `LINT004` | WARNING | `unsafe` package imported | Justify use; document in safety plan |
| `LINT005` | INFO | `reflect` package imported | Verify reflection is limited and intentional |
| `LINT006` | INFO | Package-level `var` (mutable global state) | Prefer dependency injection or `sync.Once` |

### ANA — Static Analysis Rules

AST-level analysis. False positives may occur with concurrency frameworks
(e.g. `errgroup`, worker pools).

| Rule | Severity | Trigger | Remediation |
|---|---|---|---|
| `ANA001` | WARNING | Goroutine launched without a cancellation or done signal | Pass `context.Context` or `chan struct{}` |
| `ANA002` | WARNING | Goroutine launched inside a `for`/`range` loop | Move launch outside the loop or use a worker pool |
| `ANA003` | WARNING | `time.Sleep` inside a goroutine | Replace with `time.After` / `select` with cancellation |
| `ANA004` | WARNING | `defer` inside a `for`/`range` loop | Move `defer` outside the loop or use an explicit cleanup closure |
| `ANA005` | WARNING | `context.Background()`/`context.TODO()` used inside a function that already accepts `context.Context` | Propagate the received context |
| `ANA006` | WARNING | `fmt.Errorf` without `%w` — error chain lost | Use `%w` to wrap the underlying error |
| `ANA007` | WARNING | Two-result function result used without a prior `err != nil` check | Check the error before using the value |
| `ANA008` | WARNING | Goroutine literal accesses a package-level variable without synchronisation | Use a mutex, channel, or `sync/atomic` |
| `ANA009` | WARNING | Unreachable code after unconditional `return`/`break`/`continue`/`panic` | Remove the dead code (DO-178C §6.4.4.2) |

### TRACE — Traceability Rules

| Rule | Severity | Trigger | Remediation |
|---|---|---|---|
| `TRACE001` | INFO | `.fusa-reqs.json` not found | Create it manually or via `gofusa trace` |
| `TRACE002` | WARNING | Requirement has no `//fusa:req` annotation in source | Add `//fusa:req <ID>` in the implementing file |
| `TRACE003` | INFO | Requirement has no `//fusa:test` annotation | Add `//fusa:test <ID>` in the test file |
| `TRACE004` | WARNING | Requirement missing `text` field in `.fusa-reqs.json` | Add a `text` description to the requirement |
| `TRACE005` | WARNING | Same file has both `//fusa:req` and `//fusa:test` for the same req (verification independence) | Separate impl and test annotations across files |
| `TRACE006` | WARNING | Fewer than 80% of requirements have `//fusa:req` annotations in source | Add implementation annotations or lower threshold |
| `TRACE007` | INFO | Exported-function annotation density below 80% | Add `//fusa:req` annotations to more files |

### VERIFY — Test Evidence Rules

| Rule | Severity | Trigger | Remediation |
|---|---|---|---|
| `VERIFY001` | INFO | `.fusa-evidence.json` not found | Run `gofusa verify` |
| `VERIFY002` | WARNING | Evidence bundle records failing tests | Fix the failing tests |

### RELEASE — Release Artifact Rules

| Rule | Severity | Trigger | Remediation |
|---|---|---|---|
| `RELEASE001` | WARNING | `sbom.json` not found | Run `gofusa release` |
| `RELEASE002` | WARNING | `provenance.json` not found | Run `gofusa release` |

### QUALIFY — Qualification Rules

| Rule | Severity | Trigger | Remediation |
|---|---|---|---|
| `QUALIFY001` | INFO | `qualify-report.json` not found | Run `gofusa qualify` |

## 8. CI Pipeline Integration

Recommended GitHub Actions integration:

```yaml
name: Safety
on: [push, pull_request]

jobs:
  safety:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"
      - run: go install github.com/SoundMatt/go-FuSa/cmd/gofusa@latest
      - run: gofusa check
      - run: gofusa trace
      - run: gofusa verify
      - run: gofusa release
      - run: gofusa qualify
      - uses: actions/upload-artifact@v4
        with:
          name: safety-evidence
          path: |
            .fusa-evidence.json
            sbom.json
            provenance.json
            qualify-report.json
```

Recommended pipeline order:

1. `gofusa check` — fail fast on structural and coding standard issues
2. `gofusa trace` — verify requirement coverage
3. `gofusa verify` — run tests and collect evidence
4. `gofusa release` — generate SBOM and provenance
5. `gofusa qualify` — produce qualification report

## 9. Rule Exclusions

Rules may be excluded by adding their ID to `rules.exclude` in `.fusa.json`:

```json
{ "rules": { "exclude": ["FUSA005"] } }
```

Exclusions suppress findings but are visible in every generated report.

**Safety plan obligation:** Every exclusion must be justified in the project
safety plan before the release is accepted. Acceptable justifications include:

- The rule is inapplicable to this project type (e.g., `FUSA005` for a library
  with no CI)
- A compensating control exists (e.g., `LINT004` excluded because all `unsafe`
  use is reviewed and documented)

## 10. Known Limitations

1. **LINT001** detects the explicit blank-identifier form only (`_, err = f()`).
   Errors returned as the sole return value and silently discarded, or errors
   returned by functions called as statements, are not detected. Supplement with
   `errcheck` or manual review for complete coverage.

2. **ANA001–ANA004** perform textual and AST-level analysis without
   interprocedural or data-flow analysis. They may produce false positives when
   concurrency patterns are abstracted behind helper functions or third-party
   frameworks.

3. **TRACE002** confirms that a `//fusa:req <ID>` annotation exists somewhere in
   the source tree. It does not verify that the annotated code correctly
   implements the requirement — that is a human review responsibility.

4. The tool does not analyze:
   - Assembly files (`.s`)
   - `cgo` code (`import "C"`)
   - Files matching `// Code generated` (excluded by convention)
   - Vendored dependencies (`vendor/` directory is skipped)
   - Hidden directories (`.git`, `.github`, etc.)

5. `gofusa verify` runs `go test -json -count=1 ./...` in the project root.
   Projects requiring build tags, environment variables, or external services
   must configure the environment before invoking `gofusa verify`.

6. Evidence files include SHA-256 integrity hashes but are not cryptographically
   signed. Use `cosign` or similar for a tamper-evident chain of custody in
   regulated environments.

7. go-FuSa performs static and structural analysis only. It does not replace:
   - Dynamic testing
   - Formal verification
   - Manual code review by a qualified safety engineer
   - Model-based testing or coverage measurement

## 11. Assumptions of Use

The following conditions must hold for go-FuSa findings to be meaningful in a
safety argument:

| # | Assumption |
|---|---|
| AoU-1 | The tool is applied to the **complete** Go source tree. Selective analysis of a subset may produce incomplete findings. |
| AoU-2 | Findings are reviewed by a **qualified safety engineer** before use in a safety case. go-FuSa automates detection; it does not replace engineering judgement. |
| AoU-3 | The tool is installed from a verified source (module proxy with checksum verification, or a pinned artifact), and its version is recorded in the project safety plan. |
| AoU-4 | `qualify-report.json` is **regenerated** whenever the tool version changes. A report generated by a prior version does not provide evidence for the current version. |
| AoU-5 | Rule exclusions in `rules.exclude` are reviewed and justified in the safety plan **before each release**. |
| AoU-6 | `gofusa verify` is run against the **same test suite** executed during integration testing. Running against a subset produces incomplete evidence. |

## 12. Tool Qualification Evidence Summary

| Evidence Item | Location | Generated By |
|---|---|---|
| Rule specification | `engine/rules.go`, `lint/*.go`, `analyze/*.go`, etc. | Source code |
| Test specification | `*_test.go` files (163 tests) | Source code |
| Test results | `.fusa-evidence.json` | `gofusa verify` |
| Qualification report | `qualify-report.json` | `gofusa qualify` |
| SBOM | `sbom.json` | `gofusa release` |
| Build provenance | `provenance.json` | `gofusa release` |
| Traceability matrix | stdout of `gofusa trace` | `gofusa trace` |
| This document | `docs/tool-safety-manual.md` | Manual |

### Assembling a qualification package

1. Run `gofusa qualify` — verify all cases pass
2. Run `gofusa verify` — verify all tests pass
3. Run `gofusa release` — generate SBOM and provenance
4. Archive: this document, `qualify-report.json`, `.fusa-evidence.json`,
   `sbom.json`, `provenance.json`
5. Record the tool version and SHA-256 hash of the `gofusa` binary in the
   project safety plan

---

*go-FuSa is open source under the Mozilla Public License 2.0. The MPL 2.0 permits
use in commercial and regulated products. See `LICENSE` for terms.*
