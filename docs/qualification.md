# Tool Qualification Guide

## Overview

ISO 26262 Part 8 and IEC 61508 Part 6 require that software tools used in safety-related
development processes be qualified. Tool qualification establishes confidence that a tool
performs its intended function correctly — it does not certify the tool, but provides
documented evidence to support a safety assessor's judgement.

go-FuSa provides a built-in qualification suite (`gofusa qualify`) that generates
machine-readable evidence conforming to these requirements.

## Running the qualification suite

```bash
gofusa qualify
```

This command:

1. Runs 44 built-in test cases (one positive, one negative per rule).
2. Verifies that each rule detects the pattern it claims to detect.
3. Verifies that each rule does not produce false positives on clean code.
4. Writes `qualify-report.json` with a SHA-256 integrity hash.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | All cases passed |
| 1 | One or more cases failed, or report could not be written |

## Report structure

`qualify-report.json` contains:

```json
{
  "generatedAt": "2026-01-01T12:00:00Z",
  "goVersion":   "go1.22.0",
  "module":      "github.com/SoundMatt/go-FuSa",
  "total":       44,
  "passed":      44,
  "failed":      0,
  "results": [
    {
      "case": {
        "name":          "FUSA001-pos: missing .fusa.json",
        "ruleId":        "FUSA001",
        "description":   "Project without .fusa.json must produce a FUSA001 finding.",
        "expectFinding": true
      },
      "passed": true
    }
  ],
  "hash": "a3f2...e8b1"
}
```

The `hash` field is a SHA-256 of the report contents (excluding the hash field itself),
providing tamper evidence.

## Verifying the integrity hash

```bash
# Recompute and compare manually:
jq 'del(.hash)' qualify-report.json | sha256sum
```

The output should match the `hash` field in the report.

## What is tested

The suite covers the core engine rules spanning all packages:

| Rule | Package | What is tested |
|---|---|---|
| FUSA001 | engine | `.fusa.json` present / absent |
| FUSA002 | engine | `go.mod` present / absent |
| FUSA003 | engine | `LICENSE` present / absent |
| FUSA004 | engine | `README` present / absent |
| FUSA005 | engine | CI config present / absent |
| LINT001 | lint | Discarded error return detected / not detected |
| LINT002 | lint | `panic()` call detected / not detected |
| LINT003 | lint | `recover()` call detected / not detected |
| LINT004 | lint | `unsafe` import detected / not detected |
| LINT005 | lint | `reflect` import detected / not detected |
| LINT006 | lint | Global mutable var detected / not detected |
| ANA001 | analyze | Goroutine without termination signal |
| ANA002 | analyze | Goroutine spawned in loop |
| ANA003 | analyze | `time.Sleep` in goroutine |
| ANA004 | analyze | `defer` inside loop |
| ANA005 | analyze | `context.Background()` inside function with context param |
| ANA006 | analyze | `fmt.Errorf` without `%w` — error chain lost |
| ANA007 | analyze | Two-result function used without nil check |
| ANA008 | analyze | Goroutine accessing package-level var without sync |
| ANA009 | analyze | Dead code after unconditional transfer |
| TRACE001 | trace | `.fusa-reqs.json` present / absent |
| TRACE002 | trace | Untraced requirement detected |
| TRACE003 | trace | Requirement with no `//fusa:test` annotation |
| TRACE004 | trace | Requirement missing `text` field |
| TRACE005 | trace | Verification independence (same file has req + test) |
| TRACE006 | trace | Aggregate req-to-source traceability below threshold |
| TRACE007 | trace | Exported-function annotation density below threshold |
| VERIFY001 | verify | Test evidence bundle present / absent |
| VERIFY002 | verify | Failed tests in bundle detected |
| RELEASE001 | release | `sbom.json` present / absent |
| RELEASE002 | release | `provenance.json` present / absent |
| QUALIFY001 | qualify | `qualify-report.json` present / absent |
| SAFETYCASE001 | safetycase | `safety-case.json` present / absent |
| FMEA001 | fmea | `fmea.json` present / absent |
| BOUNDARY001 | boundary | `boundary.mermaid` present / absent |
| AUDITPACK001 | auditpack | `audit-pack.zip` present / absent |
| VULN001 | vuln | `vuln.json` present / absent |
| TARA001 | tara | `tara.json` present / absent |
| PR001 | pr | Problem report log present / open critical PRs |
| COMP001 | comp | Cyclomatic complexity exceeds threshold |
| COUP001 | coupling | Exported mutable package-level variable |
| COUP002 | coupling | Exported function with func/interface parameter |
| SLSA001–003 | slsa | SLSA L2/L3 provenance and CODEOWNERS checks |
| IEC62443-001–004 | iec62443 | IEC 62443 Security Level configuration checks |
| CYBER001–020 | cyber | CWE-mapped cybersecurity static analysis rules |

## Tool Confidence Level

Under IEC 61508-3, tools are assigned a Tool Confidence Level (TCL) based on:

- **TC1** — No tool confidence measures needed (tool output does not influence safety).
- **TC2** — Tool has been validated by other means (version control, known inputs, review).
- **TC3** — Full tool qualification documentation required.

go-FuSa is primarily a **TC2** tool: its output (findings and reports) influences the
safety process but does not directly generate executable safety-critical code. The
qualification suite supports TC2 validation by providing documented evidence that the
tool's analysis rules behave as specified.

For organisations that require TC3, the qualification suite provides:

- Version-stamped, hashed reports (tamper evidence).
- Complete test case specifications (inputs and expected outputs).
- Machine-readable results for audit trail integration.

## Integration into a safety case

Include the qualification report in your project's safety case package alongside:

- `sbom.json` — Software Bill of Materials.
- `provenance.json` — Build provenance.
- `.fusa-evidence.json` — Test evidence bundle.
- Traceability matrix (`gofusa trace --format json`).

The complete artefact set provides evidence for:

- §8.4.4 of ISO 26262-8 (tool use qualification).
- §7.4.4.10 of IEC 61508-3 (software tool qualification).

## Regenerating the report

The qualification report should be regenerated:

- On every release of go-FuSa used in the project.
- When the Go toolchain version changes.
- As part of the CI pipeline (add `gofusa qualify` as a CI step).

Example GitHub Actions step:

```yaml
- name: go-FuSa qualify
  run: gofusa qualify --output qualify-report.json
- name: Upload qualification report
  uses: actions/upload-artifact@v4
  with:
    name: qualify-report
    path: qualify-report.json
```
