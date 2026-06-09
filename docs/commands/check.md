# gofusa check

Run all registered safety rules against a project and report findings.

## Synopsis

```
gofusa check [flags]
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--dir` | `.` | Project root to analyse |
| `--format` | `text` | Output format: `text`, `json`, `sarif` |
| `--output` | — | Write output to file instead of stdout |
| `--standard` | — | Filter rules to a specific standard (e.g. `ISO26262`, `DO178C`) |
| `--severity` | — | Minimum severity to report (`INFO`, `WARNING`, `ERROR`) |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings at ERROR severity |
| `1` | One or more ERROR-level findings, or tool error |

## Output formats

### text (default)

Human-readable table of findings with rule ID, severity, message, and location.

### json

Machine-readable array of finding objects:

```json
[
  {
    "rule": "LINT001",
    "severity": "ERROR",
    "message": "panic call in safety-critical path",
    "file": "main.go",
    "line": 42
  }
]
```

### sarif

SARIF 2.1.0 output suitable for upload to GitHub Code Scanning via
`github/codeql-action/upload-sarif`.

## Examples

```sh
# Text report on current directory
gofusa check

# JSON report written to file
gofusa check --format json --output check-report.json

# SARIF for GitHub Code Scanning
gofusa check --format sarif --output results.sarif

# Only ISO 26262 rules
gofusa check --standard ISO26262
```

## Rule categories

Rules are loaded from the following packages (registered via `init()`):

| Package | Rule prefix | Standards |
|---------|-------------|-----------|
| `lint/` | `LINT` | all |
| `analyze/` | `ANA` | all |
| `coupling/` | `COUP` | ISO 26262, IEC 61508 |
| `iso26262/` | `ISO26262` | ISO 26262 |
| `iec61508/` | `IEC61508` | IEC 61508 |
| `do178c/` | `DO178C` | DO-178C |
| `iso21434/` | `ISO21434` | ISO 21434 |
| `unece/` | `UNECE` | UN R.155 |

## See also

- `gofusa lint` — run only lint rules
- `gofusa analyze` — run only static analysis passes
- `gofusa qualify` — full qualification evidence bundle
