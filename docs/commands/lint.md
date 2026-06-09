# gofusa lint

Run safety-focused lint rules against Go source files.

## Synopsis

```
gofusa lint [flags] [packages...]
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--dir` | `.` | Project root |
| `--format` | `text` | Output format: `text`, `json` |
| `--output` | — | Write output to file |

## Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `LINT001` | ERROR | `panic` call detected in non-test code |
| `LINT002` | ERROR | `unsafe` package imported |
| `LINT003` | WARNING | Error return value ignored |
| `LINT004` | WARNING | Package-level mutable global variable |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No ERROR-level lint findings |
| `1` | One or more ERROR findings, or tool error |

## Examples

```sh
# Lint current project
gofusa lint

# JSON output
gofusa lint --format json --output lint-report.json
```

## Rationale

These rules enforce the subset of Go coding practices required by functional
safety standards:

- **LINT001** — `panic` is non-deterministic and violates IEC 61508 §7.4.3
  (defensive programming) and DO-178C guidance on robustness.
- **LINT002** — `unsafe` bypasses the Go type system and is prohibited by
  ISO 26262-6 Table 1 (language subset).
- **LINT003** — Unchecked errors are a common root cause of safety incidents;
  required to be handled by IEC 61508 §7.4.7.
- **LINT004** — Mutable global state introduces coupling that complicates
  formal verification; flagged under ISO 26262-6 §5.4.

## See also

- `gofusa check` — run all rules (lint + analyze + standard-specific)
- `gofusa analyze` — deeper static analysis passes
