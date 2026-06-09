# gofusa analyze

Run deeper static analysis passes using the `go/analysis` framework.

## Synopsis

```
gofusa analyze [flags]
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--dir` | `.` | Project root to analyse |
| `--format` | `text` | Output format: `text`, `json` |
| `--output` | — | Write output to file |
| `--pass` | — | Run only the named pass (repeatable) |

## Analysis passes

| Pass ID | Description |
|---------|-------------|
| `ANA001` | Detect shadowed error variables |
| `ANA002` | Detect unchecked type assertions |
| `ANA003` | Detect integer overflow in safety-critical arithmetic |
| `ANA004` | Detect use of `time.Sleep` in non-test code |
| `ANA005` | Detect missing `//nolint` justification comments |
| `ANA006` | Detect functions exceeding cyclomatic complexity threshold |
| `ANA007` | Detect missing package-level doc comments |
| `ANA008` | Detect `log.Fatal` / `os.Exit` outside of `main` |
| `ANA009` | Detect missing `context.Context` propagation |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings above configured severity |
| `1` | Findings found, or tool error |

## Examples

```sh
# Run all analysis passes
gofusa analyze

# Run only cyclomatic complexity pass
gofusa analyze --pass ANA006

# JSON output
gofusa analyze --format json --output analyze-report.json
```

## Integration with go/analysis

The analysis passes are implemented using the standard `golang.org/x/tools/go/analysis`
framework and can also be invoked as a standalone analyser via `go vet -vettool`.

```sh
# Build a vet plugin
go build -o fusa-vet ./analyze/plugin
go vet -vettool=./fusa-vet ./...
```

## See also

- `gofusa lint` — lightweight source-pattern rules
- `gofusa check` — run all rules
- `gofusa sas` — generate Software Accomplishment Summary
