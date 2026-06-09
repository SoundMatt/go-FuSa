# gofusa trace

Manage requirements traceability — import, export, verify coverage, and generate reports.

## Synopsis

```
gofusa trace <subcommand> [flags]
```

## Subcommands

| Subcommand | Description |
|------------|-------------|
| `show` | Display requirements with optional filtering |
| `import` | Import requirements from CSV, DOORS (ReqIF), or Polarion XML |
| `export` | Export requirements to CSV, DOORS (ReqIF), or Polarion XML |
| `check` | Verify all requirements have a linked test |
| `sec-tested` | Report percentage of security requirements with tests |

## Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `--dir` | `.` | Project root (must contain `.fusa-reqs.json`) |

## gofusa trace show

```
gofusa trace show [--filter <text>] [--format text|json]
```

Display requirements stored in `.fusa-reqs.json`. Use `--filter` to search by
ID, title, or text.

## gofusa trace import

```
gofusa trace import --file <path> [--format csv|doors|polarion]
```

Import requirements into `.fusa-reqs.json`.

### Supported formats

| Format | Description |
|--------|-------------|
| `csv` | Two-column CSV: `id,title` |
| `doors` | IBM DOORS ReqIF XML (`.reqif`) |
| `polarion` | Siemens Polarion XML work-items export |

## gofusa trace export

```
gofusa trace export [--format csv|doors|polarion] [--output <path>]
```

Export requirements from `.fusa-reqs.json`.

### Supported formats

| Format | Description |
|--------|-------------|
| `csv` | Two-column CSV with header |
| `doors` | Minimal ReqIF XML for import into IBM DOORS |
| `polarion` | Polarion work-items XML with ASIL custom field |

## gofusa trace check

```
gofusa trace check [--format text|json] [--output <path>]
```

Verify that every requirement in `.fusa-reqs.json` has at least one associated
test annotation (`// fusa:req REQ-XXX` or `t.Log("req:REQ-XXX")`). Exits 1 if
any requirement is untested.

## gofusa trace sec-tested

```
gofusa trace sec-tested [--threshold <pct>] [--format text|json]
```

Report the percentage of requirements tagged `security` that have a linked test.
Exits 1 if the percentage falls below `--threshold` (default 100).

## Examples

```sh
# Show all requirements
gofusa trace show

# Import from DOORS export
gofusa trace import --file requirements.reqif --format doors

# Export to Polarion
gofusa trace export --format polarion --output polarion-export.xml

# Verify full traceability (CI gate)
gofusa trace check

# Security coverage gate (≥ 80%)
gofusa trace sec-tested --threshold 80
```

## Requirement annotation syntax

Annotate test functions to link them to requirements:

```go
func TestLoginValidation(t *testing.T) {
    // fusa:req REQ-AUTH-001
    // ...
}
```

Or using log statements (picked up by the tracer):

```go
t.Log("req:REQ-AUTH-001")
```

## See also

- `gofusa check` — run all safety rules
- `gofusa report` — generate HTML/JSON traceability report
