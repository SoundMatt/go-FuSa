# MISRA C — Guidelines for the Use of the C Language

go-FuSa maps relevant MISRA C:2012 guidelines to Go language equivalents
and enforces them via lint and analysis rules.

## Overview

MISRA C:2012 (with AMD 1:2016 and AMD 2:2020) provides coding guidelines for
safety-critical C software. go-FuSa provides Go-language analogues for the
most safety-relevant MISRA C rules.

Although Go is not C, many automotive and industrial safety programmes require
MISRA-aligned justification for any language used. This document maps MISRA C
directives to go-FuSa rules and explains the Go-language rationale.

## Rule mapping

| MISRA C:2012 | Severity | Go analogue | go-FuSa rule |
|-------------|----------|-------------|--------------|
| Dir 4.1 — Run-time failures shall be minimised | Required | No `panic` in production | `LINT001` |
| Dir 4.7 — Errors shall be tested | Required | Check all error returns | `LINT003` |
| Rule 1.3 — No undefined behaviour | Required | No `unsafe` | `LINT002` |
| Rule 8.9 — Minimise object scope | Advisory | No pkg-level mutable globals | `LINT004` |
| Rule 14.1 — Unreachable code | Advisory | Detected by `go vet` | `go vet` |
| Rule 15.5 — Single exit point | Advisory | Complexity analysis | `ANA006` |
| Rule 17.7 — Return value of non-void functions | Required | Unused returns | `LINT003` |
| Rule 18.1 — Pointer arithmetic | Required | Forbidden without `unsafe` | `LINT002` |
| Rule 21.6 — Standard I/O not used in production | Required | Audit `fmt.Print*` calls | `ANA008` |

## Language subset justification

For projects that must justify Go under a MISRA or language-subset requirement:

1. **Memory safety** — Go is garbage-collected with bounds-checked arrays; no
   manual memory management or pointer arithmetic is possible without `unsafe`.
2. **No undefined behaviour** — Go's specification does not permit undefined
   behaviour; the language eliminates buffer overflows, dangling pointers, and
   signed integer overflow (wraps, no UB).
3. **Concurrency** — Go's race detector (`-race`) detects data races at test
   time; channel communication makes synchronisation explicit.
4. **Error handling** — Multiple return values and the error interface enforce
   explicit error propagation; unhandled errors are detected by `LINT003`.

## Using go-FuSa with MISRA C guidelines

```sh
# Enforce the MISRA-analogous rules
gofusa lint

# Full static analysis
gofusa analyze

# Generate compliance evidence
gofusa check --format json --output misra-analog-report.json
```

## Deviations

MISRA C requires a formal deviation process for any rule violation. go-FuSa
supports this via `//nolint` justification tracking (ANA005):

```go
//nolint:LINT001 // deviation: panic used only in init; verified no recovery path needed
func mustLoadConfig() *Config {
    c, err := loadConfig()
    if err != nil {
        panic(err) // MISRA deviation ref: DEV-2024-001
    }
    return c
}
```

ANA005 will flag `//nolint` comments that lack a justification comment on the
same line, enforcing the MISRA deviation documentation requirement.

## Standards that reference MISRA C

| Standard | Reference |
|----------|-----------|
| ISO 26262-6 | Table 1 — coding guidelines (highly recommended) |
| IEC 61508-3 | Table A.4 — language subset (recommended at SIL 2+) |
| EN 50128 | §A.1 / §A.12 — coding standards (mandatory at SIL 3+) |
| DO-178C | AC §2.4 — software coding standards |

## See also

- `docs/commands/lint.md`
- `docs/commands/analyze.md`
- `docs/standards/iso26262.md`
- `docs/standards/iec61508.md`
