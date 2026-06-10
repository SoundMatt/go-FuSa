# go-FuSa

A functional safety enablement toolkit for Go projects. go-FuSa provides static checks,
coding rules, traceability helpers, CI evidence bundles, reproducible build metadata,
runtime safety patterns, and tool qualification support to help teams build safety cases
for ISO 26262, IEC 61508, ISO 21434, and DO-178C.

[![CI](https://github.com/SoundMatt/go-FuSa/actions/workflows/ci.yml/badge.svg)](https://github.com/SoundMatt/go-FuSa/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/SoundMatt/go-FuSa.svg)](https://pkg.go.dev/github.com/SoundMatt/go-FuSa)

> **Not a certification product.** go-FuSa is an engineering accelerator that reduces
> the cost of producing functional safety evidence throughout the SDLC.

## Packages

| Package | Description |
|---|---|
| `.` | `fusa` — core types, sentinel errors, and `Version` constant |
| `config/` | Project configuration (`gofusa init`, `.fusa.json`) |
| `engine/` | Rule registration, execution engine, FUSA001–005 built-in rules |
| `report/` | Text and JSON compliance report renderers |
| `template/` | Safety plan, test evidence, and HARA document generators |
| `lint/` | Safety-oriented coding rules (error handling, panic, unsafe, globals) |
| `analyze/` | Static analysis passes (goroutine leaks, race patterns, blocking calls) |
| `trace/` | Requirements traceability engine and coverage mapping |
| `verify/` | Test evidence collection and verification bundle generation |
| `release/` | SBOM generation, build provenance, artifact signing |
| `qualify/` | Tool qualification suite — self-test framework and evidence report |
| `runtime/` | Reusable safety patterns — watchdog, heartbeat, safe-state transitions |
| `testutil/` | Test harness helpers |
| `safetycase/` | Safety case assembly — evidence collection, GSN diagram, compliance mapping |
| `fmea/` | dFMEA generation — derives failure modes, effects, and severities from exported functions |
| `boundary/` | Component boundary diagrams — package dependency graph in Mermaid and DOT formats |
| `cyber/` | Cybersecurity static analysis — 20 CWE-mapped rules (ISO 21434, gosec, CERT, MISRA-C:2023) |
| `iec62443/` | IEC 62443 industrial cybersecurity compliance — Security Level checks, SECURITY.md, incident response |
| `slsa/` | SLSA L2/L3 supply-chain checks — provenance fields, CODEOWNERS, branch-protection evidence |
| `tara/` | Threat Analysis and Risk Assessment (TARA) — ISO 21434 Ch. 9, STRIDE/CWE/risk mapping, Markdown export |
| `vuln/` | Dependency vulnerability scanner — OSV API + govulncheck call-graph analysis |
| `sarif/` | SARIF 2.1.0 renderer — produces GitHub Code Scanning compatible output |
| `badge/` | SVG badge generator — Shields.io-style status badge from check results |
| `diff/` | Report diff engine — compares two JSON reports (introduced/resolved/unchanged) |
| `comp/` | Cyclomatic complexity analysis — COMP001 (DO-178C §6.3.4) |
| `coupling/` | Data/control coupling detection — COUP001/COUP002 (DO-178C §6.4.4.3) |
| `coverage/` | Structural coverage report from `coverage.out` — statement, decision, MC/DC (DO-178C §6.4.4) |
| `pr/` | Problem report log — CRUD log + PR001 engine rule (DO-178C §11.17) |
| `sci/` | Software Configuration Index — SHA-256 checksums of lifecycle data items (DO-178C §11.16) |
| `do178/` | DO-178C Annex A gap report — 38 objectives across Tables A-1 through A-11 |
| `sas/` | Software Accomplishment Summary — 20 evidence items (DO-178C §11.20) |
| `iso21434/` | ISO 21434 cybersecurity engineering — CAL 1–4 gap assessment, TARA evidence checking |
| `unece/` | UN R.155 Annex 5 — threat-category coverage assessment (TC-1 through TC-9) |
| `cmd/gofusa` | CLI — `init`, `check`, `lint`, `analyze`, `template`, `report`, `trace`, `verify`, `release`, `qualify`, `safety-case`, `fmea`, `boundary`, `vuln`, `audit-pack`, `cyber`, `tara`, `diff`, `badge`, `req`, `fix`, `hooks`, `sign`, `do178`, `sas`, `sci`, `coverage`, `pr`, `coupling`, `iso21434`, `unece` |

## Install

```bash
go install github.com/SoundMatt/go-FuSa/cmd/gofusa@latest
```

## Quick start

```bash
# Initialise a project
gofusa init

# Run all safety checks (exit 1 on ERROR; --strict exits 1 on WARNING too)
gofusa check
gofusa check --strict

# Run only coding-standard lint rules
gofusa lint

# Run only static-analysis rules
gofusa analyze

# Run cybersecurity analysis (20 rules: gosec, ISO 21434, CWE-mapped; writes cyber-report.json)
gofusa cyber
gofusa cyber --strict  # exit 1 on any finding

# Generate a Threat Analysis and Risk Assessment (TARA) per ISO 21434 Ch. 9
gofusa tara  # writes tara.json + tara.md

# Enrich dFMEA with cyber risk context
gofusa fmea --cyber  # cross-references CYBER findings into FMEA entries by file

# Generate safety document templates (SAFETY_PLAN.md, TEST_EVIDENCE.md, HARA.md)
gofusa template --type all

# Show the requirements traceability matrix
gofusa trace

# Run tests and save a test evidence bundle
gofusa verify

# Generate SBOM (SPDX 2.2/2.3/3.0.1), build provenance, and artifact manifest
gofusa release                          # SPDX 3.0.1 (default)
gofusa release --spdx-version 2.3      # SPDX 2.3 JSON
gofusa release --spdx-version 2.2      # SPDX 2.2 JSON

# Run the tool qualification suite
gofusa qualify

# Generate a full compliance report
gofusa report

# Assemble a safety case (Markdown + JSON + Mermaid GSN diagram)
gofusa safety-case
gofusa safety-case --standard iso26262

# Generate a dFMEA table from exported functions (JSON + CSV)
gofusa fmea

# Generate a component boundary diagram (Mermaid + DOT)
gofusa boundary

# Scan dependencies for known vulnerabilities (OSV database / ISO 21434)
gofusa vuln

# Bundle all evidence artifacts into a single ZIP for auditors
gofusa audit-pack

# Generate a full HTML compliance report
gofusa report --format html --output safety-report.html

# Show test coverage gaps (requirements with no //fusa:test tag)
gofusa trace --gaps

# Enforce ≥80% of requirements have //fusa:test tags (CI gate)
gofusa trace --sec-tested 80

# Assess requirement-to-source coverage and function annotation density (DO-178C §6.4.4)
gofusa trace --req-coverage 80   # exits 1 if either metric is below 80%

# Show a specific requirement and its annotation locations
gofusa req REQ-CYBER001

# Show auto-fixable findings with remediation guidance
gofusa fix

# Install a pre-commit hook that runs gofusa check --strict
gofusa hooks install
gofusa hooks remove

# Sign a release artifact (HMAC-SHA256)
gofusa sign --keygen my.key
gofusa sign --key my.key artifact.zip          # creates artifact.zip.sig
gofusa sign --verify --key my.key artifact.zip  # verifies artifact.zip.sig

# Compare two check reports (CI regression gate — exits 1 if new findings introduced)
gofusa diff baseline.json current.json

# Generate an SVG status badge from a check report
gofusa check --format json --output report.json
gofusa badge report.json --output badge.svg

# Output SARIF 2.1.0 for GitHub Advanced Security / Code Scanning
gofusa check --format sarif --output results.sarif

# Generate data/control coupling report (DO-178C §6.4.4.3 — writes coupling-report.json)
gofusa coupling
gofusa coupling --dir ./mypackage --output coupling-report.json

# DO-178C compliance: gap report, SAS, SCI, structural coverage, problem reports
gofusa do178 --dal DAL-B                          # Annex A objectives gap report
gofusa sas --dal DAL-B --prepared-by "Jane Doe"   # Software Accomplishment Summary
gofusa sci --format markdown                       # Software Configuration Index
gofusa coverage --dal DAL-B coverage.out           # Structural coverage report
gofusa pr init                                    # Create problem report log
gofusa pr add --id PR-001 --title "Bug" --severity minor
gofusa pr list
gofusa pr close --id PR-001 --resolution "Fixed"

# Plan templates (SDP, SVP, SCMP, SQAP)
gofusa template --type svp
gofusa template --type all   # generates SAFETY_PLAN.md, SVP.md, SCMP.md, SQAP.md

# ISO 26262 gap report (ASIL-A through ASIL-D)
gofusa iso26262 --asil ASIL-B

# IEC 61508 gap report (SIL-1 through SIL-4)
gofusa iec61508 --sil SIL-2

# ISO 21434 cybersecurity gap report (CAL-1 through CAL-4)
gofusa iso21434 --cal CAL-3

# UN R.155 Annex 5 threat-category coverage
gofusa unece

# Hazard Analysis and Risk Assessment (HARA)
gofusa hara init                              # create .fusa-hara.json
gofusa hara show                              # display as Markdown table
gofusa hara asil -s S2 -e E4 -c C2           # derive ASIL from S/E/C → ASIL-C

# Finding disposition log (accept or schedule-fix for ERROR findings)
gofusa disposition add --rule LINT001 --action accept --rationale "false positive"
gofusa disposition list

# Change impact analysis (what requirements/tests are affected by changed files)
gofusa impact

# Safety metrics trending (finding counts, coverage %, requirement density)
gofusa metrics record
gofusa metrics show

# MISRA C:2023 to Go/go-FuSa alignment report
gofusa misra

# Generate everything in one command (SBOM, provenance, fmea, boundary, vuln, cyber, tara, audit-pack)
gofusa release --full
```

## Docker quick start

No local Go or gofusa installation required.

```bash
# Run safety checks against the current directory
docker run --rm -v "$(pwd)":/project ghcr.io/soundmatt/go-fusa:latest check

# Show the requirements traceability matrix
docker run --rm -v "$(pwd)":/project ghcr.io/soundmatt/go-fusa:latest trace

# Run cybersecurity analysis (CWE-mapped rules)
docker run --rm -v "$(pwd)":/project ghcr.io/soundmatt/go-fusa:latest cyber

# Generate all release evidence (SBOM, provenance, TARA, audit pack)
docker run --rm -v "$(pwd)":/project ghcr.io/soundmatt/go-fusa:latest release --full
```

**Full pipeline with docker compose:**

```bash
# Run the complete evidence-generation pipeline in one command
docker compose run --rm pipeline
```

See [docker-compose.yml](docker-compose.yml) for the full pipeline definition.

**GitHub Actions — scan your project using the published image:**

```yaml
jobs:
  safety:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/soundmatt/go-fusa:latest
    steps:
      - uses: actions/checkout@v5
      - run: gofusa check --dir .
      - run: gofusa trace --dir .
      - run: gofusa cyber --dir .
```

Copy the full example from [`.github/gofusa-example.yml`](.github/gofusa-example.yml).

**Build from source:**

```bash
docker build -t go-fusa .
docker run --rm -v "$(pwd)":/project go-fusa check
```

Published tags: `latest`, `0.24`, `0.24.0` (and matching semver for every release).

## Standards coverage

| Standard | Scope |
|---|---|
| ISO 26262 | Automotive functional safety (ASIL A–D) |
| IEC 61508 | General functional safety (SIL 1–4) |
| ISO 21434 | Automotive cybersecurity — CYBER rules, TARA generation, FMEA enrichment |
| IEC 62443 | Industrial/OT cybersecurity — Security Level compliance checks |
| SLSA L2/L3 | Supply-chain security — provenance fields, CODEOWNERS, branch protection |
| DO-178C | Aerospace software (process alignment) |

## Tool qualification

go-FuSa includes a built-in qualification suite that validates every engine rule
against known-good and known-bad synthetic projects, producing a cryptographically
hashed evidence report:

```bash
gofusa qualify
# writes qualify-report.json with SHA-256 integrity hash
```

This report can be submitted as tool confidence evidence in regulated environments.
See [docs/qualification.md](docs/qualification.md) for guidance.

## Target users

System architects, functional safety engineers, requirements engineers, platform/application/
middleware/embedded developers, verification and test automation engineers, integration and
DevOps engineers, cybersecurity engineers, quality engineers, and assessors.

See [ROADMAP.md](ROADMAP.md) for the full feature roadmap.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions require a DCO sign-off.

## License

Mozilla Public License v2.0. See [LICENSE](LICENSE).
