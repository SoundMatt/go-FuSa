# gofusa release

Generate SBOM, build provenance, and sign release artifacts.

## Synopsis

```
gofusa release [flags]
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--dir` | `.` | Project root |
| `--format` | `text` | Output format for summary: `text`, `json` |
| `--output` | — | Write summary to file |
| `--sbom` | `sbom.json` | SBOM output path |
| `--provenance` | `provenance.json` | Provenance output path |
| `--sign` | `false` | Sign artifacts with sigstore/cosign if available |

## What it produces

### SBOM (Software Bill of Materials)

Written to `sbom.json` (SPDX 2.3 format). Includes:

- Module path and version
- All direct and transitive `go.mod` dependencies
- Go toolchain version
- Build timestamp

```json
{
  "spdxVersion": "SPDX-2.3",
  "name": "github.com/example/myapp",
  "packages": [...]
}
```

### Build provenance

Written to `provenance.json` (SLSA Provenance v0.2-compatible). Includes:

- Module path
- Go version
- VCS commit hash and branch (from `debug.ReadBuildInfo`)
- Build timestamp

```json
{
  "module": "github.com/example/myapp",
  "goVersion": "go1.22.3",
  "vcsRevision": "abc1234",
  "vcsBranch": "main",
  "built": "2026-06-09T10:00:00Z"
}
```

### Artifact signing (optional)

When `--sign` is set and `cosign` is available in `PATH`, each artifact is
signed using sigstore keyless signing. The `.sig` and `.cert` files are written
alongside the artifact.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | SBOM and provenance generated successfully |
| `1` | Generation failed |

## Examples

```sh
# Generate SBOM and provenance for current project
gofusa release

# Custom output paths
gofusa release --sbom build/sbom.json --provenance build/provenance.json

# Generate and sign
gofusa release --sign

# JSON summary
gofusa release --format json --output release-summary.json
```

## CI integration

Add to your release workflow after building binaries:

```yaml
- name: Generate SBOM and provenance
  run: gofusa release --sbom sbom.json --provenance provenance.json

- name: Upload evidence
  uses: actions/upload-artifact@v6
  with:
    name: release-evidence
    path: |
      sbom.json
      provenance.json
```

## Standards traceability

| Artifact | Standard | Clause |
|----------|----------|--------|
| SBOM | IEC 62443-4-1 | SD-4 (software bill of materials) |
| Provenance | ISO 21434 | §11 (product development) |
| Signed artifacts | SLSA | Level 2 provenance |

## See also

- `gofusa check` — run safety rules before release
- `gofusa verify` — collect test evidence
- `gofusa qualify` — full qualification bundle
