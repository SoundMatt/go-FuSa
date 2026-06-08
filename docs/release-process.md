# Release Process

This document describes how go-FuSa versions are released. It is part of the
tool's own change management evidence for ISO 26262-8 / IEC 61508-6 qualification.

## Prerequisites

Before tagging a release, verify on `main`:

1. All CI jobs pass — `test`, `qualify`, `lint`, `docker`, `dco`
2. `gofusa qualify` shows 44/44 (or the current count) passed
3. `gofusa trace` shows 0 untraced requirements
4. `CHANGELOG.md` has an entry for the new version under `## [Unreleased]`
5. The `Version` constant in `fusa.go` has been bumped to the new version

## Steps

### 1. Pull latest main

```
git checkout main && git pull origin main
```

### 2. Bump version and changelog

Edit `fusa.go` — update the `Version` constant.

Edit `CHANGELOG.md` — rename `## [Unreleased]` to `## [x.y.z] — YYYY-MM-DD`
and add a new empty `## [Unreleased]` section above it.

### 3. Regenerate evidence

```
gofusa verify
gofusa release
gofusa qualify
```

Commit all updated evidence files:

```
git add fusa.go CHANGELOG.md .fusa-evidence.json sbom.json provenance.json qualify-report.json
git commit -s -m "chore(release): prepare vx.y.z"
git push origin main
```

Wait for CI to go green.

### 4. Tag and push

```
git tag -a vx.y.z -m "Release vx.y.z"
git push origin vx.y.z
```

### 5. GitHub release

Create a GitHub release from the tag. Set the title to `vx.y.z` and paste the
`CHANGELOG.md` entry as the body.

Attach the following files as release assets (the tool qualification evidence
package):

| File | Description |
|---|---|
| `qualify-report.json` | Qualification suite results (44 cases) |
| `.fusa-evidence.json` | Test evidence bundle |
| `sbom.json` | Software bill of materials |
| `provenance.json` | Build provenance record |

### 6. Post-release smoke test

```
go install github.com/SoundMatt/go-FuSa/cmd/gofusa@vx.y.z
gofusa version
gofusa qualify
```

## Versioning policy

go-FuSa follows [Semantic Versioning](https://semver.org/):

| Change type | Version bump |
|---|---|
| Bug fixes, documentation, test additions | Patch (0.x.Z) |
| New rules, new commands, backward-compatible API changes | Minor (0.X.0) |
| Breaking changes to `.fusa.json` schema, CLI, or Go public API | Major (X.0.0) |

Pre-1.0: minor bumps may include breaking changes; these are called out
explicitly in `CHANGELOG.md`.

## Release authority

Releases are authorised by the repository owner (Matt Jones). No automated
release tagging is configured — every release requires a manual `git tag`.
This ensures a qualified engineer has reviewed all evidence before any version
is declared released.

## Evidence retention

The four evidence files attached to each GitHub release constitute the
**tool qualification evidence package** for that version. Auditors qualifying
go-FuSa for use in a regulated project should:

1. Download the evidence package for the specific version in use
2. Record the `gofusa` binary SHA-256 hash in the project safety plan
3. Re-run `gofusa qualify` in their own CI to confirm reproducibility
