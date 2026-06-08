## Summary

<!-- What does this PR do? One paragraph. -->

## Motivation

<!-- Why is this change needed? Reference ROADMAP.md items where relevant. -->

## Safety checklist

- [ ] `go test -race -count=1 ./...` passes locally
- [ ] `go vet ./...` and `golangci-lint run ./...` pass
- [ ] New or changed rules have `//fusa:req` and `//fusa:test` annotations
- [ ] `gofusa trace` shows 0 untraced requirements
- [ ] `gofusa qualify` shows 44/44 passed (or the count matches new cases)
- [ ] If a new rule was added, positive **and** negative qualify cases were added
- [ ] `CHANGELOG.md` updated (add entry under `## [Unreleased]`)
- [ ] All commits are signed off (`Signed-off-by:` trailer present)

## Type of change

- [ ] Bug fix
- [ ] New feature / rule
- [ ] Refactor / cleanup
- [ ] Documentation
- [ ] CI / tooling

## Related issues / roadmap

<!-- Closes #NNN  |  Part of vX.Y scope in ROADMAP.md -->
