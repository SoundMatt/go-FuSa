# Threat Analysis and Risk Assessment (TARA)

**Module:** github.com/SoundMatt/go-FuSa  
**Generated:** 2026-07-29T03:16:05Z  
**Standard:** ISO/SAE 21434:2021 Clause 15  
**Coverage:** 3 / 108 assets (2.8%)

| ID | Asset | Threat | STRIDE | CWE | Vector | Feasibility | Impact (S/F/O/P) | Risk | Treatment | SL | Mitigation |
|---|---|---|---|---|---|---|---|---|---|---|---|
| TARA-001 | summary.go | Integer narrowing conversion causes silent data truncation | T/D | CWE-190 | Local | low | moderate/negligible/moderate/negligible | low | mitigate | 1 | Add range check before conversion |
| TARA-002 | cmd_hooks.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | medium | moderate/negligible/negligible/moderate | medium | mitigate | 2 | Create file with mode 0640 or stricter |
| TARA-003 | cmd_coverage.go | TOCTOU race allows attacker to substitute file between check and use | E/T | CWE-362 | Local | medium | moderate/negligible/negligible/negligible | medium | mitigate | 2 | Open file directly; handle ENOENT/EEXIST atomically |
