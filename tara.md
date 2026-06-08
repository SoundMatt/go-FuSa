# Threat Analysis and Risk Assessment (TARA)

**Module:** github.com/SoundMatt/go-FuSa  
**Generated:** 2026-06-08T20:30:54Z  
**Standard:** ISO 21434 Chapter 9  

| ID | Asset | Threat | STRIDE | CWE | Vector | Likelihood | Impact | SL | Control | Residual Risk |
|---|---|---|---|---|---|---|---|---|---|---|
| TARA-001 | vuln.go | Command injection from variable input enables arbitrary command execution | E/R | CWE-78 | Network | Medium | High | 3 | Use exec.Command with fixed command and sanitised args | Low after remediation |
| TARA-002 | runtime_test.go | Integer narrowing conversion causes silent data truncation | T/D | CWE-190 | Local | Low | Medium | 1 | Add range check before conversion | Low after remediation |
| TARA-003 | runtime_test.go | Integer narrowing conversion causes silent data truncation | T/D | CWE-190 | Local | Low | Medium | 1 | Add range check before conversion | Low after remediation |
| TARA-004 | cmd_auditpack.go | World-readable/writable directory allows unauthorised file access | E/I | CWE-732 | Local | Medium | Medium | 2 | Create directory with mode 0750 or stricter | Low after remediation |
| TARA-005 | cmd_boundary.go | World-readable/writable directory allows unauthorised file access | E/I | CWE-732 | Local | Medium | Medium | 2 | Create directory with mode 0750 or stricter | Low after remediation |
| TARA-006 | cmd_fmea.go | World-readable/writable directory allows unauthorised file access | E/I | CWE-732 | Local | Medium | Medium | 2 | Create directory with mode 0750 or stricter | Low after remediation |
| TARA-007 | cmd_release.go | World-readable/writable directory allows unauthorised file access | E/I | CWE-732 | Local | Medium | Medium | 2 | Create directory with mode 0750 or stricter | Low after remediation |
| TARA-008 | cmd_safetycase.go | World-readable/writable directory allows unauthorised file access | E/I | CWE-732 | Local | Medium | Medium | 2 | Create directory with mode 0750 or stricter | Low after remediation |
| TARA-009 | cmd_vuln.go | World-readable/writable directory allows unauthorised file access | E/I | CWE-732 | Local | Medium | Medium | 2 | Create directory with mode 0750 or stricter | Low after remediation |
| TARA-010 | e2e_test.go | World-readable/writable directory allows unauthorised file access | E/I | CWE-732 | Local | Medium | Medium | 2 | Create directory with mode 0750 or stricter | Low after remediation |
| TARA-011 | qualify.go | World-readable/writable directory allows unauthorised file access | E/I | CWE-732 | Local | Medium | Medium | 2 | Create directory with mode 0750 or stricter | Low after remediation |
| TARA-012 | template.go | World-readable/writable directory allows unauthorised file access | E/I | CWE-732 | Local | Medium | Medium | 2 | Create directory with mode 0750 or stricter | Low after remediation |
| TARA-013 | testutil.go | World-readable/writable directory allows unauthorised file access | E/I | CWE-732 | Local | Medium | Medium | 2 | Create directory with mode 0750 or stricter | Low after remediation |
| TARA-014 | trace_test.go | World-readable/writable directory allows unauthorised file access | E/I | CWE-732 | Local | Medium | Medium | 2 | Create directory with mode 0750 or stricter | Low after remediation |
| TARA-015 | e2e_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-016 | main_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-017 | main_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-018 | config.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-019 | config_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-020 | config_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-021 | fmea_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-022 | iec62443_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-023 | qualify.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-024 | qualify.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-025 | qualify_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-026 | release.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-027 | release_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-028 | release_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-029 | release_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-030 | release_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-031 | release_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-032 | release_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-033 | safetycase_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-034 | template.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-035 | template_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-036 | testutil.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-037 | trace.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-038 | trace_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-039 | trace_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-040 | trace_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-041 | trace_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-042 | trace_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-043 | trace_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-044 | trace_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-045 | trace_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-046 | trace_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-047 | verify.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-048 | verify_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-049 | verify_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-050 | vuln_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-051 | vuln_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-052 | vuln_test.go | World-readable/writable file allows unauthorised data access or tampering | I/T | CWE-732 | Local | Medium | Medium | 2 | Create file with mode 0640 or stricter | Low after remediation |
| TARA-053 | auditpack.go | TOCTOU race allows attacker to substitute file between check and use | E/T | CWE-362 | Local | Medium | Medium | 2 | Open file directly; handle ENOENT/EEXIST atomically | Low after remediation |
