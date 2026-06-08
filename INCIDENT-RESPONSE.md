# Incident Response Plan

go-FuSa is a development-tool library. This document describes how security
incidents and safety-critical defects are handled per IEC 62443-4-2 CR 6.2.1.

## Scope

Any confirmed vulnerability or defect in go-FuSa that could affect the safety
evidence produced by a project using the toolkit (false-clean reports, silent
data corruption, tampered audit packs).

## Reporting

Report security issues via the GitHub private-vulnerability-reporting feature or
by emailing matt@jellybaby.com with subject `[go-FuSa][SECURITY]`.

## Response SLAs

| Severity | Initial acknowledgement | Fix / workaround |
|---|---|---|
| Critical | 24 hours | 72 hours |
| High | 48 hours | 7 days |
| Medium/Low | 5 business days | 30 days |

## Handling Steps

1. Triage and confirm the report.
2. Open a private security advisory on GitHub.
3. Develop and test a fix on a private branch.
4. Issue a patch release and publish a CVE advisory.
5. Update `CHANGELOG.md` and notify downstream users via the GitHub release.

## Post-Incident Review

A brief post-incident review is written for Critical/High events and stored in
`docs/security-reviews/`.
