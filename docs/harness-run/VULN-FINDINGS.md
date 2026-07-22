# IssueBlot — static vulnerability findings

Produced by the `/vuln-scan` skill (single-pass; 6 source files). These are
**static candidates**; live verification is in the pentest report.

| id | sev | conf | category | file:line | title |
|----|-----|------|----------|-----------|-------|
| F-001 | HIGH | 0.97 | sql-injection | Data/IssueRepository.cs:21 | SQL injection via concatenated LIKE clause |
| F-002 | HIGH | 0.96 | command-injection | Export/ReportExporter.cs:13 | OS command injection via label in /bin/sh -c |
| F-003 | HIGH | 0.93 | deserialization | Restore/BackupService.cs:10 | Newtonsoft TypeNameHandling.All on untrusted body |
| F-004 | MED  | 0.90 | hardcoded-secret | Auth/PasswordHasher.cs:9 | Hardcoded pepper in source |
| F-005 | MED  | 0.88 | weak-crypto | Auth/PasswordHasher.cs:13 | Unsalted fast MD5 for password storage |
| F-006 | HIGH | 0.85 | path-traversal | Files/AttachmentService.cs:12 | Path traversal / absolute-path override |
| F-007 | MED  | 0.50 | missing-authentication | Program.cs:25 | No auth on any endpoint |

See `VULN-FINDINGS.json` for full descriptions, exploit scenarios, and fixes.

Next: `/triage targets/issueblot/VULN-FINDINGS.json --repo targets/issueblot`
