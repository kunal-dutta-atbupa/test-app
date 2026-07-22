# Triage Report — targets/issueblot

7 in → 0 duplicates, 1 false positive, **6 confirmed** (2 high / 4 medium), 2 need manual test.

Context: auto; environment = internet-facing web service; scoring = derived HIGH/MEDIUM/LOW; 1-vote verification. **Live-run reachability evidence was folded into the verdicts** — which is why two scanner-HIGHs are downgraded here.

## Act on these

### [HIGH] OS command injection in report export  (f002)
`src/Export/ReportExporter.cs:13` | command-injection | claimed HIGH (alignment +3) | confidence 9.6/10
**Owner:** component: Export/; no CODEOWNERS; single committer
**Verdict:** exploitable, votes {true_positive: 1}
**Preconditions (1):** send POST /reports/export with a crafted label (no auth)
**Threat-model match:** Unauthenticated remote code execution
**Why:** `label`/`format` concatenated into `/bin/sh -c` (ReportExporter.cs:13), reached unauth from Program.cs:32. Confirmed exploitable live — injected `id` ran and its output returned in the HTTP response; a file was written to /tmp.
**Reachability evidence:** src/Program.cs:32

### [HIGH] SQL injection in issue search  (f001)
`src/Data/IssueRepository.cs:21` | sql-injection | claimed HIGH (alignment +3) | confidence 9.5/10
**Owner:** component: Data/; no CODEOWNERS; single committer
**Verdict:** exploitable, votes {true_positive: 1}
**Preconditions (1):** send GET /issues/search?q= (no auth)
**Threat-model match:** Tenant/data leakage
**Why:** `q` concatenated into CommandText (IssueRepository.cs:20-21), reached unauth from Program.cs:25. Confirmed live: `' OR 1=1--` dumped all rows; UNION extracted sqlite_version().
**Reachability evidence:** src/Program.cs:25

### [MEDIUM] Insecure deserialization (TypeNameHandling.All)  (f003)
`src/Restore/BackupService.cs:10` | deserialization | claimed HIGH (alignment −1) | confidence 8.0/10
**Owner:** component: Restore/; no CODEOWNERS; single committer
**Verdict:** needs_manual_test, votes {true_positive: 1}
**Preconditions (2):** body read async (`AllowSynchronousIO=true`) or a non-HTTP caller; a loadable gadget type
**Threat-model match:** Unauthenticated remote code execution
**Why:** `TypeNameHandling.All` honors attacker `$type` — sink **confirmed** by direct invocation (instantiated `StringBuilder` from the wire, reached for `EvilAssembly`). But over HTTP the endpoint throws first — `reader.ReadToEnd()` is a synchronous body read, blocked by ASP.NET's default `AllowSynchronousIO=false` (every body → 500 before the deserializer). Real sink, gated HTTP path → **downgraded HIGH → MEDIUM**.
> Recommend a human build a PoC on a deployment that reads the body asynchronously; static + this run bounded it, runtime config decides it.
**Reachability evidence:** src/Program.cs:36, src/Restore/BackupService.cs:16

### [MEDIUM] Path traversal in attachment read  (f004)
`src/Files/AttachmentService.cs:12` | path-traversal | claimed HIGH (alignment −1) | confidence 7.5/10
**Owner:** component: Files/; no CODEOWNERS; single committer
**Verdict:** needs_manual_test, votes {true_positive: 1}
**Preconditions (1):** a proxy that decodes `%2f` upstream, or a non-HTTP caller of `Read()`
**Threat-model match:** Tenant/data leakage
**Why:** `Path.Combine(root, name)` + `ReadAllBytes`, no containment (AttachmentService.cs:12-13), reached unauth from Program.cs:28. Sink **confirmed** reachable with raw input, but default Kestrel keeps `%2f` literal for a single-segment route and normalizes `..` before routing, so the documented trigger never lands a real `/`. Real flaw, HTTP trigger neutralized → **downgraded HIGH → MEDIUM**.
> Recommend a human test behind the actual production proxy; some decode `%2f` and re-open this.
**Reachability evidence:** src/Program.cs:28

### [MEDIUM] Weak password hashing (unsalted MD5)  (f005)
`src/Auth/PasswordHasher.cs:13` | weak-crypto | claimed MEDIUM (alignment +2) | confidence 8.5/10
**Owner:** component: Auth/; no CODEOWNERS; single committer
**Verdict:** exploitable, votes {true_positive: 1}
**Preconditions (1):** attacker obtains a stored hash (e.g. via f001)
**Threat-model match:** Credential compromise
**Why:** MD5 with a static pepper and no per-user salt (PasswordHasher.cs:13-14). Confirmed live: server hash for 'hunter2' reproduced offline. Fast + unsalted → cheap brute-force. Kept **distinct** from f006.
**Reachability evidence:** src/Program.cs:40

### [MEDIUM] Hardcoded pepper in source  (f006)
`src/Auth/PasswordHasher.cs:9` | hardcoded-secret | claimed MEDIUM (alignment +2) | confidence 8.5/10
**Owner:** component: Auth/; no CODEOWNERS; single committer
**Verdict:** exploitable, votes {true_positive: 1}
**Preconditions (1):** attacker reads source / decompiles the assembly
**Threat-model match:** Credential compromise
**Why:** `const Pepper = "s3cr3t-pepper-v1"` compiled in (PasswordHasher.cs:9), used in every hash. Known-to-all, unrotatable → adds no entropy (confirmed by reproducing the server hash with the source value). **Distinct** from f005: fixing MD5 doesn't remove the hardcoded secret.
**Reachability evidence:** src/Program.cs:40

## Dropped

| id | title | file:line | why dropped |
|---|---|---|---|
| f007 | No authentication on any endpoint | src/Program.cs:25 | false positive — missing-hardening only (exclusion rule 13), no standalone exploit; auth is explicitly out of scope in the target's THREAT_MODEL. Amplifier for f001–f006, recorded as threat T6 in the threat model rather than a discrete finding. |
