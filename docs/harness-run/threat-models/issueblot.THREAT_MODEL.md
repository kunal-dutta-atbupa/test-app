# Threat Model: IssueBlot issue-tracker API (`targets/issueblot`)

## 1. System context

IssueBlot is a minimal ASP.NET Core (net8.0) issue-tracker web API — six source
files, five HTTP endpoints wired in `Program.cs`, each delegating to a single
service (search, attachment download, report export, backup restore, user
registration). It is an **internet-facing web service**: every endpoint takes
attacker-controlled input over unauthenticated HTTP. Persistence is a local
SQLite database; report export shells out to an external document converter;
backup restore deserializes an uploaded document. There is no authentication,
authorization, or transport security in the code (the design declares those out
of scope).

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| issue database contents | titles and metadata in the SQLite store, some confidential | high |
| stored password material | the output of the registration hashing routine | critical |
| host process & shell | ability to run commands as the service account | critical |
| server filesystem | arbitrary file read outside the attachment storage root | high |
| service availability | the API staying up under hostile input | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| `GET /issues/search?q=` | free-text query concatenated into a SQL command | unauth HTTP → database query | issue database contents |
| `GET /attachments/{name}` | route segment joined onto a storage root and read from disk | unauth HTTP → filesystem | server filesystem |
| `POST /reports/export` | JSON `format`/`label` concatenated into a `/bin/sh -c` command | unauth HTTP → process execution | host process & shell |
| `POST /backups/restore` | raw body deserialized with polymorphic type handling | unauth HTTP → object graph / type instantiation | host process & shell |
| `POST /users/register` | password hashed for storage | unauth HTTP → credential storage | stored password material |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Unauthenticated remote code execution via OS command injection in report export | remote_unauth | `POST /reports/export` | host process & shell | critical | almost_certain | unmitigated | none | F-002 (confirmed exploited live: `id` output returned, file written) |
| T2 | Unauthenticated RCE via insecure deserialization (`TypeNameHandling.All`) of the backup body | remote_unauth | `POST /backups/restore` | host process & shell | critical | possible | partially_mitigated | ASP.NET `AllowSynchronousIO=false` throws before the deserializer on the HTTP path | F-003 (sink confirmed: arbitrary `$type` instantiated via direct invocation) |
| T3 | Data exfiltration / tampering via SQL injection in issue search | remote_unauth | `GET /issues/search` | issue database contents | high | almost_certain | unmitigated | none | F-001 (confirmed exploited live: `' OR 1=1--` and UNION) |
| T4 | Arbitrary server-file read via path traversal / absolute-path override in attachment download | remote_unauth | `GET /attachments/{name}` | server filesystem | high | possible | partially_mitigated | default Kestrel keeps `%2f` literal for a single-segment route and normalizes `..` before routing | F-006 (sink confirmed reachable with raw input; documented HTTP trigger did not decode) |
| T5 | Credential compromise via weak password storage (unsalted MD5 + hardcoded pepper) | remote_unauth | `POST /users/register` + any hash-leak path | stored password material | high | likely | unmitigated | none | F-004 hardcoded pepper; F-005 MD5 (confirmed: server hash reproduced offline) |
| T6 | Any attacker reaches every sink because no endpoint is authenticated or authorized | remote_unauth | all five entry points | all assets | high | almost_certain | unmitigated | none | (gap-fill — STRIDE elevation/spoofing; no evidence, amplifies T1–T5) |

## 5. Deprioritized

| threat | reason |
|---|---|
| Transport confidentiality (no TLS) | declared out of scope by design; typically terminated at a proxy |
| Volumetric DoS / rate-limiting | infrastructure-layer control, not a code defect |
| CSRF | no cookie/session auth to abuse |
| Repudiation / audit gaps | no multi-user identity model in scope |

## 6. Open questions

- **Auth upstream:** is there an authentication gateway, API key, or WAF in front
  of these endpoints in the real deployment? T6 (and the likelihood of T1–T5)
  depends entirely on this.
- **Deserialization reachability:** does any deployment set `AllowSynchronousIO =
  true`, or is `BackupService.Restore` called from a non-HTTP path (a queue
  worker, a CLI)? Either flips T2 from `partially_mitigated` to live.
- **Proxy path decoding:** is IssueBlot fronted by a reverse proxy (nginx, some
  API gateways) that decodes `%2f` before forwarding? That re-opens T4.
- **Storage locations:** where do `issues.db` and the attachment root actually
  live, and what else is readable from the service account?

## 7. Provenance

- mode: bootstrap
- date: 2026-07-22
- target: targets/issueblot @ 1f51e7a
- inputs: git-log mined (no prior vuln-fix commits found); source read; live-run reachability evidence folded into likelihood/status
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Execute the converter via an argv array (no `/bin/sh`) and allowlist `format`; never concatenate input into a shell string | T1 | yes | S |
| Set `TypeNameHandling = None` and deserialize into a fixed DTO (or move to System.Text.Json) | T2 | yes | S |
| Parameterize every SQL query; never concatenate input into `CommandText` | T3 | yes | S |
| Canonicalize the combined path (`Path.GetFullPath`) and verify it stays under the storage root; reject separators/`..` | T4 | yes | S |
| Hash passwords with Argon2id (per-user random salt, work factor); load any pepper from a secret store, never source | T5 | yes | M |
| Add an authentication + authorization gate in front of all endpoints | T6 | yes | M |
