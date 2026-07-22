# Incident Report — IssueBlot log hunt

**Executive summary.** A single automated client (`203.0.113.77`, `curl/8.5.0`)
ran a ~5-minute campaign against IssueBlot on 2026-07-21: it **succeeded** at SQL
injection (full issue-table read, incl. a CONFIDENTIAL row) and OS command
injection (**remote code execution** as the service account), and **failed** at
path traversal and insecure deserialization. The only alert that fired was on one
of the *failed* attacks; the two successful compromises tripped nothing.

## How it was found

The attacker was **not** the loudest client — at 12 requests it was the *lowest*
volume of any source IP. It surfaced on two baseline signals: it was the only
**automation user-agent** (`curl/8.5.0`, 12/252 requests) and the only source of
**5xx errors** (4/4). Pivoting on that IP reconstructed the whole campaign.

## Unified timeline (203.0.113.77, all `curl/8.5.0`)

| time | request | status | size | read as |
|---|---|---|---|---|
| 11:02:33 | `GET /issues/search?q=test` | 200 | 120 | recon |
| 11:03:14 | `q='` | 200 | 90 | SQLi probe (bare quote) |
| 11:03:20 | `q=' OR '1'='1` | 200 | 410 | SQLi boolean tautology |
| 11:03:46 | `q=' OR 1=1--` | 200 | 412 | **SQLi: dump all rows** |
| 11:04:23 | `q=' UNION SELECT sqlite_version()--` | 200 | 300 | SQLi: DB fingerprint |
| 11:04:51 | `q=' UNION SELECT sql FROM sqlite_master--` | 200 | 900 | **SQLi: schema extraction** |
| 11:05:36 | `GET /attachments/..%2f..%2f..%2fetc%2fpasswd` | 500 | 0 | traversal attempt (failed) |
| 11:06:11 | `GET /attachments/%2fetc%2fpasswd` | 500 | 0 | abs-path attempt (failed) |
| 11:06:52 | `POST /backups/restore` | 500 | 0 | deser probe (failed) |
| 11:07:15 | `POST /backups/restore` | 500 | 0 | deser probe (failed) |
| 11:07:36 | `POST /reports/export` | 200 | 260 | **cmd injection: RCE** |
| 11:07:45 | `POST /reports/export` | 200 | 180 | **cmd injection: 2nd command** |

## INC-1 — SQL injection (confirmed_exploited)

- **Evidence (logs):** 5 injection-grammar requests from `203.0.113.77`, all HTTP
  200 with response sizes climbing 90 → 412 → 900 — data returned, not error pages.
- **Source:** `src/Data/IssueRepository.cs:21` concatenates `q` straight into the
  `LIKE` clause of `CommandText`. No parameterization.
- **PoC (fired locally this session):**
  `curl -s '.../issues/search' --data-urlencode "q=' OR 1=1--" -G`
  → `["Login page typo","Dark mode request","CONFIDENTIAL: prod DB credentials rotation","Checkout button misaligned"]`
- **Impact:** full read of the issues table (4 rows, 1 CONFIDENTIAL) + DB version
  + schema.

## INC-2 — OS command injection / RCE (confirmed_exploited)

- **Evidence (logs):** two `POST /reports/export` → 200 at 11:07, immediately after
  the failed probes.
- **Source:** `src/Export/ReportExporter.cs:13` concatenates `label` into a
  `/bin/sh -c` string.
- **PoC (fired locally this session):** injected `label` ran `id` →
  `uid=1000(vscode) ... DNR_POC_codespaces-aa33f9` returned in the HTTP body.
- **Impact:** arbitrary command execution as the service account — full read of the
  DB, attachments, and any file that user can reach.

## Ruled out

| subject | verdict | why |
|---|---|---|
| Traversal on `/attachments` (2× 500) | attempted_not_vulnerable | Kestrel keeps `%2f` literal; handler throws `FileNotFoundException` (error log). Negative PoC bounced (HTTP 500). Latent code flaw, not HTTP-reachable. |
| Deser probes on `/backups/restore` (2× 500) | attempted_not_vulnerable | `AllowSynchronousIO=false` throws before the deserializer (error log). Negative PoC bounced (HTTP 500). |
| Alert A-1002 `http.404_rate` (favicon) | benign | Browser noise, normal UA/volume. |
| Alert A-1001 `waf.path_traversal` | benign (but see detection gap) | Real attacker, but flagged the attack that *failed*; silent on the two that succeeded. |

## Detection gap (feeds the response plan)

The alert queue fired **once**, on the traversal that **bounced**, and stayed
**silent** on the SQL injection and the RCE that **succeeded**. Detections keyed
to 200-status data-egress on `/issues/search` and to command output on
`/reports/export` would have caught the real compromises.

---

## Appendix — hypothesis ledger (audit trail)

| # | Hypothesis | Query | Result | Verdict | Next pivot |
|---|---|---|---|---|---|
| 1 | A high-volume IP is attacking | requests per IP | top talker 198.51.100.24 (62); 203.0.113.77 lowest (12) | refuted | volume ≠ intent; check UA |
| 2 | An automation client stands out | UA inventory | only `curl/8.5.0` (12 req), all from 203.0.113.77 | supported | pull that IP's full activity |
| 3 | The 5xx errors share a source | who causes 500 | all 4 from 203.0.113.77 | supported | correlate with error log |
| 4 | Query strings carry SQLi grammar | grep %27/UNION/-- | 5 hits, all 203.0.113.77, all 200 | supported | confirm sink in source + PoC |
| 5 | The 500s are successful attacks | error-log + negative PoC | traversal & deser throw before any sink; PoCs bounce | refuted | route to ruled_out |
| 6 | `/reports/export` 200s are benign | source read + PoC | shell concatenation; PoC returns `id` output | refuted (it's RCE) | INC-2 |
| — | stop | two rounds, no new entities | — | stop | write outputs |
