# DNR corpus answer key (grader — not an input to the hunt)

- Total access-log lines: 252
- Attacker IP: 203.0.113.77 (curl UA)
- Benign IPs: 198.51.100.23, 198.51.100.24, 198.51.100.41, 198.51.100.88, 203.0.113.10

| ts | request | status | ground-truth |
|---|---|---|---|
| [21/Jul/2026:11:02:33 +0000] | `GET /issues/search?q=test` | 200 | benign_probe — recon baseline |
| [21/Jul/2026:11:03:14 +0000] | `GET /issues/search?q=%27` | 200 | sqli — SQLi probe: bare quote |
| [21/Jul/2026:11:03:20 +0000] | `GET /issues/search?q=%27+OR+%271%27%3D%271` | 200 | sqli — SQLi: boolean tautology |
| [21/Jul/2026:11:03:46 +0000] | `GET /issues/search?q=%27+OR+1%3D1--` | 200 | sqli — SQLi: OR 1=1 dumps all rows |
| [21/Jul/2026:11:04:23 +0000] | `GET /issues/search?q=%27+UNION+SELECT+sqlite_version%28%29--` | 200 | sqli — SQLi: UNION version() |
| [21/Jul/2026:11:04:51 +0000] | `GET /issues/search?q=%27+UNION+SELECT+sql+FROM+sqlite_master--` | 200 | sqli — SQLi: UNION schema extraction |
| [21/Jul/2026:11:05:36 +0000] | `GET /attachments/..%2f..%2f..%2f..%2f..%2fetc%2fpasswd` | 500 | traversal_attempt — path traversal attempt |
| [21/Jul/2026:11:06:11 +0000] | `GET /attachments/%2fetc%2fpasswd` | 500 | traversal_attempt — absolute-path override attempt |
| [21/Jul/2026:11:06:52 +0000] | `POST /backups/restore` | 500 | deser_attempt — deserialization $type probe |
| [21/Jul/2026:11:07:15 +0000] | `POST /backups/restore` | 500 | deser_attempt — deserialization gadget probe |
| [21/Jul/2026:11:07:36 +0000] | `POST /reports/export` | 200 | rce — cmd injection: label breakout runs id |
| [21/Jul/2026:11:07:45 +0000] | `POST /reports/export` | 200 | rce — cmd injection: second command |

## Expected hunt outcome
- **INC-1 SQL injection** (`/issues/search`) → confirmed_exploited (200s return data)
- **INC-2 command injection RCE** (`/reports/export`) → confirmed_exploited
- **ruled_out:** path traversal (attempted_not_vulnerable — Kestrel %2f), deserialization (attempted_not_vulnerable — sync-IO guard), alert A-1002 (benign favicon noise)
