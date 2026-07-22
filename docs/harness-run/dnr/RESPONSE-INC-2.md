# Incident Response — INC-2 (OS command injection / RCE)

> Lead: `INC-2` from the hunt. Working question: *did 203.0.113.77's activity
> against /reports/export succeed, how far did it go, and what do we do?*
> **All actions below are PROPOSED. Nothing here has been executed.**

## 1. Verdict & summary

`203.0.113.77` achieved **remote code execution** on IssueBlot via
`POST /reports/export` at 11:07:36–11:07:45 on 2026-07-21. It **succeeded**
(command output returned in a 200 response; reproduced by local PoC). Blast
radius is **everything the service account can reach** — the SQLite DB, the
attachment store, and any file readable by uid=1000 — because code execution
supersedes the app's own access model.

## 2. Timeline (this entity)

The RCE was the tail of a single campaign: recon → SQL injection (INC-1,
succeeded) → path traversal (failed) → deserialization probes (failed) → command
injection (this incident). Full table in `INCIDENT_REPORT.md`. Last attacker
action: 11:07:45; no `203.0.113.77` activity after that in the corpus window
(ends 13:09) — **not currently ongoing** in this data.

## 3. Blast radius (quantified)

- **Requests in the campaign:** 12 (query: `grep 203.0.113.77 access.log | wc -l`).
- **Successful RCE requests:** 2 (`POST /reports/export` → 200).
- **Execution context:** `uid=1000(vscode)`, groups incl. `docker` (from the PoC
  `id` output — the `docker` group is itself a privilege-escalation path worth
  flagging).
- **Reachable via RCE:** the issues DB (already separately exfiltrated in INC-1),
  the attachment root `/var/issueblot/attachments`, and any uid=1000-readable file.
- **What the corpus cannot show:** whether the two commands did more than `id`
  (request bodies aren't in access logs) — see open questions.

## 4. Containment (proposed)

| action | why (evidence) | risk if wrong |
|---|---|---|
| Block/deny `203.0.113.77` at the edge | sole attacker IP across 12 malicious requests | Low — TEST-NET IP, not a shared NAT for real users; verify it isn't a proxy first |
| Take `/reports/export` offline (feature-flag) until patched | it is a live unauthenticated RCE | Export feature unavailable to legitimate users until fix ships |
| Rotate any secret reachable by uid=1000 (DB creds, tokens on that host) | RCE = attacker had the service account's read access | Rotation churn; but assume-breach on confirmed RCE |

## 5. Eradication & remediation (proposed)

- **Root cause:** `src/Export/ReportExporter.cs:13` builds a `/bin/sh -c` string by
  concatenating the untrusted `label` (and `format`).
- **Fix (hand off to `/triage` → `/patch`):** invoke the converter with an **argv
  array** and no shell (`ProcessStartInfo` with `ArgumentList`), and **allowlist**
  `format`; treat `label` as data, never as shell. This closes the class, not just
  the reported input.
- **Interim mitigation if the fix will take time:** disable the endpoint (see
  containment) rather than attempting to sanitize shell metacharacters.
- **Sibling check:** no other endpoint shells out; INC-1 (SQLi) is the other
  live-exploited flaw and gets its own remediation (parameterize the query).

## 6. Recovery (proposed)

- **Credentials to rotate:** those reachable by uid=1000 on the IssueBlot host —
  the DB connection secret and any deploy/token file in the service's environment.
  Scope to *that host/account*, not "all users."
- **Notify:** whoever owns the data in the issues table (INC-1 exfiltrated it,
  including the CONFIDENTIAL prod-DB-credentials-rotation item — treat those creds
  as compromised and rotate).
- **Confirm eviction:** monitor for any new `203.0.113.77` activity and for any
  `POST /reports/export` returning shell-shaped output after the patch.

## 7. Detection engineering (proposed)

Derived from the queries that actually found this — turn them into alerts:

1. **Command-output on export:** alert when `POST /reports/export` returns a body
   matching `uid=\d+\(` / shell output shape. Would have caught INC-2 directly.
2. **SQLi egress:** alert on `GET /issues/search` 200s whose response size is an
   outlier for that route (INC-1 climbed to 900B vs. a benign median near 150B).
3. **Automation-UA on state-changing routes:** `curl`/`python-requests` POSTing to
   `/reports/export` or `/backups/restore`.
4. **Fix the queue:** A-1001 fired on a **failed** attack; A-1002 was noise. The
   two **successful** compromises fired nothing. Re-tune away from raw
   `waf.path_traversal` 500s toward success-shaped signals above.

## 8. Open questions (this corpus can't answer)

- What exact commands ran in the two RCE requests? (Need request bodies / app
  logs, not access logs.)
- Did the attacker use the `docker` group membership to escalate off the host?
- Any earlier `203.0.113.77` history before the corpus window (08:00)?
