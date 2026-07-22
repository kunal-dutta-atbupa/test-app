# DNR run — graded against the answer key

Scored `INCIDENTS.json` against [`logs/../ANSWER-KEY.md`](./ANSWER-KEY.md) (the
ground truth, kept out of the hunt's inputs).

## Corpus (what the hunt was given)

- 252 access-log lines, one attacker (`203.0.113.77`), 248 benign requests from 5 IPs.
- 12 attacker requests: 1 recon, 5 SQLi, 2 path-traversal, 2 deserialization, 2 command-injection.
- Small app-error log + a 2-entry alert queue. No answer key in the inputs.

## Score

| Ground truth | Expected verdict | Hunt result | ✓ |
|---|---|---|---|
| SQL injection (`/issues/search`) | confirmed_exploited | INC-1 confirmed_exploited | ✅ |
| Command injection (`/reports/export`) | confirmed_exploited | INC-2 confirmed_exploited | ✅ |
| Path traversal (`/attachments`) | attempted_not_vulnerable | ruled_out (attempted_not_vulnerable) | ✅ |
| Deserialization (`/backups/restore`) | attempted_not_vulnerable | ruled_out (attempted_not_vulnerable) | ✅ |
| Alert A-1002 (favicon 404) | benign | ruled_out (benign) | ✅ |

**Detection quality**
- **Recall:** 2/2 real compromises caught (SQLi, RCE).
- **Precision:** 0 false positives across 248 benign requests; only `203.0.113.77` flagged.
- **Verdict-ladder discipline:** the 2 attack classes that *bounced* were correctly
  demoted to `attempted_not_vulnerable` (not counted as compromises) — each backed
  by a source defense **and** a negative PoC fired locally.
- **Bonus:** surfaced the detection gap the answer key implies — the alert queue
  fired only on a *failed* attack and missed both *successful* ones.

## Verdict

**Clean run.** The hunt distinguished "attacked" from "compromised" correctly on
all five subjects, pinned the attacker with zero collateral on benign traffic, and
its every number traces to a logged query. This is the defensive mirror of the
offensive result: the same two bugs that were exploited live are the two that show
up as real compromises in the logs — and the two framework-mitigated flaws show up
(correctly) as failed attempts, not incidents.
