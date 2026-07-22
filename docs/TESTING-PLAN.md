# Testing plan — what each run actually proves

This repo exists to **see the reference harness run**, and to do it in a way
where the results mean something. The central trap is *contamination*: if the
model has seen a target (or its documented findings) during training, a
"discovery" may just be recall. How much that matters depends on whether the
test has an **execution oracle**.

## Two cases, split by oracle

### C / C++ — execution oracle (`targets/mrt`)
The pipeline builds the target under AddressSanitizer and only counts a bug when
an agent produces an input that **actually crashes the binary**, reproduced in a
clean container. Knowing a bug exists ≠ producing a reproducing crash. So even a
rediscovery here proves the machinery works: craft → run → verify.

Contamination matters *less*. The agent gets source only, is network-isolated,
and must mechanically land the crash.

### .NET static — no oracle (`targets/issueblot`)
The scanner just claims "SQL injection at line N." There's nothing to run. If it
read an `exploits/` folder or recalled a documented CVE, you can't tell
discovery from recall.

Contamination matters *a lot*. Two consequences, both handled here:
1. **The source is original and unmarked.** No `exploits/`, no `// VULNERABLE`,
   no CVE — see the target dirs. The answer key lives outside the scanned tree
   in `docs/answer-key/`.
2. **For third-party documented repos**, strip the answer key before scanning:
   `scripts/strip-answer-key.sh <target> <clean-copy>`.

## What each target is for

| Target | Type | Oracle | What a rediscovery proves |
|--------|------|--------|---------------------------|
| Public documented repo (e.g. drlibs) | C | yes | **Smoke test** — the machine runs and produces a verified crash. A null result means "tool broken," not "no bugs." |
| `targets/mrt` | C | yes | Discovery on **unseen** code with a hard oracle — the strongest signal short of your own private code. |
| `targets/issueblot` | .NET | no | Static discovery on **unseen** code — real, but graded by a human against the answer key. |
| Your own private code | any | maybe | **Real capability** — guaranteed uncontaminated, and the thing you actually care about. |

## Recommended sequence

1. **Smoke test first.** Run the harness on a *known-answer* target so a null
   result unambiguously means the setup is broken. `targets/mrt` +
   `scripts/verify-mrt-oracle.sh` gives you that baseline in seconds, before you
   spend tokens on an autonomous run.
2. **Static demo on `issueblot`.** Cheap, reliable in Codespaces, exercises the
   no-oracle path. Grade against the answer key.
3. **Oracle demo on `mrt`.** The real crash loop (sandbox permitting).
4. **Then judge real capability on your own code** — private Bupa repos, or a
   clean codebase with freshly-injected bugs matching no public CVE. The two
   targets here are the template for that: original source, answer key kept
   separate, one bug class per module.

## Why these targets, not the canary

The harness ships `targets/canary`, but its bugs are signposted (`// Bug:` in
the source, obvious `memcpy` of an input length). That's fine for a *smoke test*
and terrible for a *discovery test*. `mrt` and `issueblot` keep the smoke-test
property (a known answer key you control) while removing the giveaways, so a
find reflects reasoning rather than reading a comment.
