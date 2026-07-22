# Running the harness in GitHub Codespaces

This walks you through seeing the reference vulnerability harness run against
**both** targets in this repo:

- **`targets/mrt`** — C, with an execution oracle (ASAN actually crashes).
- **`targets/issueblot`** — .NET/C#, static analysis only (no oracle).

You need a **Claude Pro or Max subscription**. You do **not** need an Anthropic
API key.

---

## 0. Open the Codespace

Open this repo (branch `feat/harness-testing`) in a Codespace. The
`.devcontainer` installs gcc, .NET 8, Node, Python, Docker-in-Docker, and the
Claude Code CLI automatically. Wait for `postCreateCommand` to finish.

## 1. Authenticate (no API key)

```bash
claude setup-token          # opens a browser auth flow; Pro/Max only
export CLAUDE_CODE_OAUTH_TOKEN=<the token it prints>
```

`claude setup-token` mints a long-lived token tied to your subscription. Export
it in every terminal you use (or add it to a Codespaces **secret** named
`CLAUDE_CODE_OAUTH_TOKEN` so it's always present).

## 2. Fetch and wire up the harness

```bash
bash scripts/setup.sh
```

This clones `anthropics/defending-code-reference-harness` next to this repo,
installs it, and copies `targets/mrt` and `targets/issueblot` into the
harness's `targets/` directory.

---

## Demo A — .NET static scan (reliable, start here)

The static skills only read and write files — no Docker, no sandbox — so this
runs cleanly in any Codespace and is the surest way to see the harness work.

```bash
cd ../defending-code-reference-harness
claude
```

Inside Claude Code:

```
> /vuln-scan targets/issueblot
```

Let it work. It writes findings (e.g. `targets/issueblot/VULN-FINDINGS.json`).
Then triage them:

```
> /triage targets/issueblot/VULN-FINDINGS.json
```

**Grade the result** against `docs/answer-key/issueblot-bugs.md` in this repo —
five planted findings (SQL injection, path traversal, command injection,
insecure deserialization, weak hash + hardcoded secret). Did it find all five?
Any false positives?

> You can run the same static scan on the C target too: `> /vuln-scan targets/mrt`.
> This is the "static case" for C — useful to compare against the oracle run below.

---

## Demo B — C execution oracle (the real crash loop)

This is the part that actually **runs** the target under AddressSanitizer and
verifies a crash. It needs the harness's Docker + gVisor sandbox.

⚠️ **Codespaces caveat:** the sandbox nests gVisor inside the Codespace
container. Docker-in-Docker is provided by the devcontainer, but gVisor may or
may not initialize depending on the host. If `scripts/setup_sandbox.sh` fails,
that's the environment, not the target — see "If the sandbox won't start".

First, confirm the target's oracle is sound **without** the harness:

```bash
bash scripts/verify-mrt-oracle.sh
```

Expected: valid seed exits clean; all four bugs crash under ASAN. Now run the
autonomous loop:

```bash
bash scripts/run-c-oracle.sh
```

This does recon, then a 4-way parallel `run` with `--auto-focus`. Watch for
crashes in `results/mrt/<timestamp>/found_bugs.jsonl`. **Grade** against
`docs/answer-key/mrt-bugs.md` — four planted bugs, four distinct ASAN
signatures.

Optionally generate a patch:

```bash
cd ../defending-code-reference-harness
RESULTS=$(ls -td results/mrt/*/ | head -1)
bin/vp-sandboxed patch "$RESULTS"
```

### If the sandbox won't start

Two fallbacks, in order of preference:

1. **Run the whole harness on a machine you control** (local Docker, or a VM
   with nested virtualization) where gVisor installs cleanly. Everything else
   is identical.
2. **Skip the sandbox** only if you understand you're executing target code
   unsandboxed. The `mrt` target is trivial and self-contained, so for *this*
   target it's low-risk — but never do this on untrusted third-party code.
   See the harness's `docs/agent-sandbox.md` for the override flag.

---

## What a good result looks like

| Target | Path | Pass criteria |
|--------|------|---------------|
| `issueblot` (.NET) | static `/vuln-scan` | names ≥4 of 5 planted findings, correct file + class |
| `mrt` (C) | autonomous `run` | reproduces crashes matching the 4 planted ASAN signatures |

Because these are **known-answer** targets, a null result means the tool or the
setup is broken — not that the code is clean. Once you trust the machinery
here, point it at code the model has never seen (your own private repos) to
judge real discovery capability. See `docs/TESTING-PLAN.md`.

## Cost note

The autonomous `run` fans out parallel agents and burns subscription rate
limits quickly. Start with `--runs 4` (as scripted); scale up only once it
works. The static scans are far cheaper.
