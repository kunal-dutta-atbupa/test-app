# harness-testing

A self-contained harness for seeing Anthropic's
[defending-code-reference-harness](https://github.com/anthropics/defending-code-reference-harness)
run in **GitHub Codespaces**, against two purpose-built, **uncontaminated**
targets — one per evaluation mode:

| Target | Language | Mode | Oracle |
|--------|----------|------|--------|
| [`targets/mrt`](targets/mrt) | C | autonomous crash-finding | **yes** — AddressSanitizer actually crashes |
| [`targets/issueblot`](targets/issueblot) | .NET / C# | static `/vuln-scan` | none — findings graded by a human |

Both targets are original code that matches no public CVE and carries **no
in-source markers** describing where it is unsafe. The bug inventories (answer
keys) are kept **outside** the scanned trees in
[`docs/answer-key/`](docs/answer-key), so a scan can't recall an answer instead
of discovering it.

## Start here

1. **[`docs/CODESPACES.md`](docs/CODESPACES.md)** — step-by-step: open the
   Codespace, authenticate with your Claude subscription (no API key), and run
   both demos.
2. **[`docs/TESTING-PLAN.md`](docs/TESTING-PLAN.md)** — what each run actually
   proves, and why contamination is handled differently for the C oracle vs the
   .NET static case.

## Quick reference

```bash
# In the Codespace (devcontainer installs everything):
claude setup-token && export CLAUDE_CODE_OAUTH_TOKEN=<token>   # subscription, no API key
bash scripts/setup.sh                                          # clone + wire up the harness

# Demo A — .NET static scan (reliable, no Docker):
#   cd ../defending-code-reference-harness && claude
#   > /vuln-scan targets/issueblot
#   > /triage targets/issueblot/VULN-FINDINGS.json

# Demo B — C execution oracle (needs Docker + gVisor sandbox):
bash scripts/verify-mrt-oracle.sh    # confirm the target's oracle is sound first
bash scripts/run-c-oracle.sh         # autonomous crash-finding run
```

## Layout

```
.devcontainer/            Codespaces image: gcc, .NET 8, Node, Python, Docker-in-Docker, Claude CLI
docs/
  CODESPACES.md           how to run both demos
  TESTING-PLAN.md         contamination strategy; what each result means
  answer-key/             ground-truth bug inventories (kept out of the scanned trees)
scripts/
  setup.sh                clone the harness, install it, copy targets in
  verify-mrt-oracle.sh    build mrt with ASAN and confirm valid/crash behavior
  make-mrt-inputs.py      regenerate the C target's valid + crashing inputs
  run-c-oracle.sh         autonomous crash-finding run on mrt
  strip-answer-key.sh     make a scan-only copy of a THIRD-PARTY documented repo
targets/
  mrt/                    C execution-oracle target (4 planted memory bugs)
  issueblot/              .NET static target (5 planted web/crypto findings)
```

## What this is not

This tests **the harness**, using known-answer targets so a null result means
"setup broken," not "code clean." Once you trust the machinery, judge real
discovery capability on code the model has never seen — your own private repos.
That reasoning is in [`docs/TESTING-PLAN.md`](docs/TESTING-PLAN.md).
