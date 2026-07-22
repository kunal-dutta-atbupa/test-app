#!/usr/bin/env bash
# Autonomous execution-oracle run on the C target (mrt) via the harness.
# This is the STRETCH path: it executes target code and therefore needs the
# harness's Docker + gVisor sandbox, which may not be available in a stock
# Codespace. Run scripts/verify-mrt-oracle.sh first to confirm the target
# itself is sound.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS_DIR="${HARNESS_DIR:-$(dirname "$REPO_ROOT")/defending-code-reference-harness}"
MODEL="${VULN_PIPELINE_MODEL:-claude-sonnet-5}"

if [ ! -d "$HARNESS_DIR" ]; then
    echo "harness not found at $HARNESS_DIR — run scripts/setup.sh first"; exit 1
fi
cd "$HARNESS_DIR"

echo "== one-time sandbox setup (Docker + gVisor) =="
scripts/setup_sandbox.sh

echo
echo "== recon (read-only) =="
bin/vp-sandboxed recon mrt

echo
echo "== calibration run: 4 parallel finds, capped turns =="
bin/vp-sandboxed run mrt \
    --model "$MODEL" \
    --auto-focus --runs 4 --parallel --stream --max-turns 100

echo
RESULTS="$(ls -td results/mrt/*/ 2>/dev/null | head -1 || true)"
echo "results: ${RESULTS:-<none>}"
[ -n "${RESULTS:-}" ] && cat "$RESULTS/found_bugs.jsonl" 2>/dev/null || true
echo
echo "Grade against: $REPO_ROOT/docs/answer-key/mrt-bugs.md"
