#!/usr/bin/env bash
# One-shot setup for running the reference harness against this repo's targets.
#
# Clones the reference harness next to this repo, installs it, and copies our
# two injected-bug targets (mrt, issueblot) into the harness's targets/ dir so
# they can be addressed by name (e.g. `/vuln-scan targets/mrt`).
#
# Safe to re-run. Does NOT set up the Docker/gVisor sandbox — that is only
# needed for the autonomous C oracle path; see scripts/run-c-oracle.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS_DIR="${HARNESS_DIR:-$(dirname "$REPO_ROOT")/defending-code-reference-harness}"
HARNESS_URL="https://github.com/anthropics/defending-code-reference-harness"

echo "== reference harness =="
if [ -d "$HARNESS_DIR/.git" ]; then
    echo "  already cloned at $HARNESS_DIR — pulling"
    git -C "$HARNESS_DIR" pull --ff-only || echo "  (pull skipped)"
else
    echo "  cloning into $HARNESS_DIR"
    git clone --depth 1 "$HARNESS_URL" "$HARNESS_DIR"
fi

echo
echo "== python package =="
if [ ! -d "$HARNESS_DIR/.venv" ]; then
    python3 -m venv "$HARNESS_DIR/.venv"
fi
"$HARNESS_DIR/.venv/bin/pip" install -q -e "$HARNESS_DIR" && echo "  installed (editable)"

echo
echo "== copy targets into harness =="
for t in mrt issueblot; do
    dest="$HARNESS_DIR/targets/$t"
    rm -rf "$dest"
    cp -r "$REPO_ROOT/targets/$t" "$dest"
    echo "  targets/$t -> $dest"
done

cat <<EOF

Setup complete.

  Harness:  $HARNESS_DIR
  Targets:  targets/mrt  (C, execution oracle)
            targets/issueblot  (.NET, static only)

Next:
  1. Authenticate (subscription, no API key needed):
         claude setup-token
         export CLAUDE_CODE_OAUTH_TOKEN=<token>
  2. cd "$HARNESS_DIR" && claude
  3. Follow docs/CODESPACES.md in this repo for the two demo runs.
EOF
