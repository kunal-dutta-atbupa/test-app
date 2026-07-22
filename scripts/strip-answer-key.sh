#!/usr/bin/env bash
# Produce a scan-only copy of a target with any answer-key leakage removed, so a
# static scan can't recall a documented finding instead of discovering it.
#
# Removes: exploits/ and poc/ directories, README/THREAT_MODEL and other .md
# files, and strips comment lines that name a defect (VULNERABLE, BUG, CVE,
# XXX-sec). Our own targets are already clean; this is the tool to point at a
# THIRD-PARTY documented repo before scanning it.
#
# Usage: scripts/strip-answer-key.sh <src-target-dir> <dest-dir>
set -euo pipefail

SRC="${1:?usage: strip-answer-key.sh <src-target-dir> <dest-dir>}"
DEST="${2:?usage: strip-answer-key.sh <src-target-dir> <dest-dir>}"

rm -rf "$DEST"
cp -r "$SRC" "$DEST"

# Drop obvious answer-key artifacts.
find "$DEST" -type d \( -iname exploits -o -iname poc -o -iname pocs \) -prune -exec rm -rf {} +
find "$DEST" -type f \( -iname '*.md' -o -iname 'VULN-FINDINGS.json' -o -iname 'TRIAGE.json' \) -delete

# Strip single-line comments that advertise a bug (C/C++/C#/Java-style // and #).
find "$DEST" -type f \( -name '*.c' -o -name '*.h' -o -name '*.cpp' -o -name '*.cc' \
        -o -name '*.cs' -o -name '*.java' -o -name '*.py' \) -print0 |
while IFS= read -r -d '' f; do
    sed -i -E '/^[[:space:]]*(\/\/|#).*(VULNERAB|BUG:|FIXME.*sec|CVE-|XXX-sec|EXPLOIT)/Id' "$f"
done

echo "stripped copy at: $DEST"
echo "review it, then scan the copy instead of the original."
