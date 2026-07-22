#!/usr/bin/env bash
# Sanity-check the C target's oracle WITHOUT the harness: build with ASAN, run
# the valid seed (must exit 0), then run each crashing input (must trip ASAN).
# Run this first so a null harness result means "tool found nothing", not
# "target is broken".
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/targets/mrt/src/mrt.c"
WORK="$(mktemp -d)"
BIN="$WORK/mrt"

echo "== building $SRC with ASAN =="
gcc -O1 -g -fsanitize=address -fno-omit-frame-pointer -o "$BIN" "$SRC" || {
    echo "BUILD FAILED"; exit 1; }

python3 "$ROOT/scripts/make-mrt-inputs.py" "$WORK" >/dev/null

echo
echo "== valid.mrt (expect exit 0, no ASAN) =="
if "$BIN" "$WORK/valid.mrt" >/dev/null 2>"$WORK/valid.err"; then
    echo "  OK — clean exit"
else
    echo "  FAIL — valid seed did not exit 0:"; cat "$WORK/valid.err"; exit 1
fi

status=0
for name in bug_label bug_nums bug_blob bug_uaf; do
    err="$WORK/$name.err"
    "$BIN" "$WORK/$name.mrt" >/dev/null 2>"$err"
    sig="$(grep -oE 'AddressSanitizer: [a-z-]+' "$err" | head -1 | sed 's/AddressSanitizer: //')"
    if [ -n "$sig" ]; then
        printf "  %-10s -> ASAN %s\n" "$name" "$sig"
    else
        printf "  %-10s -> NO ASAN CRASH (unexpected)\n" "$name"; status=1
    fi
done

echo
[ "$status" -eq 0 ] && echo "oracle OK: valid clean, all 4 bugs crash under ASAN" \
                     || echo "oracle PROBLEM: see above"
rm -rf "$WORK"
exit "$status"
