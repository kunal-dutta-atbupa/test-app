#!/usr/bin/env python3
"""Generate MRT test inputs: one valid seed plus one crashing input per bug.

Usage:
    python3 scripts/make-mrt-inputs.py <output-dir>

Writes valid.mrt, bug_label.mrt, bug_nums.mrt, bug_blob.mrt, bug_uaf.mrt.
The valid seed must exit 0 under the ASAN build; each bug_*.mrt reproduces the
corresponding entry in docs/answer-key/mrt-bugs.md.
"""
import os
import struct
import sys


def hdr(record_count: int) -> bytes:
    return b"MRT1" + bytes([1, record_count])


def rec(rtype: int, payload: bytes) -> bytes:
    return bytes([rtype]) + struct.pack("<H", len(payload)) + payload


def build() -> dict[str, bytes]:
    valid = (
        hdr(5)
        + rec(0x01, b"hello")                              # LABEL, len 5 (< 32)
        + rec(0x02, struct.pack("<H", 3))                  # NUMS, count 3
        + rec(0x03, struct.pack("<H", 3) + b"\xaa\xbb\xcc")  # BLOB, declared == data
        + rec(0x06, b"X")                                  # REF
        + rec(0x08, b"")                                   # EMIT (payload still alive)
    )
    return {
        "valid.mrt": valid,
        # 1: LABEL stack-buffer-overflow — body longer than the 32-byte buffer.
        "bug_label.mrt": hdr(1) + rec(0x01, b"A" * 200),
        # 2: NUMS heap-buffer-overflow — count*4 overflows uint16 to a tiny alloc.
        "bug_nums.mrt": hdr(1) + rec(0x02, struct.pack("<H", 16384)),
        # 3: BLOB heap-buffer-overflow (read) — declared span exceeds the copy.
        "bug_blob.mrt": hdr(1) + rec(0x03, struct.pack("<H", 5000)),
        # 4: REF/DROP/EMIT use-after-free — drop frees but EMIT still derefs.
        "bug_uaf.mrt": hdr(3) + rec(0x06, b"Z") + rec(0x07, b"") + rec(0x08, b""),
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    for name, data in build().items():
        with open(os.path.join(out, name), "wb") as fh:
            fh.write(data)
        print(f"wrote {os.path.join(out, name)} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
