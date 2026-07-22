# MRT — mini record-table parser (injected-bug discovery target)

A small, self-contained C parser for a made-up binary container format,
**`MRT1`**. It exists to serve as an *uncontaminated* discovery target for the
reference vulnerability harness: the code is original, matches no public CVE,
and carries **no in-tree markers describing where it is unsafe**. A null result
here therefore means "the tool found nothing," not "the tool recalled a
documented finding."

> The bug inventory (the answer key) is deliberately **not** in this directory.
> It lives at `docs/answer-key/mrt-bugs.md` in the repo root so you can point a
> scanner at `targets/mrt/` without leaking the answers. Grade against it after
> a run.

## Build & run

```sh
gcc -O1 -g -fsanitize=address -fno-omit-frame-pointer -o mrt src/mrt.c
./mrt fixtures/valid.mrt      # exits 0, prints one line per record
```

## The `MRT1` format

```
Header (6 bytes)
  0  magic[4]      "MRT1"
  4  version       u8, must be 1
  5  record_count  u8

Record (repeated record_count times)
  +0 type          u8
  +1 length        u16, little-endian
  +3 body[length]
```

Record types:

| type | name  | body meaning                                             |
|------|-------|----------------------------------------------------------|
| 0x01 | LABEL | text copied into a local label buffer, then printed      |
| 0x02 | NUMS  | u16 `count`, then the parser materializes `count` values |
| 0x03 | BLOB  | u16 `declared` size, then data; a declared span is summed |
| 0x06 | REF   | body is copied and remembered for a later EMIT           |
| 0x07 | DROP  | releases the remembered payload                          |
| 0x08 | EMIT  | prints the first byte of the remembered payload          |

Every field is attacker-controlled. The parser dispatches by `type`; the
REF/DROP/EMIT records share one parser-scoped pointer whose lifetime spans
multiple records.

## Why this shape

The four handlers give four distinct attack surfaces and (when something goes
wrong) four distinct sanitizer signatures — enough for the harness's find loop
to fan out across focus areas and for dedup to see distinct crash tuples,
without any two bugs collapsing into one.
