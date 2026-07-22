# Threat model — MRT parser

## Asset / entry point
A single untrusted file passed as `./mrt <file>`. The entire file is
attacker-controlled: header fields and every record's type, length, and body.

## Trust boundaries
- **File → header.** `magic`, `version`, and `record_count` are read before any
  record. Only `magic` and `version` are checked; `record_count` is trusted.
- **Record framing → handler.** The dispatch loop reads a record's `type` and
  `length`, then hands the handler a pointer to the body plus the declared
  `length`. The loop does **not** verify that the declared length (or the
  running offset) stays within the bytes actually present in the file.
- **In-band size fields → allocation and iteration.** Several bodies carry their
  own size/count fields (e.g. NUMS `count`, BLOB `declared`). These drive
  allocation sizes and loop bounds inside the handlers.
- **Cross-record state.** REF/DROP/EMIT operate on a shared parser-scoped
  pointer, so a record's effect can depend on records processed earlier.

## Attacker goal
Reach a memory-safety violation (out-of-bounds read/write, use-after-free)
detectable by AddressSanitizer, using only a crafted input file.

## Out of scope
Non-memory-safety logic errors, denial of service via large inputs, and the
correctness of the checksum/label output values.

> This document names the attack surface, not the defects. Specific bug
> locations are recorded separately in `docs/answer-key/mrt-bugs.md`.
