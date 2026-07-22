# Triage Report — targets/mrt

4 in → 0 duplicates, 0 false positives, **4 confirmed** (2 high / 2 medium), 0 need manual test.

Context: auto; environment = CLI/batch tool (file inputs untrusted); scoring = derived HIGH/MEDIUM/LOW; 1-vote verification. All four are **execution-verified** — reproduced under AddressSanitizer — so verification is unusually strong here.

## Act on these

### [HIGH] Stack buffer overflow in handle_label  (f001)
`src/mrt.c:38` | stack-buffer-overflow | claimed HIGH (alignment +3) | confidence 9.5/10
**Owner:** component: targets/mrt/; single committer; no CODEOWNERS
**Verdict:** exploitable, votes {true_positive: 1}
**Preconditions (1):** attacker supplies a crafted MRT1 file with a LABEL body > 31 bytes
**Why:** unbounded copy of `len` attacker bytes into `char label[32]` (mrt.c:37-39), reached from the REC_LABEL dispatch (mrt.c:126). Reproduces an ASAN stack-buffer-overflow — an RCE-class write primitive.
**Reachability evidence:** src/mrt.c:126

### [HIGH] Heap overflow via u16 truncation in handle_nums  (f002)
`src/mrt.c:48` | heap-buffer-overflow | claimed HIGH (alignment +3) | confidence 9.2/10
**Owner:** component: targets/mrt/; single committer; no CODEOWNERS
**Verdict:** exploitable, votes {true_positive: 1}
**Preconditions (1):** attacker supplies a NUMS record with count ≥ 16384
**Why:** `uint16_t bytes = count*4` truncates, under-allocating while the loop writes `count` ints (mrt.c:48, 52-54), reached from REC_NUMS dispatch (mrt.c:127). Reproduces an ASAN heap-buffer-overflow (write).
**Reachability evidence:** src/mrt.c:127

### [MEDIUM] OOB heap read in handle_blob checksum  (f003)
`src/mrt.c:73` | heap-buffer-overflow (read) | claimed MEDIUM (alignment +2) | confidence 9.0/10
**Owner:** component: targets/mrt/; single committer; no CODEOWNERS
**Verdict:** exploitable, votes {true_positive: 1}
**Preconditions (1):** attacker supplies a BLOB record whose declared size exceeds its body
**Why:** `checksum(copy+2, declared)` walks an attacker-declared span past the `malloc(len)` copy (mrt.c:69-73), reached from REC_BLOB dispatch (mrt.c:128). Reproduces an ASAN heap-buffer-overflow (read) — info leak / crash, so MEDIUM.
**Reachability evidence:** src/mrt.c:128

### [MEDIUM] Use-after-free across REF/DROP/EMIT  (f004)
`src/mrt.c:88` | use-after-free | claimed MEDIUM (alignment +2) | confidence 9.0/10
**Owner:** component: targets/mrt/; single committer; no CODEOWNERS
**Verdict:** exploitable, votes {true_positive: 1}
**Preconditions (1):** attacker supplies records ordered REF → DROP → EMIT
**Why:** `handle_drop` frees `ps->last` without clearing it (mrt.c:88); `handle_emit` then dereferences it (mrt.c:92-93), reached from REC_DROP/REC_EMIT dispatch (mrt.c:130-131). Reproduces an ASAN heap-use-after-free.
**Reachability evidence:** src/mrt.c:130

## Dropped

_None — every finding was confirmed._
