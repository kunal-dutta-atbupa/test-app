# Threat Model: MRT1 record-table parser (`targets/mrt`)

## 1. System context

`mrt` is a small, self-contained C program (~140 LOC, single translation unit
`src/mrt.c`) that parses a made-up binary container format, **MRT1**. It is
invoked as `./mrt <file>`: it reads the whole file into a heap buffer, checks a
6-byte header, then walks a sequence of typed records, dispatching each to a
handler (`LABEL`, `NUMS`, `BLOB`, `REF`/`DROP`/`EMIT`). Every byte of the input
is attacker-controlled. It is a command-line / batch tool: the *operator* who
runs it is trusted, but the **file it is pointed at is not** — and in a realistic
embedding the same parser could sit behind a service that accepts uploaded files.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| host process integrity | control-flow / memory of the parsing process; corruption can mean code execution | critical |
| process memory contents | heap/stack data adjacent to parser buffers, potentially leaked via out-of-bounds reads | medium |
| service availability | the parsing process staying alive rather than crashing on hostile input | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| `main()` file read (`argv[1]` → `fread`) | reads an arbitrary file into a heap buffer, validates only magic + version | untrusted file → process memory | host process integrity, process memory contents, service availability |
| record dispatch loop (`main` switch on `type`) | length-prefixed records copied/indexed by attacker-supplied `len`/count fields with no bound against remaining input | untrusted file → process memory | host process integrity, process memory contents |
| `REF`/`DROP`/`EMIT` payload lifecycle | a parser-scoped pointer whose lifetime spans multiple records | untrusted record ordering → dangling pointer | host process integrity, process memory contents |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Remote/arbitrary code execution via out-of-bounds **writes** while parsing a crafted MRT1 file | local_user | record dispatch loop | host process integrity | critical | likely | unmitigated | none in shipped build (ASAN is test-only) | stack-buffer-overflow in `handle_label`; heap-buffer-overflow (write) in `handle_nums` |
| T2 | Information disclosure / crash via out-of-bounds **reads** and use-after-free | local_user | record dispatch loop; REF/DROP/EMIT lifecycle | process memory contents, host process integrity | high | likely | unmitigated | none | heap-buffer-overflow (read) in `handle_blob`; heap-use-after-free (read) in `handle_emit` after `handle_drop` |
| T3 | Denial of service: any malformed record aborts the process | local_user | main() file read; record dispatch loop | service availability | medium | almost_certain | unmitigated | none | (gap-fill — every T1/T2 primitive also crashes; no separate evidence needed) |

## 5. Deprioritized

| threat | reason |
|---|---|
| Spoofing of input source | no network / no authentication in scope; operator chooses the file |
| Repudiation | no multi-user actions, no audit surface |
| Supply-chain compromise | single self-contained `.c` file, no third-party dependencies |
| Elevation of privilege beyond the process | no setuid/IPC/privilege boundary inside the tool itself |

## 6. Open questions

- **Deployment exposure:** is `mrt` only ever run by a human on local files, or
  is it (or this parser, embedded) reachable from a network service that accepts
  uploaded MRT1 files? If the latter, `actor` on T1/T2 rises to `remote_unauth`
  and likelihood to `almost_certain`.
- **Production hardening:** is the shipped build compiled with
  `_FORTIFY_SOURCE`, stack canaries, and ASLR? The verification build uses ASAN,
  which is a *detector*, not a production control.
- **Input size limits:** is there an upstream cap on file size / record count
  before this parser is reached?

## 7. Provenance

- mode: bootstrap
- date: 2026-07-22
- target: targets/mrt @ 1f51e7a
- inputs: git-log mined (no prior vuln-fix commits found); source read
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Bounds-check every `len`/count field against the actual remaining input before any copy or index | T1,T2,T3 | yes | M |
| Null out `ps->last` after `free()` (and gate `EMIT` on it) to eliminate the use-after-free class | T2 | partial | S |
| Compute allocation sizes in a width that can't truncate (`size_t`, checked multiply) before `malloc` | T1 | partial | S |
| Build the shipped binary with `-D_FORTIFY_SOURCE=2 -fstack-protector-strong` + ASLR, and fuzz the parser in CI | T1,T2,T3 | partial | M |
