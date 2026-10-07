# Changelog

## 0.1.0 — 2026-10-07

- First version: BLAKE2b (RFC 7693) in SPARK, with keyed and unkeyed
  hashing, digests of 1 to 64 bytes, one-shot (`Hash`), two-part
  one-shot (`Hash (Prefix, Message, ...)`, without building the
  concatenation) and incremental (`Init` / `Update` / `Final` / `Clear`)
  interfaces.
- `Blake2b.Spec.Incremental`: an executable ghost model of incremental
  hashing, run by the tests against `Spec.Hash` and against the
  implementation after every step.
- `Blake2b.Spec`: an executable ghost transcription of RFC 7693, validated
  against the RFC's test vector, the BLAKE2 team's 512 known answers, two
  independent C implementations over every message length 0..1024 crossed
  with five key lengths and six digest lengths, and 20 000 vectors from
  HACL*'s verified BLAKE2b (CPython 3.14) over all key and digest lengths.
- Proved with GNATprove 16.1.0 (Silver everywhere, no `pragma Assume`, no
  justified checks):
  - G, each round, the compression function and both one-shot procedures
    compute exactly what `Blake2b.Spec` says;
  - the incremental interface keeps its invariant, including the 128-bit
    byte counter (carry and all) and the rule that the last block is only
    compressed by `Final`;
  - `Init`, `Update` and `Final` compute exactly the functions of
    `Blake2b.Spec.Incremental`, a functional model of incremental hashing
    in the shape of the reference implementation, for every input. The
    counter is also proved against arithmetic on mathematical integers;
  - the model computes `Spec.Hash`, however the message is cut into
    pieces (`Spec.Incremental.Lemma_Update`, `Lemma_Final`), so
    incremental hashing equals one-shot hashing for complete messages
    that fit in one `Byte_Array` (up to 2³¹ bytes). The individual steps
    and the 128-bit counter remain proved against the model beyond
    this complete-message theorem's domain.
    `Blake2b.Hashing.Theorem_Incremental` states and proves this for the
    real procedures.
- Proof-only client API for incremental hashing: `Model`,
  `Has_Absorbed`, `Lemma_Update` and `Lemma_Final` (Static ghost code,
  never compiled), with which callers prove that their own incremental
  hashing computes `Spec.Hash`.
- Zeroisation of the chaining value, buffered blocks and counters, with
  GCC stack scrubbing (`strub`) and zeroing of every call-used register
  (`zero_call_used_regs ("all")`) on every entry point that handles keys
  or input. An external review found that `"used"`, the first choice,
  cleared only each entry point's own registers: key-derived values
  stayed in vector registers after `Final`. `scripts/check-hardening.sh`
  now checks the object code of every hardened return against the
  registers GCC clears for the target.
- Test suite (about 300 000 checks), a seven-cell build matrix (-O0/-O2/-O3
  with checks off and on, plus a contracts-enabled cell), a mutation suite,
  a constant-time check under Valgrind, and a benchmark against the
  reference C.
- Assurance tooling hardened after the same review:
  - the mutation suite first checks the unmutated baseline, keeps every
    log, and counts a layer as having caught a mutant only when its log
    shows unproved checks or failed tests. A tool failure is an error,
    not a catch;
  - the source gate checks the code as the compiler reads it: strings,
    characters and comments removed, case-folded, with line breaks
    ignored. It has a self-test of known bypasses, run in CI;
  - the hardening gate requests all disassembler symbols when supported,
    so LLVM's section aliases do not hide function names;
  - the constant-time gate runs Valgrind on isolated plain and hardened
    builds, accepting hardened stack-scrubbing writes only at their
    verified instruction addresses. Both builds must detect a deliberately
    secret-dependent branch;
  - CI invokes shell scripts explicitly through `bash`, independent of
    their executable file modes.
