# Changelog

## Unreleased

- **Compression frame scrubbed.** After a normal return of `Init`, `Update`,
  `Final` or the one-shot `Hash`, one message word could remain on the stack
  in the frame of `Blake2b.Core.Compress`: GCC's `strub` scrubs only the
  stack of the body it wraps, and the compression function was a function
  of its own. `Compress` is now `Inline_Always` and the four hardened entry
  points are `flatten`ed, so its frame lies inside the scrubbed body. No
  contract or proof changed. Measured on macOS arm64: bulk data about
  3-4% faster, 64 bytes about 6.5% slower, `blake2b-hashing.o` about six
  times larger.
- **Hardening gates strengthened.** `scripts/check-hardening.sh` now also
  reads `blake2b-core.o`, fails on any function in `blake2b-hashing.o` other
  than the entry points, their clones and the accessors that handle no
  secret, fails if `Compress` has a symbol or is called, and checks in the
  source that each entry point has `strub`, `zero_call_used_regs` and
  `flatten` (the attribute strings are compared exactly: GCC ignores
  `"Flatten"`); `memcpy`, `memmove` and `memset` are allowed and listed; any
  other undefined reference fails; a jump out of an entry point, a wrapper
  or a clone fails unless it goes into its own cold part (by name, or by its
  own cold section in a relocation record), and a cold part may jump
  nowhere; an indirect jump, a jump whose relocation names the function
  itself, and a function that runs off its end (its last instruction is not
  a return, a jump, a call or a trap) fail too; a returning cold part of a
  function whose returns are checked must clear the registers. The
  register-clearing parser tracks later writes, register widths and branch
  targets: the old one accepted a register written again after its clear,
  a narrow clear and a clear on a skipped branch. New:
  `scripts/test-check-hardening-negative.sh` (the gate fails when a
  hardening is removed), `scripts/check-stack-scan.sh` (26 scenarios, any
  canary word left after a normal return fails, each against a control) and
  `scripts/test-check-stack-scan.sh`. CI runs them on all four platforms.

- **Carry mutants caught.** The 128-bit counter's addition moves to a
  private unit of its own, `Blake2b.Hashing.Counter_Arithmetic`
  (`Inline_Always`, contract unchanged), proved under the default step
  budget. Under `blake2b-hashing.adb`'s ten-times-larger budget Alt-Ergo
  ran on for hours on the false goal of the mutants `carry` and
  `plus-carry`, past every memory guard, so neither had ever been shown
  caught; both now are, judged as strictly as the theory mutants, and the
  new unit is in the step-margin measurement. A new test calls the
  counter's addition and the model's `Plus` directly, at and around the
  carry and on 10,000 random cases checked against Ada's big integers, so
  the tests catch both mutants too. `scripts/check-hardening.sh`
  fails if the counter's object defines any function, with two new
  negative controls.

## 0.1.1 — 2026-10-14

- **Corrected trusted base.** 0.1.0 declared `Blake2b.Core.Same`, `Same8`
  and `Same_Block` with `Import`, so GNATprove trusted them, and its README
  did not list them. They are now ordinary expression functions with the
  same names and signatures, and GNATprove checks their `Logical_Equal`
  annotation. `scripts/check-sources.sh` now forbids `Import` anywhere in
  `src/`, not only in `Blake2b.Spec`.
- **Whole-stream theory** (every declaration is Static ghost, so no code or
  data is compiled; each of the four new object files holds only its
  package's elaboration flag,
  so that no library member lacks a symbol and macOS `ranlib` stays quiet;
  no existing executable or public signature changes, and the seven
  existing objects are unchanged). `Blake2b.Streaming` names a
  logical message of up to 2^34 + 36 bytes as 14 sources of 2^32
  bytes cut into ordered pieces. Its children give per-call lemmas
  (`Theory`), the tie to `Spec.Hash` (`Consistency`) and a proved loop of
  real `Init`, `Update` and `Final` calls (`Example.Run_Loop`) with a
  full-length witness. This is per-call lemmas plus one proved loop, not a
  single quantified theorem, and it claims nothing beyond 2^34 + 36 bytes.
  The README states the scope.
- `TRUST.md`: the trust register, listing the toolchain pins, the
  specification, the hardening checks and the warning suppressions. No
  entry is signed yet. `scripts/check-sources.sh` checks that it has one
  row per warning suppression (a count).
- Tests: every pair of cut points for messages of 0..300 bytes, with and
  without a key, against both C oracles; two long streams (2^32 + 129 and
  2^34 + 36 bytes) in the release profile (`test_main --long`), run by CI
  on every platform.
- Mutation suite: sixteen more mutants of the theory, a memory and time
  guard, a step-margin check on the baseline, and a tainted outcome for
  proofs the guard killed.

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
