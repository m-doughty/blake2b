# blake2b trust register

Everything the crate's claims rest on that its own proof does not
establish. **No entry is signed.** The sign-off is a signature by the
maintainer's key, produced by a tool that does not exist yet; until it does,
every sign-off reads `unsigned`. Entries here are proposals, and an agent
cannot sign them. The README says what is proven, what is tested and what is
trusted; this file is the detail behind its "trusted" list.

## Summary

| Class | Entries | Needs a signature |
|---|---|---|
| Assumptions (`pragma Assume`, `False_Positive`, `Intentional`, `Skip_Proof`, an `Import` GNATprove trusts) | none | would need one each |
| Unproved code (`SPARK_Mode => Off`, C or Rust behind it) | none | would need one each |
| Third-party SPARK | none (`alire.toml` lists no dependency; not checked by the script) | would need one per dependency |
| Trusted definitions | none (0.1.0 had three: see N-1) | listed, none |
| Warning suppressions | W-1 to W-8 | no, each has a recorded `Reason` |
| Toolchain and proof model | T-1 to T-3 | a bump is a signed change |
| The specification | S-1 | listed |
| Not proved, checked in object code | H-1 | listed |

`scripts/check-sources.sh` enforces the first two rows and the trusted
definitions: it forbids the escape hatches it knows in `src/` (`Import` and `pragma Interface` included),
and it lists the warning suppressions (it finds 8) and checks that this file
has one `W-n` row for each, by count. A source that adds an escape hatch or a
suppression fails CI. The project's `--warnings=error` is a second guard
against constructs the gate does not name.

## Entries

| ID | Kind | Location | Sign-off |
|---|---|---|---|
| T-1 | Toolchain | GNAT, GNATprove, gprbuild, Alire | unsigned |
| T-2 | Toolchain | the provers and Why3 | unsigned |
| T-3 | Proof model | GNAT runtime big-integer library | unsigned |
| S-1 | Specification | `Blake2b.Spec` | unsigned |
| H-1 | Not proved | wipes, register and stack clearing | unsigned |
| W-1 | Warning suppression | `src/blake2b-hashing.ads`, `Machine_Attribute` | no signature needed |
| W-2 | Warning suppression | `src/blake2b-hashing.adb` (`Digest_Of`), `Machine_Attribute` | no signature needed |
| W-3 | Warning suppression | `src/blake2b-wipe.ads`, `Machine_Attribute` | no signature needed |
| W-4 | Warning suppression | `src/blake2b-hashing.adb` (`Digest_Of`), "statement has no effect" | no signature needed |
| W-5 | Warning suppression | `src/blake2b-hashing.adb` (`Digest_Of`), `H` is set by `Sanitize_Words8` | no signature needed |
| W-6 | Warning suppression | `src/blake2b-hashing.adb` (`Digest_Of`), `Buf` is set by `Sanitize_Block` | no signature needed |
| W-7 | Warning suppression | `src/blake2b-hashing.adb` (`Theorem_Incremental`), `S` is set but not used | no signature needed |
| W-8 | Warning suppression | `src/blake2b-streaming-example.adb` (`Run_Loop`), `S` is set by `Finish` but not used | no signature needed |

### T-1 Compiler and build tools
- **Proposition:** GNAT 16.1.0 compiles the SPARK source to code that behaves
  as the language defines it, and GNATprove 16.1.0 implements SPARK's
  semantics, so a proof of the source is a proof about the compiled program.
  gprbuild 26.0.1 and Alire 2.1.1 build what the sources say.
- **Why believed:** the pinned versions run the whole test suite (12,533,563
  checks) at -O0, -O2 and -O3, with checks off and on, and the digests agree
  with two independent C implementations and HACL\*.
- **If false:** a proof could hold for a program the compiler does not
  produce. The tests would be the only remaining evidence.
- **Scope:** all code. A version bump is a signed change.

### T-2 Provers
- **Proposition:** Z3 4.15.4, cvc5 1.3.2 and Alt-Ergo 2.6.1, driven by Why3
  1.8.2 as shipped with GNATprove 16.1.0, never report a false statement
  proved.
- **Why believed:** widely used; each statement is proved by at least one of
  three independent provers; the mutation suite shows that mutated programs
  are not proved.
- **If false:** a lemma or postcondition could be false while shown proved.
- **Scope:** every proved check. Proofs are limited in steps, never time, so
  results do not depend on the machine.

### T-3 The big-integer proof model
- **Proposition:** GNATprove's model of `Ada.Numerics.Big_Numbers.Big_Integers`
  (whose runtime bodies are `SPARK_Mode => Off`; four conversions are skipped
  in `Blake2b.Hashing`'s analysis) agrees with mathematical integers.
- **Why believed:** it is the standard library's own SPARK model. The
  128-bit counter is proved against it, and the mutation suite shows the
  proof catches a missing carry past 2⁶⁴ (`carry`, `plus-carry`), which no
  test through the public interface can reach (it takes 2⁶⁴ bytes); a test
  calls the counter's addition and the model's `Plus` directly and checks
  them against Ada's big integers. The counter is proved in a unit of its own,
  `Blake2b.Hashing.Counter_Arithmetic`, under the default step budget, and
  both mutants leave the counter's postcondition unproved there within it
  (up to 0.1.1 they ran past every memory guard and were never caught).
- **If false:** the counter and length claims in ghost code could be about
  the wrong numbers.
- **Scope:** ghost code only. It is compiled into no release build (the
  contracts-enabled build, `-gnata`, does compile the non-static ghost parts).

### S-1 The specification
- **Proposition:** `Blake2b.Spec` (and the incremental model
  `Blake2b.Spec.Incremental`) computes BLAKE2b exactly as RFC 7693 defines it.
- **Why believed:** it is tested, not proved: the RFC's vector, 512 known
  answers, two independent C implementations over every length 0..1024
  crossed with five key lengths and six digest lengths, and 20,000 vectors
  from HACL\*'s verified BLAKE2b.
- **If false:** the code would be proved equal to the wrong function.
- **Scope:** every functional claim. A proof shows code equals spec; only
  testing shows spec equals BLAKE2b.

### H-1 Wiping, registers and stack
- **Proposition:** after `Final` and `Clear`, no copy of the key, chaining
  value or block that the library holds survives in the state; after a
  normal return of `Init`, `Update`, `Final` and the one-shot `Hash`, none
  survives as a whole word on the stack below the caller; and none survives
  in a call-used register when `Init`, `Update`, `Final` or `Digest_Of`'s
  scrubbed body returns (the `Hash` wrappers then only release that body's
  stack, and their own registers are not checked). The caller's own key
  array is not erased by these calls.
- **What is proved:** the wipe postconditions say the secret-bearing fields
  of the state (chaining value, buffered block, counters) are zero; the
  phase and the output length are kept, and `Final` sets the phase to
  finalized. That is about the value of an object only.
- **What is checked, not proved:** `Sanitize_*` are never inlined and are
  `noipa`; `Init`, `Update`, `Final` and `Digest_Of` carry `strub`,
  `zero_call_used_regs ("all")` and `flatten`, and `Core.Compress` is
  `Inline_Always`, so that the compression function's message words and
  working vector lie inside a scrubbed frame (`strub` scrubs only the body
  it wraps; up to 0.1.1 the compression function was a function of its own
  and one message word could remain in its frame after a normal return).
  `scripts/check-hardening.sh` checks the object code: strub clones,
  registers cleared at every return, no other function defined in
  `blake2b-hashing.o` but the accessors that handle no secret, no
  `Compress` symbol or call, no function in the counter's object
  (`Add_Counter` is `Inline_Always` too); `flatten` is checked in the source, its
  strings compared exactly (the object cannot show it missing at `-O3
  -gnatn`); any undefined reference outside the listed classes fails, and so
  does a jump out of an entry point, wrapper or clone (except into its own
  cold part) or out of a cold part, an indirect jump, and a function that
  runs off its end. `scripts/check-stack-scan.sh`
  measures the stack after a normal return in 26 scenarios and fails on any
  value left, against controls that do leave values. The C library's
  `memcpy`, `memmove` and `memset` are called from inside the entry points
  (allowed and listed: they run inside the call, whose return zeroes every
  call-used register). Callee-saved registers are not zeroed (the ABI
  restores them). `strub` scrubs the stack of the body it wraps, not the
  frames of callees outside it (the libc routines, the wipe routines): the
  evidence that they hold nothing is that the stack scan finds no canary
  below the caller. Its region is at least 24 KiB and is doubled while the
  deepest non-zero byte it finds is near its end; it does not show that
  every byte the call wrote was read.
- **Not claimed:** the stack after an exception or a task abort (measured
  and reported, not gated: values do remain after an exception); `Clear`
  (no `strub`; it reads no secret); the one-shot `Hash` wrappers, which are
  not hardened themselves (they call `Digest_Of`, which is); registers outside the
  compiler's target description (on Linux x86-64 with AVX-512 the C
  library's `memcpy` may use `ymm16`-`ymm31`, which baseline x86-64 does not
  name; on AArch64 the upper halves of `v8`-`v15`; inferred, not measured);
  partial words and derived values, which the scan's whole-word canaries do
  not recognise; the registers of the one-shot `Hash` wrappers after
  `Digest_Of` returns (they hold stack addresses, not secrets, in the
  shipped macOS arm64 object; not checked on other targets); the x86-64 red
  zone (argued in the scan's header, not measured); a compiler or target
  outside the build matrix. The allow-lists in `check-hardening.sh` were
  derived on macOS arm64 and first checked on the other platforms by CI.
- **If false:** key-derived bytes could remain in memory the library no
  longer controls.
- **Scope:** the compiler and target in the build matrix, in the release
  profile (checks and contracts off), which is what the object check and the
  stack scan read. A contracts-enabled build runs the specification
  (`Spec.Hash`, `Spec.Compress`) on the secrets in frames nothing scrubs.

### W-1 to W-3 `Machine_Attribute` ignored (GNATprove)
- **Locations:** `src/blake2b-hashing.ads` (`Init`, `Update`, `Final`),
  `src/blake2b-hashing.adb` (`Digest_Of`), `src/blake2b-wipe.ads`
  (`Sanitize_Words8`, `Sanitize_Block`).
- **Reason recorded:** "code-generation attribute: no effect on proof".
  GNATprove ignores the attribute, which is correct: it affects code
  generation only.

### W-4 to W-6 Wipes of values never read again (`Digest_Of`)
- **Locations:** `src/blake2b-hashing.adb`, the three suppressions around
  `Wipe.Sanitize_Words8 (H)` and `Wipe.Sanitize_Block (Buf)`.
- **Reason recorded:** "zeroisation of secrets that are not read again".
  Flow analysis rightly sees no later read; the wipe is the point.

### W-7 State not used after `Final` (`Theorem_Incremental`)
- **Location:** `src/blake2b-hashing.adb`, around `Final (S, Digest)`.
- **Reason recorded:** "the theorem is about Digest; the state ends here".

### W-8 State not used after `Finish` (`Run_Loop`)
- **Location:** `src/blake2b-streaming-example.adb`, around the call to
  `Finish`.
- **Reason recorded:** "the example is about Digest; the state ends here".

## Notes
- **N-1 Removed in 0.1.1:** 0.1.0 declared `Blake2b.Core.Same`, `Same8` and
  `Same_Block` with `Import` and `Logical_Equal`, which GNATprove trusted, and
  its README did not list them. From 0.1.1 they are ordinary expression
  functions whose `Logical_Equal` annotation GNATprove checks.
- **N-2 Proof visibility:** the whole-stream lemmas read the private
  completion of `Blake2b.Hashing.Max_Input` through proof visibility. That is
  how this toolchain behaves, not a language guarantee. If a toolchain stops
  doing it the proofs fail; they cannot silently succeed on a wrong statement.
