# blake2b

**blake2b**: BLAKE2b (RFC 7693) in SPARK, proven to compute exactly
what an executable transcription of the RFC specifies, a transcription
that is tested against independent implementations.

- **Proven correct.** GNATprove proves that the mixing function G, every
  round, the compression function and both one-shot hash procedures
  compute exactly what `Blake2b.Spec`, a plain, executable transcription
  of RFC 7693, says. For every input, not a sample of them.
- **Incremental hashing proven equal to one-shot hashing:** `Init`, any
  sequence of `Update`s and `Final` compute `Spec.Hash` of everything
  absorbed, however the message is cut into pieces. Each step is proven
  to compute exactly its counterpart in a functional model, 128-bit
  counter and carry included.
- **Proven free of run-time errors** (SPARK Silver) throughout: no
  overflow, no out-of-range index, no uninitialised read. Release builds
  therefore compile without run-time checks.
- **The specification is tested, not proven:** against the RFC's test
  vector, the BLAKE2 team's 512 known answers, two independent C
  implementations, and HACL*'s formally verified BLAKE2b (through CPython
  3.14), over the key and digest lengths the published vectors leave out.
- **Fast:** on bulk data, within about 1.1× of the BLAKE2 reference C
  built by the same compiler at the same optimisation level.
- **Hardened:** keys and intermediate state are wiped, with GCC stack
  scrubbing and register zeroing on every entry point that handles them.
- **No dependencies.** BSD-3-Clause.

## Using it

```ada
with Blake2b;         use Blake2b;
with Blake2b.Hashing;

procedure Example (Data, Key : Byte_Array) is
   Digest_32 : Byte_Array (0 .. 31);   --  the digest length is the
   Digest_64 : Byte_Array (0 .. 63);   --  length of the array: 1 .. 64
begin
   --  Unkeyed BLAKE2b-256.
   Blake2b.Hashing.Hash (Data, No_Bytes, Digest_32);

   --  Keyed BLAKE2b-512 (a MAC); keys are 0 .. 64 bytes.
   Blake2b.Hashing.Hash (Data, Key, Digest_64);

   --  The hash of a 4-byte prefix followed by Data, without building
   --  the concatenation (the shape of Argon2's variable-length hash).
   Blake2b.Hashing.Hash
     (Prefix  => [64, 0, 0, 0],
      Message => Data,
      Key     => No_Bytes,
      Digest  => Digest_64);

   --  Incremental: absorb input in pieces of any length.
   declare
      S : Blake2b.Hashing.State;
   begin
      Blake2b.Hashing.Init (S, Length => 64, Key => Key);
      Blake2b.Hashing.Update (S, Data);
      Blake2b.Hashing.Update (S, Data);
      Blake2b.Hashing.Final (S, Digest_64);   --  also wipes S
   end;
end Example;
```

`Byte_Array` is indexed by a 64-bit integer subtype, and arrays may have
any bounds. `State` is limited, so key material in it cannot be copied.
`Clear` wipes a state abandoned before `Final`.

## Proving your own code with it

Every contract is stated against `Blake2b.Spec`, so SPARK code that
calls this crate can prove what it computes.

**One-shot hashing** needs nothing more: `Hash`'s postcondition is
`Digest = Spec.Hash (Message, Key, Digest'Length)`.

**Incremental hashing.** A `State` cannot record the bytes it has
absorbed: SPARK has no ghost record components. So the caller keeps them,
as its own ghost value, and calls one lemma before each `Update` and one
before `Final`:

- `Has_Absorbed (S, Key, Message)`: `S` has absorbed exactly `Message`,
  in pieces of any sizes, since `Init (S, Length, Key)`. After `Init` it
  holds for every empty `Message`.
- `Lemma_Update (S, Key, Before, Data, Joined)`: when `S` has absorbed
  `Before`, and `Joined` holds `Before` followed by `Data`, then after
  `Update (S, Data)` it has absorbed `Joined`. `Joined` may be a longer
  slice of the same message or a ghost concatenation; any bounds will do.
  The lemma also discharges `Update`'s precondition.
- `Lemma_Final (S, Key, Message)`: when `S` has absorbed `Message`,
  `Final` writes `Spec.Hash (Message, Key, Output_Length (S))`.

These are `Ghost => Static`: GNATprove proves them and no build ever
compiles them. So refer to them from Static-level assertions,
`pragma Assert (Static => ...)`. This is how a message cut into pieces at
any offsets (`Cuts`, in order) is proved to hash to `Spec.Hash`. It is
`Theorem_Incremental`'s body, which GNATprove proves:

```ada
Init (S, Digest'Length, Key);
for I in Cuts'Range loop
   pragma Loop_Invariant
     (P in 0 .. Message'Length
      and then (if I > Cuts'First then P = Cuts (I - 1) else P = 0)
      and then Is_Absorbing (S)
      and then Output_Length (S) = Digest'Length
      and then Has_Absorbed (S, Key, Message (F .. F + P - 1)));
   Lemma_Update
     (S, Key,
      Before => Message (F .. F + P - 1),
      Data   => Message (F + P .. F + Cuts (I) - 1),
      Joined => Message (F .. F + Cuts (I) - 1));
   Update (S, Message (F + P .. F + Cuts (I) - 1));
   P := Cuts (I);
end loop;
Lemma_Update
  (S, Key,
   Before => Message (F .. F + P - 1),
   Data   => Message (F + P .. Message'Last),
   Joined => Message);
Update (S, Message (F + P .. Message'Last));
Lemma_Final (S, Key, Message);
Final (S, Digest);    --  proved: Digest = Spec.Hash (Message, Key, ...)
```

Here `F` is `Message'First`, and `P` counts the bytes absorbed so far.
The theorem is itself Static ghost code, so its loop invariant needs no
`Static =>` label. In your own (compiled) code, label the invariant that
mentions `Has_Absorbed` with `Static =>`.

**How far the end-to-end proof reaches.** `Has_Absorbed` and
`Theorem_Incremental` name the whole message as one `Byte_Array`, so they
cover messages of at most 2³¹ bytes (2 GiB). That's the same domain as
`Spec.Hash` itself, and so the same as the one-shot proof. A stream
absorbed in pieces can be longer, up to RFC 7693's 2¹²⁸ − 1 bytes (with
a key, the key's padded 128-byte block counts, so 2¹²⁸ − 129 message bytes). For
those streams every step is still proven:
- each `Update` and the `Final` equal `Spec.Incremental`'s functions;
- the 128-bit counter is exact, carry included.

For streams of up to 2³⁴ + 36 bytes (below) the end-to-end statement is
proven as well. Beyond that no proof states "this equals BLAKE2b of the
whole stream", because the proof has no name for it. That's a limit on
what the proof can express, not evidence that longer streams hash
differently: the code that runs is the same.

### Streams longer than one array

`Blake2b.Streaming` names a logical message of up to 2³⁴ + 36 bytes (the
size RFC 9106 needs) as 14 sources of 2³² bytes each (all 14 are present, whatever their
contents), cut into ordered pieces. A piece is a run of one source and may
be empty; a schedule has at least one piece, so an empty message is one empty
piece. The worked example `Run_Loop` also needs each piece to fit one
`Byte_Array`, at most 2³¹ bytes; the model itself does not. Every
declaration is `Ghost => Static`, so no code or data is compiled; each
of the four units' object files holds only the package's elaboration flag
(so that the library archive has no member without a symbol). What is
proven:
- **Per call** (`Blake2b.Streaming.Theory`): `Init`, each `Update` and
  `Final` take the model of the incremental hash to the model of the
  logical prefix absorbed so far, `Logical_After`. After the last piece,
  `Final` gives `Logical_Hash`, RFC 7693's padded block fold of the whole
  message: key block, counters, zero padding, final flag.
- **Tied to the specification** (`Blake2b.Streaming.Consistency`):
  whenever one `Byte_Array` holds the message, `Logical_Hash` is
  `Spec.Hash`.
- **A worked example** (`Blake2b.Streaming.Example.Run_Loop`): the real
  `Init`, a loop of real `Update`s over any schedule of up to 2³¹ − 2
  pieces, and the real `Final`, proven to give `Logical_Hash`. A witness
  shows the example's preconditions hold at the full length, 2³⁴ + 36
  bytes over 14 sources.

Be exact about what this is. It is per-call lemmas plus one proved loop,
not a single theorem quantified over every sequence of calls. The loop
itself is bounded by the array that holds its schedule of pieces; the
per-call lemmas put no bound on the number of calls. A client follows
`Run_Loop`'s pattern in its own proof. The domain is the Argon2
shape and nothing wider: for a stream past 2³⁴ + 36 bytes this claims
nothing, and the counter's high word is zero throughout it, so it adds
nothing to the 128-bit counter proof above. The proofs read
`Blake2b.Hashing.Max_Input`'s private completion through proof visibility
(true of GNATprove 16.1.0, not a language guarantee); if a toolchain stops
doing so, the proofs fail rather than succeed wrongly. The model is not
proven against the RFC; it is tied to `Spec.Hash`, which the tests check.

A client reasons with the lemmas as `Run_Loop` does: chain each call's model
with `Lemma_Update_Of`, which takes any context equal to the prefix's. This
proves, in a client of 10 checks, that `Init`, one `Update` of the whole
message and `Final` give `Logical_Hash` (add `use type Inc.Context;`, where
`Inc` is `Blake2b.Spec.Incremental`, to see the context equality):

```ada
with Blake2b;                  use Blake2b;
with Blake2b.Streaming;        use Blake2b.Streaming;
with Blake2b.Streaming.Theory; use Blake2b.Streaming.Theory;

procedure Hash_In_One_Piece
  (Key    : Byte_Array;
   C      : Contents;
   M      : Pieces;
   Length : Offset;
   Data   : Byte_Array;
   NN     : Digest_Length)
with Ghost => Static, Global => null,
     Pre => OK (Key, C, M, Length)
            and then Data'Length = Length
            and then Realizes (C, M, Length, 0, Data),
     Post => Inc.Final (Inc.Update (Inc.Init (Key, NN), Data))
             = Logical_Hash (Key, C, M, Length, NN)
is
   After_Init   : constant Inc.Context := Inc.Init (Key, NN);
   After_Update : constant Inc.Context := Inc.Update (After_Init, Data);
begin
   Lemma_Init (Key, C, M, Length, NN);
   Lemma_Update_Of (After_Init, Key, C, M, Length, 0, Data);
   Lemma_Final_Of (After_Update, Key, C, M, Length);
end Hash_In_One_Piece;
```

Chaining `Lemma_Append` and `Lemma_Init` directly does not prove, because
the contexts are compared as values the provers do not see as one term;
`Lemma_Update_Of` and `Lemma_Final_Of` exist for that.

Two things to get right in your own proofs:
- the last piece's `Joined` is the message itself, not a slice of all of
  it, so that `Lemma_Final` applies to the message you prove things
  about;
- offsets from `Message'First` keep the bounds arithmetic clear of
  overflow on empty arrays.

## What is proven, what is tested, what is trusted

| Property | How it is established |
|---|---|
| G, rounds, compression and one-shot `Hash` equal the specification | **Proof** (GNATprove, functional postconditions) |
| No run-time error anywhere in the library | **Proof** (SPARK Silver) |
| `Init`, `Update`, `Final` each compute exactly their counterpart in `Spec.Incremental` | **Proof**, for every input up to RFC 7693's 2¹²⁸ − 1 bytes, the 128-bit counter's carry included; and tested |
| The 128-bit counter adds correctly | **Proof** against arithmetic on mathematical integers, not only against the model |
| Incremental hashing equals one-shot hashing, however the message is cut | **Proof** for every message one `Byte_Array` can hold, which is at most 2³¹ bytes, `Spec.Hash`'s own domain (`Spec.Incremental`'s lemmas; `Theorem_Incremental` for the real procedures); and tested (22 000 random chunkings, plus one 1 MiB update). Beyond that, the steps are still proven equal to the model; for streams of up to 2³⁴ + 36 bytes cut into any pieces, per-call lemmas and a proved loop (`Blake2b.Streaming`) give the end-to-end statement. The tests hash many cuts of messages up to 300 bytes and two long streams (2³² + 129 and 2³⁴ + 36 bytes) against two C implementations; they do not run the ghost `Logical_Hash` |
| The specification equals BLAKE2b | Tested: RFC vector, 512 known answers, two C implementations, 20 000 HACL* vectors |
| Same digests at -O0, -O2, -O3, with checks off and on | Tested: build matrix |
| Each layer catches the faults it should | Tested: mutation suite |
| No branch or memory index depends on key or message in the exercised cases | Tested: Valgrind memcheck on isolated plain and hardened builds, with deliberate secret-branch controls (Linux x86-64 CI) |
| State is wiped by `Final` and `Clear` | Proof (postconditions) and test; wipes checked present in release object code |
| After a normal return of `Init`, `Update`, `Final` or `Hash`, no key, message or chaining-value word is left on the stack | Tested: stack scan (26 scenarios, each against a control that does leave canaries), and checked in object code. Not proved; exceptions and task abort are not claimed |

**What the proof rests on** (the trusted base): GNATprove 16.1.0 with
Why3 and the Z3, CVC5 and Alt-Ergo provers; the GNAT/GCC compiler; the
Ada runtime, including GNATprove's model of the standard big-integer
library, which is used only in proofs and compiled into no release
build; and the specification itself, which is validated by the tests
above, not proven. [TRUST.md](TRUST.md) is the register of all of it, with the warning
suppressions; it carries no signatures yet. Releases before 0.1.1 also
trusted three imported ghost functions (`Blake2b.Core.Same`, `Same8`,
`Same_Block`) that this list did not name; 0.1.1 replaces them with
functions GNATprove checks. A proof shows the code equals the specification;
only testing can show the specification equals BLAKE2b.

**What the wipes promise.** The wipe postconditions are proved, but they
speak only about the value of an object. That no copy survives in a
register or on the stack is addressed separately, and checked in object
code rather than proved:
- wipe routines that are never inlined and never subject to
  interprocedural analysis;
- GCC stack scrubbing (`strub`) of the body it wraps. `strub` scrubs only
  that stack, not the frames of callees outside the body (`memcpy`,
  `memmove`, `memset`, the wipe routines; the stack scan below finds no
  canary in them, which is the only evidence), so the compression function
  is `Inline_Always` and the four hardened entry points are `flatten`ed:
  its message words and working vector live in the scrubbed frame. (Up to
  0.1.1 it was a function of its own, and one message word could remain in
  its frame after a normal return.) `scripts/check-hardening.sh` fails if
  any function other than the entry points, their clones and the
  accessors that handle no secret is defined in `blake2b-hashing.o`, or if
  `Compress` has a symbol or is called. The leaf C library routines
  `memcpy`, `memmove` and `memset` may still be called from inside an
  entry point; they run inside the call, whose return zeroes every
  call-used register, and are listed by the check;
- zeroing of **every** call-used register on return
  (`zero_call_used_regs ("all")`), including those only the compression
  function used. `"used"` would clear only the entry point's own
  registers, and an external review found key-derived values left in
  vector registers after `Final` that way. `scripts/check-hardening.sh`
  checks each hardened entry point's object code against the registers
  GCC clears for that target.

Callee-saved registers aren't zeroed: by the ABI, every function that
uses them restores the caller's values before returning.

The register claim is for the registers the compiler's target description
names, which is what `zero_call_used_regs` zeroes and what the check reads.
Registers outside that view are not covered: on Linux x86-64 with AVX-512,
the C library's `memcpy` and `memmove` may use `ymm16`-`ymm31`, which the
baseline x86-64 target does not name, so key or message bytes copied by them
could remain there (inferred, not measured); on AArch64 the upper halves of
`v8`-`v15` are neither zeroed nor restored (the shipped object uses none of
them). The claim covers the release profile (checks and contracts off). A
contracts-enabled build evaluates the specification on the secrets, outside
the scrubbed bodies, and is for testing only.

**What is measured, and what is not claimed.** `scripts/check-stack-scan.sh`
fills key, message and chaining-value words with recognisable values,
calls each entry point (one-shot with and without key and prefix, `Init`,
`Update`, `Final` and `Clear`, at lengths from 0 to 1000 bytes, including
a full and a one-byte final block), and counts the values left on the
stack below the caller afterwards. Any of those values left after a normal
return fails the scan. It looks for whole eight-byte words, so a partial
word or a value derived from them (an intermediate of the compression)
would not be recognised. The region it reads is at least 24 KiB and is
doubled while the deepest non-zero byte found is near its end, so it is
sized from what was left, not from the deepest frame written. Every verdict has a control: the same build with `strub`
and `zero_call_used_regs` removed must leave values (on macOS arm64 it does, in 21 of
the 26 scenarios), or, where the call leaves none even unhardened, a
deliberate spill of the secrets into a volatile local must be found in
the control and not in the hardened build. `scripts/test-check-stack-scan.sh`
shows the scan fails when `Update`'s `strub` is removed and when the
compression function is put back out of line (removing `flatten` alone is
caught by the source check, not by the scan). Not claimed: an exception
(measured and reported, not gated: values do remain after one), a task
abort, `Clear` (it has no `strub`; it reads no secret), the one-shot
`Hash` wrappers (they are not hardened themselves; they call `Digest_Of`,
which is, and are measured through the public calls), and callee-saved
registers. That `flatten` is on each entry point is checked in the source,
because at `-O3 -gnatn` the compiler inlines the helpers anyway and the
object cannot show it missing. The x86-64 red zone (a leaf function may
use stack below the stack pointer) is argued in the scan's header, not
measured. The checks run on all four platforms in CI; the allow-lists in
`check-hardening.sh` were derived on macOS arm64.

## How the proof is structured

- `Blake2b.Spec` (ghost): RFC 7693 sections 2–3, written to be read
  against the RFC. G, Round, Rounds, Compress, the parameter block, the
  padded input (`Byte_At`, one byte at a time, without building
  concatenations), the fold over blocks, the final block, and the digest.
- `Blake2b.Core`: the compression function, each piece with a
  postcondition equal to its specification counterpart. The message
  schedule is transcribed independently (twelve rows, as the reference C
  has, against the RFC's ten), and a lemma proves the two transcriptions
  agree.
- `Blake2b.Spec.Incremental` (ghost): what an incremental hash does to
  its context (chaining value, 128-bit counter, buffered bytes), as
  functions in the shape of the reference implementation's
  `blake2b_init`, `blake2b_update` and `blake2b_final`. It is not part of
  the RFC, so it is not trusted. Two lemmas prove it computes
  `Spec.Hash`:
  - `Lemma_Update`: absorbing `Data` into the context of `Before` gives
    the context of `Before` followed by `Data`;
  - `Lemma_Final`: finishing the context of a message gives `Spec.Hash`
    of it.
- `Blake2b.Streaming` (and its children `Theory`, `Consistency`, `Example`):
  the whole-stream statement above, for streams longer than one array.
- `Blake2b.Hashing`: `Init`, `Update` and `Final` are proved to compute
  exactly `Spec.Incremental`'s functions of `Model (S)`, a proof-only view
  of the state. `Theorem_Incremental` puts it all together: for every
  key, digest length, message and way of cutting the message into pieces,
  the real procedures produce `Spec.Hash` of the message.
- `Blake2b.Hashing.Counter_Arithmetic` (private): the 128-bit counter's
  addition, proved against mathematical integers and against the model's
  `Plus`. It is a unit of its own so that it is proved under the default
  step budget (`blake2b-hashing.adb` has ten times as much for its
  theorems; under that budget a prover can run on for hours on a false
  counter goal, so a dropped carry could not be shown caught). It is
  `Inline_Always`, so it runs inside the scrubbed bodies, and
  `scripts/check-hardening.sh` fails if its object defines any function.
- Composition: function bodies are hidden from the provers except where
  they are the thing being proved, and an extensionality lemma turns
  element-wise array equality into logical equality, so each step
  composes into the next by substitution.
- No `pragma Assume`, no justified checks, nothing skipped, no `Import`
  anywhere in `src/`; CI enforces this with `scripts/check-sources.sh`,
  which also checks that `TRUST.md` has one row per warning suppression
  (a count, not a match of locations). Provers are bounded by steps, not
  time, so a proof result is the same on every machine.

## Building

With [Alire](https://alire.ada.dev) 2.1.1 or later:

```sh
alr build            # the library; dependents get -O3 -gnatn -gnatp
```

The release profile builds without run-time checks (`-gnatp`): the
Silver proof covers every check that removes.

## Proving

GNATprove is a dependency of the nested `tests/` crate only, so the
library's own manifest stays free of it:

```sh
cd tests
alr build            # generate the library configuration and build dependencies
alr exec -- gnatprove -P ../blake2b.gpr -j0
```

Expected: `all checks proved`.

## Testing

```sh
cd tests
alr build
./bin/profile-profile/test_main       # about 12.5 million checks
cd ..
scripts/matrix.sh                     # seven build configurations
scripts/mutants.sh                    # thirty deliberate faults
scripts/check-hardening.sh            # wipes and scrubbing in object code
scripts/test-check-hardening-negative.sh  # the check fails when a hardening is removed
scripts/check-stack-scan.sh           # nothing left on the stack after a normal return
scripts/test-check-stack-scan.sh      # the scan fails when strub or the inlining is removed
scripts/check-constant-time.sh        # Linux x86-64, needs Valgrind headers
scripts/check-sources.sh              # no proof escape hatches (Import too)
```

The suite checks:
- the specification and the implementation against the RFC vector, the
  512 known answers (whose SHA-256 is pinned), and both C oracles, over
  lengths 0..1024 × keys of 0, 1, 32, 63, 64 bytes × digests of 1, 20,
  32, 48, 63, 64 bytes;
- 100 000 seeded random cases;
- with `--vectors`, any file of vectors in the same layout: CI generates
  20 000 with CPython 3.14, whose `hashlib.blake2b` is HACL*'s formally
  verified implementation (`scripts/cpython-vectors.py`), and checks the
  specification and the implementation against every one;
- the two-part hash at a random split point of each of many messages;
- arbitrary array bounds, including the top of the index range;
- incremental hashing over random chunkings, against one-shot hashing
  and the C reference;
- the incremental model run on its own against `Spec.Hash`, and the
  implementation against the model after every step;
- wiping, and, in the contracts-enabled build, misuse being rejected.

The mutation suite applies thirty single-site faults to a scratch copy:
fourteen in the code and its models, sixteen in the streaming theory.
It checks that each is caught by the proof, the tests, or both, as
expected. The two carry faults, `carry` and `plus-carry`, are judged as
strictly as the theory faults below, in the counter's own unit: each must
leave its unproved check there, failed within the step budget. (Up to 0.1.1
the counter was proved under `blake2b-hashing.adb`'s larger budget, where
Alt-Ergo ran past any memory guard on them, so neither was ever shown
caught.) The fourteen:
- rotation constants, a schedule entry, an IV word, the parameter block,
  the final-block flag, the keyed counter, digest truncation, the
  last-block rule, and a fault in the specification;
- `Update` buffering zeroes instead of the input, and an off-by-one in
  the incremental model;
- the counter's carry dropped from the code, and from the model's counter,
  each caught by the proof and by a test that calls the counter's addition
  and the model's `Plus` directly (through the public interface a carry
  takes 2^64 bytes);
- one that only the proof can catch: the proof model seeing the leftover
  bytes past the buffer (the tests execute their own copy of the model).

The sixteen theory faults are proof-only, because no build compiles the
theory. Each must leave an unproved check inside the unit named for it
(the unit it mutates, except for the witness that shrinks the domain, which
mutates `Blake2b.Streaming` and is judged in `Example`), and that check must fail within the step budget: a prover killed by the time or
memory guard counts as tainted, not as a catch. They cover the counter, the
key padding, the final flag, the buffer boundary, a lemma call removed, the
worked example and the full-length witness. Before they run, every check of
the theory must cost at most half its 10 000-step budget under its cheapest
prover. Two known gaps: removing the `Lemma_Room` call in `Run_Loop` is not
caught, because the provers see the private completion of
`Blake2b.Hashing.Max_Input`; and ablating the padding fact at loop level
exhausts time or memory rather than steps, so only the per-byte ablation is
kept. The script is run by hand, locally and in the Linux images, not in CI.

The constant-time gate marks key and message contents undefined for Valgrind
Memcheck while their lengths stay public. It exercises both `Hash` overloads
and incremental `Init`, `Update`, and `Final`, over message lengths of 0, 1,
64, 127, 128, 129, 255, 1 000, and 4 096 bytes and keys of 0, 32, and 64
bytes, with a 64-byte digest. This is a dynamic check of those paths, not a
mathematical proof of constant time or a measurement of CPU timing.

`scripts/check-constant-time.sh` creates separate source snapshots under
`obj/constant-time/plain/` and `obj/constant-time/hardened/`. It force-builds
both at the library's release switches. Only the plain snapshot receives
`-fstrub=disable`; the hardened snapshot keeps the shipped stack scrubbing
and register clearing. These objects cannot enter a production build.
`scripts/check-hardening.sh` continues to check the production objects.

Both Memcheck runs use no suppressions. The plain run rejects every reported
error. For the hardened run, `scripts/ct-valgrind.py` accepts only specific
eight-byte writes below the current stack pointer when their exact reported
instruction addresses match the expected compiler-generated zeroing loops
in the five hashing wrappers. Unexpected memory errors, secret-dependent
branches, and secret-dependent memory addresses fail. Changes to the emitted
scrubbing sequence therefore need fresh inspection rather than a broader
function-wide exception. XML reports, disassembly, binaries, and build logs
are retained under the snapshots; CI uploads the log directories even on
failure.
Reports retain raw ELF symbol names so overloaded Ada entry points stay
distinct and match the disassembly across Valgrind versions.

Each build also runs the complete hashing workload with
`--negative-control`, then deliberately branches on a poisoned byte in
`ct_negative_branch`. The report checker must detect that branch while still
rejecting any unrelated errors. A missing branch report fails the gate, so
the workaround cannot silently turn off secret-use checking. `ALR`,
`VALGRIND`, `PYTHON`, and `OBJDUMP` can select executable paths when needed.

## Benchmarks

`tests/bin/profile-profile/bench_main`: BLAKE2b-512, unkeyed, one-shot,
against the BLAKE2 reference C compiled by the same GCC at the same
`-O3`. Median of 7 runs, Windows 11 x86_64, GNAT 16.1.0:

| Message | blake2b | reference C | time ratio |
|---|---|---|---|
| 64 B | 256 MB/s | 356 MB/s | 1.39 |
| 1 KiB | 728 MB/s | 806 MB/s | 1.11 |
| 64 KiB | 753 MB/s | 817 MB/s | 1.09 |
| 1 MiB | 711 MB/s | 773 MB/s | 1.09 |

These figures include the hardening, which the reference does not do.
Since 0.1.2-dev the compression function is inlined into the entry points
(see "What the wipes promise"). Measured on macOS arm64 against 0.1.1, not
on the machine of this table: bulk data about 3-4% faster, 1 KiB the same,
64 bytes about 6.5% slower, and `blake2b-hashing.o` about six times larger
(35 KB of code, five copies of the unrolled rounds). The table above
predates that change.
Stack scrubbing and register zeroing cost about 0.15× at 64 bytes, a
fixed cost per call, and nothing measurable on bulk data. Wall-clock
figures vary with the machine, so CI gates the deterministic figure
instead: the ratio of instructions executed, measured with callgrind.

## Vendored / third-party

Test-only; none of it is linked into the library:
- `tests/ref/blake2b-ref.c`, `blake2.h`, `blake2-impl.h` and
  `tests/data/blake2-kat.json`, from the BLAKE2 team's repository
  (CC0 1.0, see `tests/ref/BLAKE2-COPYING`);
- `tests/ref/monocypher.c` and `monocypher.h`, Monocypher 4.0.3
  (CC0 1.0 or BSD-2-Clause, see `tests/ref/MONOCYPHER-LICENCE.md`).

Sources and SHA-256 digests are pinned in `tests/ref/SOURCES.md`.

## Status & roadmap

Current version: **0.1.1** (2026-10-14). Previous release: 0.1.0 (2026-10-07).

Next:
- coverage-guided fuzzing, using AFL++'s GCC plugin built against
  GNAT 16;
- an external review.

`argon2` (Argon2, RFC 9106) builds on this crate.

## License

BSD-3-Clause: see [LICENSE](LICENSE).
