# blake2b_spark

**blake2b_spark**: BLAKE2b (RFC 7693) in SPARK, proven to compute
exactly what the RFC specifies.

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
- **The specification is tested, not trusted:** against the RFC's test
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
cover messages under 2³¹ bytes (2 GiB). That's the same domain as
`Spec.Hash` itself, and so the same as the one-shot proof. A stream
absorbed in pieces can be longer, up to RFC 7693's 2¹²⁸ − 1 bytes. For
those streams every step is still proven:
- each `Update` and the `Final` equal `Spec.Incremental`'s functions;
- the 128-bit counter is exact, carry included.

What no proof states for them is the end-to-end "this equals BLAKE2b of
the whole stream", because no array can hold the whole stream to name it.
That's a limit on what the proof can express, not evidence that longer
streams hash differently: the code that runs is the same.

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
| Incremental hashing equals one-shot hashing, however the message is cut | **Proof** for every message one `Byte_Array` can hold, which is under 2³¹ bytes, `Spec.Hash`'s own domain (`Spec.Incremental`'s lemmas; `Theorem_Incremental` for the real procedures); and tested (22 000 random chunkings, plus one 1 MiB update). Beyond that, the steps are still proven equal to the model, but the theorem can't name the whole stream (see below) |
| The specification equals BLAKE2b | Tested: RFC vector, 512 known answers, two C implementations, 20 000 HACL* vectors |
| Same digests at -O0, -O2, -O3, with checks off and on | Tested: build matrix |
| Each layer catches the faults it should | Tested: mutation suite |
| No branch or memory index depends on key or message in the exercised cases | Tested: Valgrind memcheck on isolated plain and hardened builds, with deliberate secret-branch controls (Linux x86-64 CI) |
| State is wiped by `Final` and `Clear` | Proof (postconditions) and test; wipes checked present in release object code |

**What the proof rests on** (the trusted base): GNATprove 16.1.0 with
Why3 and the Z3, CVC5 and Alt-Ergo provers; the GNAT/GCC compiler; the
Ada runtime, including GNATprove's model of the standard big-integer
library, which is used only in proofs and compiled into no release
build; and the specification itself, which is validated by the tests
above, not proven. A proof shows the code equals the specification;
only testing can show the specification equals BLAKE2b.

**What the wipes promise.** The wipe postconditions are proved, but they
speak only about the value of an object. That no copy survives in a
register or on the stack is addressed separately, and checked in object
code rather than proved:
- wipe routines that are never inlined and never subject to
  interprocedural analysis;
- GCC stack scrubbing (`strub`) of everything the call used;
- zeroing of **every** call-used register on return
  (`zero_call_used_regs ("all")`), including those only the compression
  function used. `"used"` would clear only the entry point's own
  registers, and an external review found key-derived values left in
  vector registers after `Final` that way. `scripts/check-hardening.sh`
  checks each hardened entry point's object code against the registers
  GCC clears for that target.

Callee-saved registers aren't zeroed: by the ABI, every function that
uses them restores the caller's values before returning.

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
- `Blake2b.Hashing`: `Init`, `Update` and `Final` are proved to compute
  exactly `Spec.Incremental`'s functions of `Model (S)`, a proof-only view
  of the state. `Theorem_Incremental` puts it all together: for every
  key, digest length, message and way of cutting the message into pieces,
  the real procedures produce `Spec.Hash` of the message.
- Composition: function bodies are hidden from the provers except where
  they are the thing being proved, and an extensionality lemma turns
  element-wise array equality into logical equality, so each step
  composes into the next by substitution.
- No `pragma Assume`, no justified checks, nothing skipped; CI enforces
  this with `scripts/check-sources.sh`. Provers are bounded by steps, not
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
alr exec -- gnatprove -P ../blake2b_spark.gpr -j0
```

Expected: `all checks proved`.

## Testing

```sh
cd tests
alr build
./bin/profile-profile/test_main       # about 300 000 checks
cd ..
scripts/matrix.sh                     # seven build configurations
scripts/mutants.sh                    # fourteen deliberate faults
scripts/check-hardening.sh            # wipes and scrubbing in object code
scripts/check-constant-time.sh        # Linux x86-64, needs Valgrind headers
scripts/check-sources.sh              # no proof escape hatches
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
- the two-part hash at every split point;
- arbitrary array bounds, including the top of the index range;
- incremental hashing over random chunkings, against one-shot hashing
  and the C reference;
- the incremental model run on its own against `Spec.Hash`, and the
  implementation against the model after every step;
- wiping, and, in the contracts-enabled build, misuse being rejected.

The mutation suite applies fourteen single-line faults to a scratch copy.
It checks that each is caught by the proof, the tests, or both, as
expected:
- rotation constants, a schedule entry, an IV word, the parameter block,
  the final-block flag, the keyed counter, digest truncation, the
  last-block rule, and a fault in the specification;
- `Update` buffering zeroes instead of the input, and an off-by-one in
  the incremental model;
- three that only the proof can catch:
  - the counter's carry dropped from the code;
  - the carry dropped from the model's counter;
  - the proof model seeing the leftover bytes past the buffer.

  A carry only happens after 2^64 bytes, which no test can reach, and the
  tests execute their own copy of the model.

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

| Message | blake2b_spark | reference C | time ratio |
|---|---|---|---|
| 64 B | 256 MB/s | 356 MB/s | 1.39 |
| 1 KiB | 728 MB/s | 806 MB/s | 1.11 |
| 64 KiB | 753 MB/s | 817 MB/s | 1.09 |
| 1 MiB | 711 MB/s | 773 MB/s | 1.09 |

These figures include the hardening, which the reference does not do.
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

Current version: **0.1.0** (2026-10-07).

Next:
- coverage-guided fuzzing, using AFL++'s GCC plugin built against
  GNAT 16;
- an external review.

`argon2id_spark` (Argon2id, RFC 9106) builds on this crate.

## License

BSD-3-Clause: see [LICENSE](LICENSE).
