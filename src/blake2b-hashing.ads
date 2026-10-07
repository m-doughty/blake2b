--  BLAKE2b (RFC 7693) in SPARK: the public interface.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  Postconditions below take 'Old of function results (State is limited,
--  so S'Old is not available). Those prefixes are evaluated on entry,
--  where each function's precondition is already guaranteed by the
--  subprogram's own.
pragma Unevaluated_Use_Of_Old (Allow);

--  The incremental interface's postconditions have two parts:
--  * Executable: checked at run time in builds with assertions enabled
--    (-gnata), like any contract, and proved;
--  * Static: proved by GNATprove, never compiled into any build (they
--    describe the state through Model, which exists only for the proof).
pragma Assertion_Level (Executable);

with Ada.Numerics.Big_Numbers.Big_Integers;
use Ada.Numerics.Big_Numbers.Big_Integers;

with Blake2b.Spec;
with Blake2b.Spec.Incremental;
use type Blake2b.Spec.Incremental.Context;

--  Both interfaces are proved to compute exactly what Blake2b.Spec, a
--  transcription of RFC 7693, says:
--
--  * one-shot hashing (Hash): Digest = Spec.Hash (Message, Key, ...);
--  * incremental hashing (Init, Update, Final): each step computes
--    exactly the corresponding function of Blake2b.Spec.Incremental, and
--    Init, any sequence of Updates and Final compute Spec.Hash of
--    everything absorbed (Theorem_Incremental, below).
--
--  All of it is also proved free of run-time errors.
--
--  A digest is 1 .. 64 bytes; its length is the length of the Digest
--  array passed in. A key is 0 .. 64 bytes; pass No_Bytes for unkeyed
--  hashing. Arrays may have any bounds.

package Blake2b.Hashing
  with SPARK_Mode
is

   ----------------------------------------------------------------------
   --  One-shot hashing
   ----------------------------------------------------------------------

   --  BLAKE2b of Message, keyed with Key.
   procedure Hash
     (Message : Byte_Array;
      Key     : Byte_Array;
      Digest  : out Byte_Array)
   with Global => null,
        Pre    => Key'Length <= Max_Key_Bytes
                  and then Digest'Length in 1 .. Max_Digest_Bytes,
        Post   => Digest = Spec.Hash (Message, Key, Digest'Length);

   --  BLAKE2b of Prefix followed by Message, keyed with Key, without
   --  building the concatenation. (Argon2's variable-length hash H' is
   --  BLAKE2b of a 4-byte length prefix followed by its input.)
   procedure Hash
     (Prefix  : Byte_Array;
      Message : Byte_Array;
      Key     : Byte_Array;
      Digest  : out Byte_Array)
   with Global => null,
        Pre    => Key'Length <= Max_Key_Bytes
                  and then Digest'Length in 1 .. Max_Digest_Bytes,
        Post   => Digest
                  = Spec.Hash2 (Prefix, Message, Key, Digest'Length);

   ----------------------------------------------------------------------
   --  Incremental hashing
   ----------------------------------------------------------------------

   --  A hash in progress. Limited, so it (and the key material in it)
   --  cannot be copied. Default-initialised states are Empty.
   type State is limited private
   with Default_Initial_Condition => Is_Empty (State);

   function Is_Empty (S : State) return Boolean;
   function Is_Absorbing (S : State) return Boolean;
   function Is_Finalized (S : State) return Boolean;

   --  The digest length chosen at Init.
   function Output_Length (S : State) return Digest_Length
   with Pre => Is_Absorbing (S);

   --  Mathematical integers for the size bound below. Ghost, so release
   --  builds contain none of it (no big-integer code, no heap, no
   --  finalisation).
   package Big
     with Ghost
   is
      package Lengths is new Signed_Conversions (I64);
      package Words is new Unsigned_Conversions (U64);
      function Length (N : I64) return Big_Integer
        renames Lengths.To_Big_Integer;
      function Word (W : U64) return Big_Integer
        renames Words.To_Big_Integer;
   end Big;

   --  The number of input bytes absorbed so far, counting a key as one
   --  full block (128 bytes), exactly as BLAKE2b's 128-bit offset counter
   --  does. RFC 7693 limits the input to less than 2**128 bytes; Max_Input
   --  is that limit.
   function Absorbed (S : State) return Big_Natural
   with Ghost,
        Pre => Is_Absorbing (S);

   function Max_Input return Big_Positive
   with Ghost;

   ----------------------------------------------------------------------
   --  Proof model of incremental hashing. Static ghost code: GNATprove
   --  proves it, and no build ever compiles it (so it costs nothing, and
   --  client code built with assertions enabled cannot fail to link
   --  against it). Client proofs refer to it from Static-level
   --  assertions: pragma Assert (Static => Has_Absorbed (...)).
   ----------------------------------------------------------------------

   --  The hash in progress as Blake2b.Spec.Incremental describes it: the
   --  chaining value, the counter, the buffered bytes and the digest
   --  length.
   function Model (S : State) return Spec.Incremental.Context
   with Ghost => Static,
        Pre   => Is_Absorbing (S),
        Post  => Model'Result.NN = Output_Length (S);

   --  S has absorbed exactly Message (in pieces of any sizes) since
   --  Init (S, Output_Length (S), Key).
   function Has_Absorbed (S : State; Key, Message : Byte_Array)
      return Boolean
   is
     (Model (S)
      = Spec.Incremental.After_Absorbing (Key, Message, Output_Length (S)))
   with Ghost => Static,
        Pre   => Is_Absorbing (S) and then Key'Length <= Max_Key_Bytes;

   --  Starts a hash of Length bytes, keyed with Key (No_Bytes if
   --  unkeyed). Any state may be re-initialised.
   procedure Init
     (S      : out State;
      Length : Digest_Length;
      Key    : Byte_Array)
   with Global => null,
        Pre    => Key'Length <= Max_Key_Bytes,
        Post   =>
          (Executable =>
             Is_Absorbing (S)
             and then Output_Length (S) = Length
             and then Absorbed (S)
                      = (if Key'Length > 0 then To_Big_Integer (128)
                         else To_Big_Integer (0)),
           Static     =>
             Model (S) = Spec.Incremental.Init (Key, Length));

   --  Absorbs Data, which may be any length, including zero.
   procedure Update (S : in out State; Data : Byte_Array)
   with Global => null,
        Pre    => Is_Absorbing (S)
                  and then Absorbed (S) + Big.Length (Data'Length)
                           <= Max_Input,
        Post   =>
          (Executable =>
             Is_Absorbing (S)
             and then Output_Length (S) = Output_Length (S)'Old
             and then Absorbed (S)
                      = Absorbed (S)'Old + Big.Length (Data'Length),
           Static     =>
             Model (S) = Spec.Incremental.Update (Model (S)'Old, Data));

   --  Writes the digest and wipes the state.
   procedure Final (S : in out State; Digest : out Byte_Array)
   with Global => null,
        Pre    => Is_Absorbing (S)
                  and then Digest'Length = Output_Length (S),
        Post   =>
          (Executable => Is_Finalized (S),
           Static     => Digest = Spec.Incremental.Final (Model (S)'Old));

   --  Wipes a state, for instance one abandoned before Final.
   procedure Clear (S : in out State)
   with Global => null,
        Post   => Is_Empty (S);

   --  The two steps of a client proof that an incremental hash computes
   --  Spec.Hash of the bytes it absorbed. The client keeps those bytes as
   --  its own ghost value (Before), and calls:
   --
   --  * Lemma_Update before each Update (S, Data), with Joined being
   --    Before followed by Data (any array with those contents: a longer
   --    slice of the same message, or a ghost concatenation). After the
   --    Update, Has_Absorbed (S, Key, Joined) holds. The lemma also
   --    discharges Update's precondition.
   --  * Lemma_Final before Final: the digest is then Spec.Hash.
   --
   --  Right after Init (S, Length, Key), Has_Absorbed (S, Key, M) holds
   --  for every empty M. Theorem_Incremental is a worked example.
   procedure Lemma_Update
     (S : State; Key, Before, Data, Joined : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Is_Absorbing (S)
                  and then Key'Length <= Max_Key_Bytes
                  and then Spec.Incremental.Is_Concatenation
                             (Joined, Before, Data)
                  and then Has_Absorbed (S, Key, Before),
        Post   => Spec.Incremental.Update (Model (S), Data)
                  = Spec.Incremental.After_Absorbing
                      (Key, Joined, Output_Length (S))
                  and then Absorbed (S) + Big.Length (Data'Length)
                           <= Max_Input;

   procedure Lemma_Final (S : State; Key, Message : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Is_Absorbing (S)
                  and then Key'Length <= Max_Key_Bytes
                  and then Has_Absorbed (S, Key, Message),
        Post   => Spec.Incremental.Final (Model (S))
                  = Spec.Hash (Message, Key, Output_Length (S));

   --  Theorem: incremental hashing computes BLAKE2b. For every key,
   --  digest length and message, and every way of cutting the message
   --  into consecutive pieces, Init, one Update per piece and Final
   --  produce Spec.Hash (Message, Key, Digest'Length).
   --
   --  Cuts are offsets into Message (0 .. Message'Length), in order: the
   --  pieces are Message's bytes from one cut to the next, with the
   --  message's start before the first cut and its end after the last.
   --  Repeated cuts give empty pieces.
   --
   --  Message is one Byte_Array, so the theorem covers messages under
   --  2**31 bytes: Spec.Hash's own domain. Longer streams (up to RFC
   --  7693's 2**128 - 1 bytes) are still covered step by step, by the
   --  Static postconditions of Update and Final, but no statement can name
   --  their whole contents. See the README.
   type Cut_Points is array (Positive range <>) of I64
   with Ghost => Static;

   procedure Theorem_Incremental
     (Message : Byte_Array;
      Key     : Byte_Array;
      Cuts    : Cut_Points;
      Digest  : out Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Key'Length <= Max_Key_Bytes
                  and then Digest'Length in 1 .. Max_Digest_Bytes
                  and then (for all I in Cuts'Range =>
                              Cuts (I) in 0 .. Message'Length)
                  and then (for all I in Cuts'Range =>
                              (if I > Cuts'First
                               then Cuts (I - 1) <= Cuts (I))),
        Post   => Digest = Spec.Hash (Message, Key, Digest'Length);

private

   use type U64;

   --  Hardening for the subprograms that handle keys and input: GCC's
   --  stack scrubbing (the stack the call and its callees used is zeroed
   --  on return), and zeroing of every call-used register on return.
   --  "all", not "used": "used" clears only the registers the subprogram
   --  itself used, and leaves whatever its callees (the compression
   --  function) left in the others. scripts/check-hardening.sh checks the
   --  object code. See Blake2b.Wipe.
   pragma Warnings
     (GNATprove, Off, "pragma ""Machine_Attribute"" ignored*",
      Reason => "code-generation attribute: no effect on proof");
   pragma Machine_Attribute (Init, "strub", "internal");
   pragma Machine_Attribute (Init, "zero_call_used_regs", "all");
   pragma Machine_Attribute (Update, "strub", "internal");
   pragma Machine_Attribute (Update, "zero_call_used_regs", "all");
   pragma Machine_Attribute (Final, "strub", "internal");
   pragma Machine_Attribute (Final, "zero_call_used_regs", "all");
   pragma Warnings
     (GNATprove, On, "pragma ""Machine_Attribute"" ignored*");

   type Phase_Kind is (Empty, Absorbing, Finalized);

   subtype Buffer_Length is I64 range 0 .. Block_Bytes;

   --  H: chaining value. (T_Hi, T_Lo): BLAKE2b's 128-bit offset counter,
   --  the number of bytes compressed so far. Buf (0 .. Buf_Len - 1):
   --  bytes absorbed but not yet compressed; the last block is always
   --  kept here for Final, never compressed by Update. Bytes of Buf past
   --  Buf_Len are leftovers, never read.
   type State is limited record
      H       : Words8 := [others => 0];
      T_Lo    : U64 := 0;
      T_Hi    : U64 := 0;
      Buf     : Block := [others => 0];
      Buf_Len : Buffer_Length := 0;
      NN      : Digest_Length := Max_Digest_Bytes;
      Phase   : Phase_Kind := Empty;
   end record;

   --  The proof model of the counter, in mathematical integers. Ghost:
   --  only contracts ever evaluate it, never ordinary code.
   function Two_64 return Big_Positive is
     (Big.Word (U64'Last) + 1)
   with Ghost;

   function Two_128 return Big_Positive is (Two_64 * Two_64)
   with Ghost;

   function Max_Input return Big_Positive is (Two_128 - 1);

   --  The 128-bit counter as a number.
   function Counter (S : State) return Big_Natural is
     (Big.Word (S.T_Hi) * Two_64 + Big.Word (S.T_Lo))
   with Ghost;

   --  The invariant every absorbing state keeps, in plain 64-bit
   --  arithmetic so that the typestate predicates are cheap ordinary
   --  code:
   --  * only whole blocks have been compressed;
   --  * the last block is held back: if nothing is buffered, nothing has
   --    been compressed yet (so Final always has a block to finish);
   --  * the input stays within RFC 7693's limit, so the counter is exact:
   --    counter + buffered <= 2**128 - 1, which (with T_Lo a multiple of
   --    128 and Buf_Len <= 128) is exactly the condition below.
   function Valid (S : State) return Boolean is
     (S.T_Lo mod Block_Bytes = 0
      and then (if S.Buf_Len = 0 then S.T_Lo = 0 and then S.T_Hi = 0)
      and then (S.T_Hi < U64'Last
                or else S.T_Lo <= U64'Last - U64 (S.Buf_Len)));

   function Is_Empty (S : State) return Boolean is (S.Phase = Empty);

   function Is_Absorbing (S : State) return Boolean is
     (S.Phase = Absorbing and then Valid (S));

   function Is_Finalized (S : State) return Boolean is
     (S.Phase = Finalized);

   function Output_Length (S : State) return Digest_Length is (S.NN);

   function Absorbed (S : State) return Big_Natural is
     (Counter (S) + Big.Length (S.Buf_Len));

   --  The leftover bytes past Buf_Len are zero in the model, as the
   --  model's buffer always is.
   function Model (S : State) return Spec.Incremental.Context is
     ((H       => S.H,
       T       => (Lo => S.T_Lo, Hi => S.T_Hi),
       Buf     => [for J in Block_Index =>
                     (if J < S.Buf_Len then S.Buf (J) else 0)],
       Buf_Len => S.Buf_Len,
       NN      => S.NN));

end Blake2b.Hashing;
