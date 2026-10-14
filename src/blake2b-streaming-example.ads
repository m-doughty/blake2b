--  BLAKE2b (RFC 7693) in SPARK: a long message hashed in pieces, worked
--  through with the real Init, Update and Final.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Ada.Numerics.Big_Numbers.Big_Integers;
use Ada.Numerics.Big_Numbers.Big_Integers;

with Blake2b.Hashing;
use Blake2b.Hashing;
with Blake2b.Streaming.Theory;
use Blake2b.Streaming.Theory;

--  How a client proves that streaming a logical message through
--  Blake2b.Hashing computes its logical hash, whatever the number and
--  sizes of the pieces:
--
--  * Run_Loop: Init, one Update per piece of an arbitrary schedule, and
--    Final, with a loop invariant relating Model (S) to the context of
--    the prefix absorbed so far (Logical_After). The digest is
--    Logical_Hash. Each Update's size precondition is discharged by
--    Lemma_Room.
--  * Witness: Run_Loop's premises hold at the full length, Max_Length
--    bytes, so its contract is not vacuous there.
--
--  "Any number of Updates" means this: the per-call lemmas of
--  Blake2b.Streaming.Theory, chained by induction over the client's
--  calls, as Run_Loop's loop does. It is not one quantified theorem.
--
--  Static ghost code: GNATprove proves it, and no build ever compiles it.
--  Every declaration is marked static ghost, and deliberately not the
--  package itself, so that its object file still holds one symbol, the
--  package's elaboration flag: a library member with no symbols makes
--  macOS ranlib print a warning on every build of the library.

package Blake2b.Streaming.Example
  with SPARK_Mode
is

   use type Inc.Context;

   --  Every piece fits one Byte_Array (Index is 0 .. 2**31 - 1).
   function Fits (M : Pieces) return Boolean is
     (for all I in M'Range => M (I).Count <= 2**31)
   with Ghost => Static;

   --  The bytes of piece I of M, as one array.
   function Piece_Data (C : Contents; M : Pieces; I : Positive)
      return Byte_Array
   is
     ([for J in 0 .. M (I).Count - 1 =>
         C (M (I).Source, M (I).Start + J)])
   with Ghost => Static,
        Pre   => Has_Contents (C)
                 and then I in M'Range
                 and then M (I).Count <= 2**31
                 and then M (I).Count <= 2**32 - M (I).Start;

   --  The array of piece I holds logical bytes M (I).First onwards.
   procedure Lemma_Piece
     (C      : Contents;
      M      : Pieces;
      Length : Offset;
      I      : Positive)
   with Ghost  => Static,
        Global => null,
        Pre    => Has_Contents (C)
                  and then Valid (M, Length)
                  and then I in M'Range
                  and then M (I).Count <= 2**31,
        Post   => Realizes (C, M, Length, M (I).First, Piece_Data (C, M, I));

   --  Update's size precondition, for any prefix of a logical message: a
   --  state that has absorbed the key block and the first L bytes has
   --  room for Len more whenever L + Len <= Max_Length.
   procedure Lemma_Room
     (S      : State;
      Key    : Byte_Array;
      L, Len : Offset)
   with Ghost  => Static,
        Global => null,
        Pre    => Is_Absorbing (S)
                  and then Key'Length <= Max_Key_Bytes
                  and then Absorbed (S) = Big.Length (KB (Key) + L)
                  and then Len <= Max_Length - L,
        Post   => Absorbed (S) + Big.Length (Len) <= Max_Input;

   --  Init, one Update per piece of M (any schedule of up to 2**31 - 2
   --  pieces, each up to one Byte_Array, empty pieces allowed) and
   --  Final give the logical hash of the whole message.
   procedure Run_Loop
     (Key    : Byte_Array;
      C      : Contents;
      M      : Pieces;
      Length : Offset;
      Digest : out Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Key'Length <= Max_Key_Bytes
                  and then Digest'Length in 1 .. Max_Digest_Bytes
                  and then Has_Contents (C)
                  and then Valid (M, Length)
                  and then Fits (M),
        Post   => Digest = Logical_Hash (Key, C, M, Length, Digest'Length);

   --  A message of 14 sources of 2**32 bytes, every byte V. (A function,
   --  not a static aggregate, which the compiler would try to fold.)
   function Filled (V : Byte) return Contents is
     ([for Id in Source_Id => [for P in Source_Position => V]])
   with Ghost => Static,
        Post  => Has_Contents (Filled'Result);

   --  A schedule of the full length, 2**34 + 36 bytes, over all 14
   --  sources: eight pieces of 2**31 bytes, one of 36, five empty.
   subtype Full_Pieces is Pieces (1 .. 14) with Ghost => Static;

   function Full_Schedule return Full_Pieces
   with Ghost => Static,
        Post  => Valid (Full_Schedule'Result, Max_Length)
                 and then Fits (Full_Schedule'Result);

   --  Run_Loop's premises hold at Length = Max_Length.
   procedure Witness (Key : Byte_Array; V : Byte; Digest : out Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Key'Length <= Max_Key_Bytes
                  and then Digest'Length in 1 .. Max_Digest_Bytes,
        Post   => Digest = Logical_Hash (Key, Filled (V), Full_Schedule,
                                         Max_Length, Digest'Length);

end Blake2b.Streaming.Example;
