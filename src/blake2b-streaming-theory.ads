--  BLAKE2b (RFC 7693) in SPARK: what Init, Update and Final do to a long
--  message hashed in pieces.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Blake2b.Spec;
with Blake2b.Spec.Incremental;

--  Over the logical message of Blake2b.Streaming (Key, Contents C, pieces
--  M, Length bytes), this package defines RFC 7693's padded block fold
--  and digest directly (Logical_Fold, Logical_Hash) and the incremental
--  context after the first L bytes (Logical_After), and proves, one call
--  at a time:
--
--  * Lemma_Init: Init gives the context of the empty prefix;
--  * Lemma_Append: Update with Data holding the next Data'Length bytes
--    takes the context of a prefix to the context of the longer prefix;
--  * Lemma_Logical_Final: Final of the whole message's context gives
--    Logical_Hash.
--
--  Lemma_Update_Of and Lemma_Final_Of are the same two steps for any
--  context equal to the prefix's, the form a client proof uses with
--  Blake2b.Hashing.Model. By induction over the client's calls, Init,
--  any number of Updates and Final compute Logical_Hash:
--  Blake2b.Streaming.Example is a worked example. Logical_Hash is
--  Blake2b.Spec.Hash wherever one Byte_Array holds the message
--  (Blake2b.Streaming.Consistency).
--
--  The fold is stated without Spec.Fold, whose message is one Byte_Array.
--  The counter's high word is zero throughout: the padded input is at
--  most 128 + Max_Length + 127 bytes.
--
--  Static ghost code: GNATprove proves it, and no build ever compiles it.
--  Every declaration is marked static ghost, and deliberately not the
--  package itself, so that its object file still holds one symbol, the
--  package's elaboration flag: a library member with no symbols makes
--  macOS ranlib print a warning on every build of the library.

package Blake2b.Streaming.Theory
  with SPARK_Mode, Pure
is

   package Inc renames Blake2b.Spec.Incremental;

   use type U64;
   use type Inc.Context;
   use type Inc.Counter;

   --  Logical equality of chaining values, blocks and contexts. Ada's "="
   --  on arrays reaches the provers as element-wise equality, which they
   --  will not substitute into an opaque function such as Spec.Compress;
   --  these are interpreted as logical equality, which they substitute
   --  freely. GNATprove checks each annotation against the function's
   --  body. (Blake2b.Core has the same two functions, privately.)
   function Same8 (L, R : Words8) return Boolean is (L = R)
   with Ghost    => Static,
        Annotate => (GNATprove, Logical_Equal);

   function Same_Block (L, R : Block) return Boolean is (L = R)
   with Ghost    => Static,
        Annotate => (GNATprove, Logical_Equal);

   procedure Lemma_Same8 (L, R : Words8)
   with Ghost  => Static,
        Global => null,
        Pre    => L = R,
        Post   => Same8 (L, R);

   procedure Lemma_Same_Block (L, R : Block)
   with Ghost  => Static,
        Global => null,
        Pre    => L = R,
        Post   => Same_Block (L, R);

   function Same_Context (L, R : Inc.Context) return Boolean is
     (Same8 (L.H, R.H)
      and then L.T.Lo = R.T.Lo
      and then L.T.Hi = R.T.Hi
      and then Same_Block (L.Buf, R.Buf)
      and then L.Buf_Len = R.Buf_Len
      and then L.NN = R.NN)
   with Ghost    => Static,
        Annotate => (GNATprove, Logical_Equal);

   procedure Lemma_Same_Context (L, R : Inc.Context)
   with Ghost  => Static,
        Global => null,
        Pre    => L = R,
        Post   => Same_Context (L, R);

   --  The premises every lemma below shares: a valid key, every source in
   --  full, and M a valid cut of the Length-byte message.
   function OK
     (Key    : Byte_Array;
      C      : Contents;
      M      : Pieces;
      Length : Offset) return Boolean
   is
     (Key'Length <= Max_Key_Bytes
      and then Has_Contents (C)
      and then Valid (M, Length))
   with Ghost => Static;

   --  The length of the padded key block: 128 if keyed, else 0.
   function KB (Key : Byte_Array) return I64 is
     (if Key'Length > 0 then Block_Bytes else 0)
   with Ghost => Static;

   --  The index of the block of the padded input that holds its first
   --  KB (Key) + L bytes' last byte: the block a context buffers after
   --  the first L bytes of the message (0 if there are none).
   function BB (Key : Byte_Array; L : Offset) return I64 is
     (if KB (Key) + L = 0 then 0 else (KB (Key) + L - 1) / Block_Bytes)
   with Ghost => Static;

   --  Byte J of RFC 7693's padded input d: the key, zero-padded to a
   --  block if keyed, then the message, then zeros.
   function D
     (Key    : Byte_Array;
      C      : Contents;
      M      : Pieces;
      Length : Offset;
      J      : I64) return Byte
   is
     (if J < KB (Key) then
        (if J < Key'Length then Key (Key'First + J) else 0)
      else Byte_At (C, M, Length, J - KB (Key)))
   with Ghost => Static,
        Pre   => OK (Key, C, M, Length)
                 and then J in 0 .. KB (Key) + Max_Length + 127;

   --  Block N of d.
   function Logical_Block
     (Key    : Byte_Array;
      C      : Contents;
      M      : Pieces;
      Length : Offset;
      N      : I64) return Block
   is
     ([for J in Block_Index => D (Key, C, M, Length, Block_Bytes * N + J)])
   with Ghost => Static,
        Pre   => OK (Key, C, M, Length) and then N in 0 .. BB (Key, Length);

   --  The chaining value after compressing blocks 0 .. N - 1 of d, from
   --  H, each as a non-final block with counter 128 (i + 1).
   function Logical_Fold
     (H      : Words8;
      Key    : Byte_Array;
      C      : Contents;
      M      : Pieces;
      Length : Offset;
      N      : I64) return Words8
   is
     (if N = 0 then H
      else Spec.Compress (Logical_Fold (H, Key, C, M, Length, N - 1),
                          Logical_Block (Key, C, M, Length, N - 1),
                          T_Lo => U64 (Block_Bytes * N),
                          T_Hi => 0,
                          Last => False))
   with Ghost              => Static,
        Pre                => OK (Key, C, M, Length)
                              and then N in 0 .. BB (Key, Length),
        Subprogram_Variant => (Decreases => N);

   --  The incremental context after Init (Key, NN) and the first L bytes
   --  of the message: every block of the padded input so far but the
   --  last compressed, the last one buffered.
   function Logical_After
     (Key       : Byte_Array;
      C         : Contents;
      M         : Pieces;
      Length, L : Offset;
      NN        : Digest_Length) return Inc.Context
   is
     (H       => Logical_Fold (Spec.Initial_H (Key'Length, NN), Key, C, M,
                               Length, BB (Key, L)),
      T       => (Lo => U64 (Block_Bytes * BB (Key, L)), Hi => 0),
      Buf     => [for J in Block_Index =>
                    (if Block_Bytes * BB (Key, L) + J < KB (Key) + L
                     then D (Key, C, M, Length, Block_Bytes * BB (Key, L) + J)
                     else 0)],
      Buf_Len => KB (Key) + L - Block_Bytes * BB (Key, L),
      NN      => NN)
   with Ghost => Static,
        Pre   => OK (Key, C, M, Length) and then L <= Length;

   --  RFC 7693's NN-byte digest of the whole logical message, keyed with
   --  Key: the fold over every block of d but the last, then the last
   --  with the final flag and the total input length as its counter.
   function Logical_Hash
     (Key    : Byte_Array;
      C      : Contents;
      M      : Pieces;
      Length : Offset;
      NN     : Digest_Length) return Byte_Array
   is
     (declare
         H : constant Words8 :=
           Spec.Compress
             (Logical_Fold (Spec.Initial_H (Key'Length, NN), Key, C, M,
                            Length, BB (Key, Length)),
              Logical_Block (Key, C, M, Length, BB (Key, Length)),
              T_Lo => U64 (KB (Key) + Length),
              T_Hi => 0,
              Last => True);
      begin
         [for J in 0 .. NN - 1 => Spec.Out_Byte (H, J)])
   with Ghost => Static,
        Pre   => OK (Key, C, M, Length);

   --  Data holds the logical bytes L .. L + Data'Length - 1, whatever its
   --  bounds.
   function Realizes
     (C         : Contents;
      M         : Pieces;
      Length, L : Offset;
      Data      : Byte_Array) return Boolean
   is
     (Data'Length <= Length - L
      and then (for all I in I64 range 0 .. Data'Length - 1 =>
                  Data (Data'First + I) = Byte_At (C, M, Length, L + I)))
   with Ghost => Static,
        Pre   => Has_Contents (C)
                 and then Valid (M, Length)
                 and then L <= Length;

   --  Init gives the context of the empty prefix.
   procedure Lemma_Init
     (Key    : Byte_Array;
      C      : Contents;
      M      : Pieces;
      Length : Offset;
      NN     : Digest_Length)
   with Ghost  => Static,
        Global => null,
        Pre    => OK (Key, C, M, Length),
        Post   => Logical_After (Key, C, M, Length, 0, NN)
                  = Inc.Init (Key, NN);

   --  Update with the next Data'Length bytes takes the context of the
   --  first L bytes to the context of the first L + Data'Length.
   procedure Lemma_Append
     (Key       : Byte_Array;
      C         : Contents;
      M         : Pieces;
      Length, L : Offset;
      Data      : Byte_Array;
      NN        : Digest_Length)
   with Ghost  => Static,
        Global => null,
        Pre    => OK (Key, C, M, Length)
                  and then L <= Length
                  and then Realizes (C, M, Length, L, Data),
        Post   => Inc.Update (Logical_After (Key, C, M, Length, L, NN), Data)
                  = Logical_After (Key, C, M, Length, L + Data'Length, NN);

   --  Final of the whole message's context gives the logical hash.
   procedure Lemma_Logical_Final
     (Key    : Byte_Array;
      C      : Contents;
      M      : Pieces;
      Length : Offset;
      NN     : Digest_Length)
   with Ghost  => Static,
        Global => null,
        Pre    => OK (Key, C, M, Length),
        Post   => Inc.Final (Logical_After (Key, C, M, Length, Length, NN))
                  = Logical_Hash (Key, C, M, Length, NN);

   --  Lemma_Append for any context Ctx equal to the prefix's (the shape
   --  of Blake2b.Hashing.Lemma_Update).
   procedure Lemma_Update_Of
     (Ctx       : Inc.Context;
      Key       : Byte_Array;
      C         : Contents;
      M         : Pieces;
      Length, L : Offset;
      Data      : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => OK (Key, C, M, Length)
                  and then L <= Length
                  and then Realizes (C, M, Length, L, Data)
                  and then Ctx = Logical_After (Key, C, M, Length, L, Ctx.NN),
        Post   => Inc.Update (Ctx, Data)
                  = Logical_After (Key, C, M, Length, L + Data'Length,
                                   Ctx.NN);

   --  Lemma_Logical_Final for any context Ctx equal to the whole
   --  message's.
   procedure Lemma_Final_Of
     (Ctx    : Inc.Context;
      Key    : Byte_Array;
      C      : Contents;
      M      : Pieces;
      Length : Offset)
   with Ghost  => Static,
        Global => null,
        Pre    => OK (Key, C, M, Length)
                  and then Ctx = Logical_After (Key, C, M, Length, Length,
                                                Ctx.NN),
        Post   => Inc.Final (Ctx) = Logical_Hash (Key, C, M, Length, Ctx.NN);

end Blake2b.Streaming.Theory;
