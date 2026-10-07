--  BLAKE2b (RFC 7693) in SPARK: incremental hashing, as functions.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  Executable in every build, like Blake2b.Spec: the test suite runs this
--  model against Blake2b.Spec.Hash and against the implementation.
pragma Assertion_Policy (Ghost => Check);

--  RFC 7693 defines BLAKE2b on a whole message. An incremental hash
--  absorbs the message in pieces instead, keeping a context between them:
--  the chaining value h, the 128-bit offset counter t (the bytes
--  compressed so far) and a buffer holding the bytes not yet compressed.
--  This package says what the incremental interface (Blake2b.Hashing's
--  Init, Update and Final) does to that context, as functions, in the
--  shape of the reference implementation's blake2b_init, blake2b_update
--  and blake2b_final. Blake2b.Hashing is proved to compute exactly these
--  functions.
--
--  It is not part of the RFC, so it is not trusted: two lemmas prove that
--  it computes Blake2b.Spec.Hash, however the message is split.
--
--  * After_Absorbing (Key, Message, NN) is the context once Message has
--    been absorbed, in any number of pieces of any sizes: every block of
--    the padded input but the last compressed, the last one buffered.
--  * Lemma_Update: absorbing Data into the context of Before gives the
--    context of Before followed by Data.
--  * Lemma_Final: finishing the context of Message gives
--    Spec.Hash (Message, Key, NN).
--
--  By induction over the pieces, Init, any sequence of Updates and Final
--  compute Spec.Hash of the pieces' concatenation.
--  Blake2b.Hashing.Theorem_Incremental states and proves exactly that for
--  the real procedures.

package Blake2b.Spec.Incremental
  with SPARK_Mode, Ghost, Pure
is

   --  The 128-bit offset counter t: Lo is t mod 2**64, Hi is t >> 64.
   type Counter is record
      Lo : U64;
      Hi : U64;
   end record;

   --  t := t + N, as the reference implementation increments it (its
   --  blake2b_increment_counter): add to the low word, and carry into the
   --  high word when the low word wraps. Modulo 2**128, like the counter.
   function Plus (T : Counter; N : U64) return Counter is
     (declare
         Lo : constant U64 := T.Lo + N;
      begin
         (Lo => Lo, Hi => (if Lo < N then T.Hi + 1 else T.Hi)));

   --  T advanced by N whole blocks. (One addition with carry: 128 * N is
   --  far below 2**64.)
   function Advance (T : Counter; N : I64) return Counter is
     (Plus (T, U64 (Block_Bytes * N)))
   with Pre => N in 0 .. 2**26;

   subtype Buffer_Length is I64 range 0 .. Block_Bytes;

   --  An incremental hash's context. Buf (0 .. Buf_Len - 1) holds the
   --  bytes absorbed but not yet compressed; the rest of Buf is zero.
   type Context is record
      H       : Words8;
      T       : Counter;
      Buf     : Block;
      Buf_Len : Buffer_Length;
      NN      : Digest_Length;
   end record;

   --  The chaining value after compressing blocks 0 .. N - 1 of the input
   --  Tail followed by Data, starting from chaining value H and offset
   --  counter T. Block i is a non-final block with counter T + 128 (i + 1).
   function Stream_Fold
     (H : Words8; T : Counter; Tail, Data : Byte_Array; N : I64)
      return Words8
   is
     (if N = 0 then H
      else Compress (Stream_Fold (H, T, Tail, Data, N - 1),
                     Block_Of (No_Bytes, Tail, Data, N - 1),
                     T_Lo => Advance (T, N).Lo,
                     T_Hi => Advance (T, N).Hi,
                     Last => False))
   with Pre                => N in 0 .. Block_Count (No_Bytes, Tail, Data) - 1,
        Subprogram_Variant => (Decreases => N);

   --  blake2b_init_key: the parameter block in h, a zero counter, and (if
   --  keyed) the key, zero-padded to a full block, buffered as the first
   --  block of input.
   function Init (Key : Byte_Array; NN : Digest_Length) return Context is
     (H       => Initial_H (Key'Length, NN),
      T       => (Lo => 0, Hi => 0),
      Buf     =>
        [for J in Block_Index =>
           (if J < Key'Length then Key (Key'First + J) else 0)],
      Buf_Len => Block_Bytes * Key_Blocks (Key),
      NN      => NN)
   with Pre => Valid_Key (Key);

   --  blake2b_update: the buffered bytes (C.Buf (0 .. C.Buf_Len - 1))
   --  followed by Data form the input still to be compressed. Every whole
   --  block of it but the last is compressed; the last 1 .. 128 bytes are
   --  buffered, because only Final knows whether they are the last block
   --  of the message.
   function Update (C : Context; Data : Byte_Array) return Context is
     (if Data'Length = 0 then C
      else
        (declare
            Total : constant I64 := C.Buf_Len + Data'Length;
            N     : constant I64 := (Total - 1) / Block_Bytes;
         begin
            (H       => Stream_Fold (C.H, C.T, C.Buf (0 .. C.Buf_Len - 1),
                                     Data, N),
             T       => Advance (C.T, N),
             Buf     => Block_Of (No_Bytes, C.Buf (0 .. C.Buf_Len - 1),
                                  Data, N),
             Buf_Len => Total - Block_Bytes * N,
             NN      => C.NN)));

   --  blake2b_final: the buffered bytes, zero-padded, are the last block:
   --  the counter becomes the total input length, the block is compressed
   --  with the final flag, and the digest is the first NN bytes of h.
   function Final (C : Context) return Byte_Array is
     (declare
         T : constant Counter := Plus (C.T, U64 (C.Buf_Len));
         H : constant Words8 :=
           Compress (C.H, C.Buf, T_Lo => T.Lo, T_Hi => T.Hi, Last => True);
      begin
         [for J in 0 .. C.NN - 1 => Out_Byte (H, J)])
   with Post => Final'Result'First = 0 and then Final'Result'Length = C.NN;

   --  The context once Message has been absorbed after Init (Key, NN),
   --  however it was split: with dd blocks of padded input, blocks
   --  0 .. dd - 2 compressed (as Spec.Fold does) and block dd - 1
   --  buffered.
   function After_Absorbing
     (Key, Message : Byte_Array; NN : Digest_Length) return Context
   is
     (if Message'Length = 0 then Init (Key, NN)
      else
        (declare
            DD : constant I64 := Block_Count (Key, No_Bytes, Message);
         begin
            (H       => Fold (Initial_H (Key'Length, NN),
                              Key, No_Bytes, Message, DD - 1),
             T       => (Lo => U64 (Block_Bytes * (DD - 1)), Hi => 0),
             Buf     => Block_Of (Key, No_Bytes, Message, DD - 1),
             Buf_Len => Block_Bytes * Key_Blocks (Key) + Message'Length
                        - Block_Bytes * (DD - 1),
             NN      => NN)))
   with Pre => Valid_Key (Key);

   --  Joined is Before followed by Data, element by element, whatever the
   --  bounds of the three arrays.
   function Is_Concatenation (Joined, Before, Data : Byte_Array)
      return Boolean
   is
     (Joined'Length = Before'Length + Data'Length
      and then (for all I in I64 range 0 .. Before'Length - 1 =>
                  Joined (Joined'First + I) = Before (Before'First + I))
      and then (for all I in I64 range 0 .. Data'Length - 1 =>
                  Joined (Joined'First + Before'Length + I)
                  = Data (Data'First + I)));

   --  Absorbing Data into the context of Before gives the context of
   --  Before followed by Data.
   procedure Lemma_Update
     (C : Context; Key, Before, Data, Joined : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Valid_Key (Key)
                  and then Is_Concatenation (Joined, Before, Data)
                  and then C = After_Absorbing (Key, Before, C.NN),
        Post   => Update (C, Data) = After_Absorbing (Key, Joined, C.NN);

   --  Finishing the context of Message gives BLAKE2b of Message.
   procedure Lemma_Final (C : Context; Key, Message : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Valid_Key (Key)
                  and then C = After_Absorbing (Key, Message, C.NN),
        Post   => Final (C) = Hash (Message, Key, C.NN);

end Blake2b.Spec.Incremental;
