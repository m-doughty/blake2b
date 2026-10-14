--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  The proofs of the per-call lemmas. Static ghost code: proved by
--  GNATprove, never compiled.
--
--  Update compresses the stream "buffered tail, then Data" (Tail below is
--  the buffered tail of the prefix's context), so each lemma about Update
--  relates that stream's blocks to the blocks of d. Lemma_Append is split
--  into its chaining value, counter and buffer, each in its own small
--  proof context.

package body Blake2b.Streaming.Theory
  with SPARK_Mode
is

   procedure Lemma_Same8 (L, R : Words8) is null;
   procedure Lemma_Same_Block (L, R : Block) is null;

   procedure Lemma_Init
     (Key    : Byte_Array;
      C      : Contents;
      M      : Pieces;
      Length : Offset;
      NN     : Digest_Length) is null;

   --  Block K of the stream "buffered tail, then Data" is block
   --  BB (Key, L) + K of d, truncated at the end of the new prefix.
   procedure Lemma_Stream_Block
     (Key       : Byte_Array;
      C         : Contents;
      M         : Pieces;
      Length, L : Offset;
      Data      : Byte_Array;
      Tail      : Byte_Array;
      K         : I64)
   with Ghost  => Static,
        Global => null,
        Pre    =>
          OK (Key, C, M, Length) and then L <= Length
          and then Realizes (C, M, Length, L, Data)
          and then Tail'First = 0
          and then Tail'Length = KB (Key) + L - Block_Bytes * BB (Key, L)
          and then (for all J in Tail'Range =>
                      Tail (J) = D (Key, C, M, Length,
                                    Block_Bytes * BB (Key, L) + J))
          and then K in 0 .. Spec.Block_Count (No_Bytes, Tail, Data) - 1,
        Post   =>
          (for all J in Block_Index =>
             Spec.Block_Of (No_Bytes, Tail, Data, K) (J) =
               (if Block_Bytes * K + J < Tail'Length + Data'Length
                then D (Key, C, M, Length,
                        Block_Bytes * (BB (Key, L) + K) + J)
                else 0));

   --  One byte of that stream.
   procedure Lemma_Stream_Byte
     (Key       : Byte_Array;
      C         : Contents;
      M         : Pieces;
      Length, L : Offset;
      Data      : Byte_Array;
      Tail      : Byte_Array;
      P         : I64)
   with Ghost  => Static,
        Global => null,
        Pre    =>
          OK (Key, C, M, Length) and then L <= Length
          and then Realizes (C, M, Length, L, Data)
          and then Tail'First = 0
          and then Tail'Length = KB (Key) + L - Block_Bytes * BB (Key, L)
          and then (for all J in Tail'Range =>
                      Tail (J) = D (Key, C, M, Length,
                                    Block_Bytes * BB (Key, L) + J))
          and then P in 0 .. Block_Bytes
                             * Spec.Block_Count (No_Bytes, Tail, Data) - 1,
        Post   =>
          Spec.Byte_At (No_Bytes, Tail, Data, P) =
            (if P < Tail'Length + Data'Length
             then D (Key, C, M, Length, Block_Bytes * BB (Key, L) + P)
             else 0)
   is
   begin
      if P < Tail'Length then
         null;
      elsif P - Tail'Length < Data'Length then
         pragma Assert
           (Data (Data'First + (P - Tail'Length))
            = Byte_At (C, M, Length, L + (P - Tail'Length)));
         pragma Assert
           (Block_Bytes * BB (Key, L) + P - KB (Key) = L + (P - Tail'Length));
      end if;
   end Lemma_Stream_Byte;

   procedure Lemma_Stream_Block
     (Key       : Byte_Array;
      C         : Contents;
      M         : Pieces;
      Length, L : Offset;
      Data      : Byte_Array;
      Tail      : Byte_Array;
      K         : I64)
   is
   begin
      for J in Block_Index loop
         Lemma_Stream_Byte (Key, C, M, Length, L, Data, Tail,
                            Block_Bytes * K + J);
         pragma Loop_Invariant
           (for all I in Block_Index'First .. J =>
              Spec.Block_Of (No_Bytes, Tail, Data, K) (I) =
                (if Block_Bytes * K + I < Tail'Length + Data'Length
                 then D (Key, C, M, Length,
                         Block_Bytes * (BB (Key, L) + K) + I)
                 else 0));
      end loop;
   end Lemma_Stream_Block;

   --  The counter of the logical fold, as the model's Advance computes it.
   procedure Lemma_Counter (B0, K : I64)
   with Ghost  => Static,
        Global => null,
        Pre    => B0 in 0 .. 2**28 and then K in 0 .. 2**26,
        Post   =>
          Inc.Advance ((Lo => U64 (Block_Bytes * B0), Hi => 0), K).Lo
            = U64 (Block_Bytes * (B0 + K))
          and then
          Inc.Advance ((Lo => U64 (Block_Bytes * B0), Hi => 0), K).Hi = 0
   is
      A : constant U64 := U64 (Block_Bytes * B0);
      N : constant U64 := U64 (Block_Bytes * K);
   begin
      pragma Assert (A <= 2**35 and then N <= 2**33);
      pragma Assert (A + N = U64 (Block_Bytes * (B0 + K)));
      pragma Assert (not (A + N < N));
   end Lemma_Counter;

   --  Arithmetic of one Update: the buffered tail of the prefix of length
   --  L (KB + L - 128 BB (L) bytes) and Len more bytes leave N whole
   --  blocks to compress, and the new prefix's buffered block is
   --  BB (L) + N.
   procedure Lemma_Next (Key : Byte_Array; L : Offset; Len : I64)
   with Ghost  => Static,
        Global => null,
        Pre    => Key'Length <= Max_Key_Bytes
                  and then Len in 1 .. Max_Length - L,
        Post   =>
          KB (Key) + L - Block_Bytes * BB (Key, L) in 0 .. Block_Bytes
          and then BB (Key, L)
                   + (KB (Key) + L - Block_Bytes * BB (Key, L) + Len - 1)
                     / Block_Bytes
                   = BB (Key, L + Len)
   is
   begin
      null;
   end Lemma_Next;

   --  The buffered block index is monotone in the prefix length.
   procedure Lemma_BB_Mono (Key : Byte_Array; A, B : Offset)
   with Ghost  => Static,
        Global => null,
        Pre    => Key'Length <= Max_Key_Bytes and then A <= B,
        Post   => BB (Key, A) <= BB (Key, B)
   is
   begin
      null;
   end Lemma_BB_Mono;

   --  One block of the fold: if the model's fold over the first K - 1
   --  blocks of "tail, then Data" is the logical fold up to block
   --  BB (Key, L) + K - 1, then so it is one block further.
   procedure Lemma_Fold_Step
     (Key       : Byte_Array;
      C         : Contents;
      M         : Pieces;
      Length, L : Offset;
      Data      : Byte_Array;
      Tail      : Byte_Array;
      H, IH     : Words8;
      T         : Inc.Counter;
      K         : I64)
   with Ghost  => Static,
        Global => null,
        Pre    =>
          OK (Key, C, M, Length) and then L <= Length
          and then Realizes (C, M, Length, L, Data)
          and then Tail'First = 0
          and then Tail'Length = KB (Key) + L - Block_Bytes * BB (Key, L)
          and then (for all J in Tail'Range =>
                      Tail (J) = D (Key, C, M, Length,
                                    Block_Bytes * BB (Key, L) + J))
          and then T.Lo = U64 (Block_Bytes * BB (Key, L))
          and then T.Hi = 0
          and then K in 1 .. (Tail'Length + Data'Length - 1) / Block_Bytes
          and then BB (Key, L) + K <= BB (Key, Length)
          and then Same8 (Inc.Stream_Fold (H, T, Tail, Data, K - 1),
                          Logical_Fold (IH, Key, C, M, Length,
                                        BB (Key, L) + K - 1)),
        Post   =>
          Same8 (Inc.Stream_Fold (H, T, Tail, Data, K),
                 Logical_Fold (IH, Key, C, M, Length, BB (Key, L) + K))
   is
   begin
      Lemma_Stream_Block (Key, C, M, Length, L, Data, Tail, K - 1);
      pragma Assert
        (for all J in Block_Index =>
           Spec.Block_Of (No_Bytes, Tail, Data, K - 1) (J)
           = Logical_Block (Key, C, M, Length, BB (Key, L) + K - 1) (J));
      Lemma_Same_Block
        (Spec.Block_Of (No_Bytes, Tail, Data, K - 1),
         Logical_Block (Key, C, M, Length, BB (Key, L) + K - 1));
      Lemma_Counter (BB (Key, L), K);
   end Lemma_Fold_Step;

   --  The N whole blocks of "tail, then Data" fold to the logical fold up
   --  to block BB (Key, L) + N.
   procedure Lemma_Append_Fold
     (Key       : Byte_Array;
      C         : Contents;
      M         : Pieces;
      Length, L : Offset;
      Data      : Byte_Array;
      Tail      : Byte_Array;
      H, IH     : Words8;
      T         : Inc.Counter;
      N         : I64)
   with Ghost  => Static,
        Global => null,
        Pre    =>
          OK (Key, C, M, Length) and then L <= Length
          and then Realizes (C, M, Length, L, Data)
          and then Data'Length > 0
          and then Tail'First = 0
          and then Tail'Length = KB (Key) + L - Block_Bytes * BB (Key, L)
          and then (for all J in Tail'Range =>
                      Tail (J) = D (Key, C, M, Length,
                                    Block_Bytes * BB (Key, L) + J))
          and then T.Lo = U64 (Block_Bytes * BB (Key, L))
          and then T.Hi = 0
          and then N = (Tail'Length + Data'Length - 1) / Block_Bytes
          and then BB (Key, L) + N <= BB (Key, Length)
          and then Same8 (H, Logical_Fold (IH, Key, C, M, Length,
                                           BB (Key, L))),
        Post   =>
          Same8 (Inc.Stream_Fold (H, T, Tail, Data, N),
                 Logical_Fold (IH, Key, C, M, Length, BB (Key, L) + N))
   is
   begin
      pragma Assert (Same8 (Inc.Stream_Fold (H, T, Tail, Data, 0), H));
      for K in 1 .. N loop
         Lemma_Fold_Step (Key, C, M, Length, L, Data, Tail, H, IH, T, K);
         pragma Loop_Invariant
           (Same8 (Inc.Stream_Fold (H, T, Tail, Data, K),
                   Logical_Fold (IH, Key, C, M, Length, BB (Key, L) + K)));
      end loop;
   end Lemma_Append_Fold;

   --  Update's chaining value is the new prefix's logical fold.
   procedure Lemma_Append_H
     (Key       : Byte_Array;
      C         : Contents;
      M         : Pieces;
      Length, L : Offset;
      Data      : Byte_Array;
      NN        : Digest_Length)
   with Ghost  => Static,
        Global => null,
        Pre    => OK (Key, C, M, Length) and then L <= Length
                  and then Realizes (C, M, Length, L, Data)
                  and then Data'Length > 0,
        Post   =>
          Same8
            (Inc.Update (Logical_After (Key, C, M, Length, L, NN), Data).H,
             Logical_After (Key, C, M, Length, L + Data'Length, NN).H)
   is
      Ctx : constant Inc.Context := Logical_After (Key, C, M, Length, L, NN);
      N   : constant I64 := (Ctx.Buf_Len + Data'Length - 1) / Block_Bytes;
   begin
      Lemma_Next (Key, L, Data'Length);
      Lemma_BB_Mono (Key, L + Data'Length, Length);
      pragma Assert
        (for all J in 0 .. Ctx.Buf_Len - 1 =>
           Ctx.Buf (J)
           = D (Key, C, M, Length, Block_Bytes * BB (Key, L) + J));
      Lemma_Append_Fold
        (Key, C, M, Length, L, Data, Ctx.Buf (0 .. Ctx.Buf_Len - 1),
         Ctx.H, Spec.Initial_H (Key'Length, NN), Ctx.T, N);
      pragma Assert
        (Inc.Update (Ctx, Data).H
         = Inc.Stream_Fold (Ctx.H, Ctx.T, Ctx.Buf (0 .. Ctx.Buf_Len - 1),
                            Data, N));
      pragma Assert
        (Same8 (Inc.Update (Ctx, Data).H,
                Logical_Fold (Spec.Initial_H (Key'Length, NN), Key, C, M,
                              Length, BB (Key, L) + N)));
      pragma Assert (BB (Key, L) + N = BB (Key, L + Data'Length));
      pragma Assert
        (Same8 (Inc.Update (Ctx, Data).H,
                Logical_Fold (Spec.Initial_H (Key'Length, NN), Key, C, M,
                              Length, BB (Key, L + Data'Length))));
      pragma Assert
        (Logical_After (Key, C, M, Length, L + Data'Length, NN).H
         = Logical_Fold (Spec.Initial_H (Key'Length, NN), Key, C, M,
                         Length, BB (Key, L + Data'Length)));
   end Lemma_Append_H;

   --  Update's counter is the new prefix's counter.
   procedure Lemma_Append_T
     (Key       : Byte_Array;
      C         : Contents;
      M         : Pieces;
      Length, L : Offset;
      Data      : Byte_Array;
      NN        : Digest_Length)
   with Ghost  => Static,
        Global => null,
        Pre    => OK (Key, C, M, Length) and then L <= Length
                  and then Realizes (C, M, Length, L, Data)
                  and then Data'Length > 0,
        Post   =>
          Inc.Update (Logical_After (Key, C, M, Length, L, NN), Data).T
          = Logical_After (Key, C, M, Length, L + Data'Length, NN).T
   is
      Ctx : constant Inc.Context := Logical_After (Key, C, M, Length, L, NN);
      N   : constant I64 := (Ctx.Buf_Len + Data'Length - 1) / Block_Bytes;
   begin
      Lemma_Next (Key, L, Data'Length);
      Lemma_Counter (BB (Key, L), N);
      pragma Assert (Inc.Update (Ctx, Data).T = Inc.Advance (Ctx.T, N));
   end Lemma_Append_T;

   --  Update's buffer is the new prefix's buffered block.
   procedure Lemma_Append_Buf
     (Key       : Byte_Array;
      C         : Contents;
      M         : Pieces;
      Length, L : Offset;
      Data      : Byte_Array;
      NN        : Digest_Length)
   with Ghost  => Static,
        Global => null,
        Pre    => OK (Key, C, M, Length) and then L <= Length
                  and then Realizes (C, M, Length, L, Data)
                  and then Data'Length > 0,
        Post   =>
          Same_Block
            (Inc.Update (Logical_After (Key, C, M, Length, L, NN), Data).Buf,
             Logical_After (Key, C, M, Length, L + Data'Length, NN).Buf)
   is
      Ctx : constant Inc.Context := Logical_After (Key, C, M, Length, L, NN);
      N   : constant I64 := (Ctx.Buf_Len + Data'Length - 1) / Block_Bytes;
   begin
      Lemma_Next (Key, L, Data'Length);
      pragma Assert
        (for all J in 0 .. Ctx.Buf_Len - 1 =>
           Ctx.Buf (J)
           = D (Key, C, M, Length, Block_Bytes * BB (Key, L) + J));
      Lemma_Stream_Block
        (Key, C, M, Length, L, Data, Ctx.Buf (0 .. Ctx.Buf_Len - 1), N);
      pragma Assert
        (Inc.Update (Ctx, Data).Buf
         = Spec.Block_Of (No_Bytes, Ctx.Buf (0 .. Ctx.Buf_Len - 1), Data,
                          N));
      pragma Assert
        (for all J in Block_Index =>
           Inc.Update (Ctx, Data).Buf (J)
           = Logical_After (Key, C, M, Length, L + Data'Length, NN).Buf (J));
      Lemma_Same_Block
        (Inc.Update (Ctx, Data).Buf,
         Logical_After (Key, C, M, Length, L + Data'Length, NN).Buf);
   end Lemma_Append_Buf;

   procedure Lemma_Append
     (Key       : Byte_Array;
      C         : Contents;
      M         : Pieces;
      Length, L : Offset;
      Data      : Byte_Array;
      NN        : Digest_Length)
   is
   begin
      if Data'Length = 0 then
         return;
      end if;
      Lemma_Append_H (Key, C, M, Length, L, Data, NN);
      Lemma_Append_T (Key, C, M, Length, L, Data, NN);
      Lemma_Append_Buf (Key, C, M, Length, L, Data, NN);
      Lemma_Next (Key, L, Data'Length);
      pragma Assert
        (Inc.Update (Logical_After (Key, C, M, Length, L, NN), Data).Buf_Len
         = Logical_After (Key, C, M, Length, L + Data'Length, NN).Buf_Len);
      pragma Assert
        (Inc.Update (Logical_After (Key, C, M, Length, L, NN), Data).NN = NN);
   end Lemma_Append;

   --  The final counter: the buffered block's offset plus the buffered
   --  length is the padded input's length, with no carry.
   procedure Lemma_Final_Counter (Key : Byte_Array; Length : Offset)
   with Ghost  => Static,
        Global => null,
        Pre    => Key'Length <= Max_Key_Bytes,
        Post   =>
          Inc.Plus ((Lo => U64 (Block_Bytes * BB (Key, Length)), Hi => 0),
                    U64 (KB (Key) + Length
                         - Block_Bytes * BB (Key, Length))).Lo
            = U64 (KB (Key) + Length)
          and then
          Inc.Plus ((Lo => U64 (Block_Bytes * BB (Key, Length)), Hi => 0),
                    U64 (KB (Key) + Length
                         - Block_Bytes * BB (Key, Length))).Hi = 0
   is
      A : constant U64 := U64 (Block_Bytes * BB (Key, Length));
      R : constant U64 :=
        U64 (KB (Key) + Length - Block_Bytes * BB (Key, Length));
   begin
      pragma Assert (A <= 2**35 and then R <= Block_Bytes);
      pragma Assert (A + R = U64 (KB (Key) + Length));
      pragma Assert (not (A + R < R));
   end Lemma_Final_Counter;

   --  Byte P of the padded input past the key block and the message is
   --  zero: the padding fact, alone in its own small proof context.
   procedure Lemma_Pad_Byte
     (Key    : Byte_Array;
      C      : Contents;
      M      : Pieces;
      Length : Offset;
      P      : I64)
   with Ghost  => Static,
        Global => null,
        Pre    =>
          OK (Key, C, M, Length)
          and then P in KB (Key) + Length .. KB (Key) + Max_Length + 127,
        Post   => D (Key, C, M, Length, P) = 0
   is
   begin
      Lemma_Padding (C, M, Length, P - KB (Key));
   end Lemma_Pad_Byte;

   procedure Lemma_Logical_Final
     (Key    : Byte_Array;
      C      : Contents;
      M      : Pieces;
      Length : Offset;
      NN     : Digest_Length)
   is
      Ctx : constant Inc.Context :=
        Logical_After (Key, C, M, Length, Length, NN);
      B   : constant I64 := BB (Key, Length);
   begin
      for J in Block_Index loop
         if Block_Bytes * B + J >= KB (Key) + Length then
            Lemma_Pad_Byte (Key, C, M, Length, Block_Bytes * B + J);
         end if;
         pragma Loop_Invariant
           (for all I in 0 .. J =>
              Ctx.Buf (I) = Logical_Block (Key, C, M, Length, B) (I));
      end loop;
      Lemma_Same_Block (Ctx.Buf, Logical_Block (Key, C, M, Length, B));
      Lemma_Final_Counter (Key, Length);
      pragma Assert
        (Inc.Plus (Ctx.T, U64 (Ctx.Buf_Len)).Lo = U64 (KB (Key) + Length)
         and then Inc.Plus (Ctx.T, U64 (Ctx.Buf_Len)).Hi = 0);
   end Lemma_Logical_Final;

   procedure Lemma_Same_Context (L, R : Inc.Context) is
   begin
      Lemma_Same8 (L.H, R.H);
      Lemma_Same_Block (L.Buf, R.Buf);
   end Lemma_Same_Context;

   procedure Lemma_Update_Of
     (Ctx       : Inc.Context;
      Key       : Byte_Array;
      C         : Contents;
      M         : Pieces;
      Length, L : Offset;
      Data      : Byte_Array)
   is
   begin
      Lemma_Same_Context (Ctx, Logical_After (Key, C, M, Length, L, Ctx.NN));
      Lemma_Append (Key, C, M, Length, L, Data, Ctx.NN);
   end Lemma_Update_Of;

   procedure Lemma_Final_Of
     (Ctx    : Inc.Context;
      Key    : Byte_Array;
      C      : Contents;
      M      : Pieces;
      Length : Offset)
   is
   begin
      Lemma_Same_Context
        (Ctx, Logical_After (Key, C, M, Length, Length, Ctx.NN));
      Lemma_Logical_Final (Key, C, M, Length, Ctx.NN);
   end Lemma_Final_Of;

end Blake2b.Streaming.Theory;
