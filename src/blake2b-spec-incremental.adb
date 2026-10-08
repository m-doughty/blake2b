--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  The same ghost policy as the specification (Ada requires it).
pragma Assertion_Policy (Ghost => Check);

with Blake2b.Core;

--  The proofs of Lemma_Update and Lemma_Final. Everything here is Static
--  ghost code: proved by GNATprove, never compiled into any build.

package body Blake2b.Spec.Incremental
  with SPARK_Mode
is

   --  The context of Message in one shape that also covers the empty
   --  message (where After_Absorbing is Init): with dd blocks of padded
   --  input, Buf holds block dd - 1 byte for byte (Buffer_Form), h is the
   --  fold over blocks 0 .. dd - 2 and the counter is 128 (dd - 1).
   function Buffer_Form (C : Context; Key, Message : Byte_Array)
      return Boolean
   is
     (declare
         DD : constant I64 := Block_Count (Key, No_Bytes, Message);
      begin
         (for all J in Block_Index =>
            C.Buf (J)
            = Byte_At (Key, No_Bytes, Message, Block_Bytes * (DD - 1) + J))
         and then C.Buf_Len = Block_Bytes * Key_Blocks (Key)
                              + Message'Length - Block_Bytes * (DD - 1))
   with Ghost => Static,
        Pre   => Valid_Key (Key);

   function Form (C : Context; Key, Message : Byte_Array) return Boolean is
     (declare
         DD : constant I64 := Block_Count (Key, No_Bytes, Message);
      begin
         C.H = Fold (Initial_H (Key'Length, C.NN),
                     Key, No_Bytes, Message, DD - 1)
         and then C.T = (Lo => U64 (Block_Bytes * (DD - 1)), Hi => 0)
         and then Buffer_Form (C, Key, Message))
   with Ghost => Static,
        Pre   => Valid_Key (Key);

   procedure Lemma_Form (C : Context; Key, Message : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Valid_Key (Key)
                  and then C = After_Absorbing (Key, Message, C.NN),
        Post   => Form (C, Key, Message)
   is
   begin
      if Message'Length = 0 then
         pragma Assert (Block_Count (Key, No_Bytes, Message) = 1);
         pragma Assert
           (Fold (Initial_H (Key'Length, C.NN), Key, No_Bytes, Message, 0)
            = Initial_H (Key'Length, C.NN));
      end if;
   end Lemma_Form;

   --  The number of blocks of padded input is the input length, the key
   --  block included, divided by 128 and rounded up (one block at least).
   procedure Lemma_Block_Count (Key, Message : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Valid_Key (Key),
        Post   =>
          (declare
              L  : constant I64 := Block_Bytes * Key_Blocks (Key)
                                   + Message'Length;
              DD : constant I64 := Block_Count (Key, No_Bytes, Message);
           begin
              (if L = 0 then DD = 1 else DD - 1 = (L - 1) / Block_Bytes)
              and then Block_Bytes * (DD - 1) <= I64'Max (L - 1, 0)
              and then L <= Block_Bytes * DD)
   is
   begin
      null;
   end Lemma_Block_Count;

   --  Fold over the first N blocks only reads input bytes 0 .. 128 N - 1,
   --  so two messages that agree there fold to the same chaining value.
   procedure Lemma_Fold_Agree (H : Words8; Key, A, B : Byte_Array; N : I64)
   with Ghost  => Static,
        Global => null,
        Pre    => Valid_Key (Key)
                  and then N in 0 .. Block_Count (Key, No_Bytes, A) - 1
                  and then N in 0 .. Block_Count (Key, No_Bytes, B) - 1
                  and then (for all J in 0 .. Block_Bytes * N - 1 =>
                              Byte_At (Key, No_Bytes, A, J)
                              = Byte_At (Key, No_Bytes, B, J)),
        Post   => Fold (H, Key, No_Bytes, A, N)
                  = Fold (H, Key, No_Bytes, B, N)
   is
   begin
      for I in 1 .. N loop
         pragma Loop_Invariant
           (Fold (H, Key, No_Bytes, A, I - 1)
            = Fold (H, Key, No_Bytes, B, I - 1));
         Core.Lemma_Same8 (Fold (H, Key, No_Bytes, A, I - 1),
                           Fold (H, Key, No_Bytes, B, I - 1));
         pragma Assert
           (for all J in Block_Index =>
              Block_Of (Key, No_Bytes, A, I - 1) (J)
              = Block_Of (Key, No_Bytes, B, I - 1) (J));
         Core.Lemma_Same_Block (Block_Of (Key, No_Bytes, A, I - 1),
                                Block_Of (Key, No_Bytes, B, I - 1));
         pragma Assert
           (Fold (H, Key, No_Bytes, A, I) = Fold (H, Key, No_Bytes, B, I));
      end loop;
   end Lemma_Fold_Agree;

   --  Joined starts with Before, so their padded inputs agree on the
   --  bytes Before has: the key block and Before itself. When Data is
   --  empty they have the same bytes, so they agree everywhere.
   procedure Lemma_Agree_Before (Key, Before, Data, Joined : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Valid_Key (Key)
                  and then Is_Concatenation (Joined, Before, Data),
        Post   =>
          Block_Count (Key, No_Bytes, Before)
          <= Block_Count (Key, No_Bytes, Joined)
          and then
          (for all J in 0 .. Block_Bytes * Key_Blocks (Key)
                             + Before'Length - 1 =>
             Byte_At (Key, No_Bytes, Before, J)
             = Byte_At (Key, No_Bytes, Joined, J))
          and then
          (if Data'Length = 0 then
             Block_Count (Key, No_Bytes, Before)
             = Block_Count (Key, No_Bytes, Joined)
             and then
             (for all J in 0 .. Block_Bytes
                                * Block_Count (Key, No_Bytes, Before) - 1 =>
                Byte_At (Key, No_Bytes, Before, J)
                = Byte_At (Key, No_Bytes, Joined, J)))
   is
   begin
      Lemma_Block_Count (Key, Before);
      Lemma_Block_Count (Key, Joined);
   end Lemma_Agree_Before;

   --  What Update (C, Data) has to compress, the buffered tail followed
   --  by Data, has as many blocks as Joined's padded input has from block
   --  dd - 1 of Before on.
   procedure Lemma_Stream_Count
     (C : Context; Key, Before, Data, Joined : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Valid_Key (Key)
                  and then Is_Concatenation (Joined, Before, Data)
                  and then Data'Length > 0
                  and then Buffer_Form (C, Key, Before),
        Post   =>
          C.Buf_Len = Block_Bytes * Key_Blocks (Key) + Before'Length
                      - Block_Bytes * (Block_Count (Key, No_Bytes, Before) - 1)
          and then
          Block_Count (Key, No_Bytes, Before) - 1
          + Block_Count (No_Bytes, C.Buf (0 .. C.Buf_Len - 1), Data)
          = Block_Count (Key, No_Bytes, Joined)
   is
   begin
      Lemma_Block_Count (Key, Before);
      Lemma_Block_Count (Key, Joined);
   end Lemma_Stream_Count;

   --  One byte of it: byte P of the buffered tail followed by Data is byte
   --  128 (dd - 1) + P of Joined's padded input.
   procedure Lemma_Stream_Byte
     (C : Context; Key, Before, Data, Joined : Byte_Array; P : I64)
   with Ghost  => Static,
        Global => null,
        Pre    => Valid_Key (Key)
                  and then Is_Concatenation (Joined, Before, Data)
                  and then Data'Length > 0
                  and then Buffer_Form (C, Key, Before)
                  and then Block_Count (Key, No_Bytes, Before) - 1
                           + Block_Count (No_Bytes,
                                          C.Buf (0 .. C.Buf_Len - 1), Data)
                           = Block_Count (Key, No_Bytes, Joined)
                  and then P in 0 .. Block_Bytes
                                     * Block_Count
                                         (No_Bytes,
                                          C.Buf (0 .. C.Buf_Len - 1), Data)
                                     - 1,
        Post   =>
          Byte_At (No_Bytes, C.Buf (0 .. C.Buf_Len - 1), Data, P)
          = Byte_At (Key, No_Bytes, Joined,
                     Block_Bytes * (Block_Count (Key, No_Bytes, Before) - 1)
                     + P)
   is
      KB   : constant I64 := Key_Blocks (Key);
      LB   : constant I64 := Block_Bytes * KB + Before'Length;
      C0   : constant I64 := Block_Count (Key, No_Bytes, Before) - 1;
      Tail : constant Byte_Array := C.Buf (0 .. C.Buf_Len - 1);
      TL   : constant I64 := Tail'Length;
      Q    : constant I64 := Block_Bytes * C0 + P;
   begin
      Lemma_Block_Count (Key, Before);
      Lemma_Block_Count (Key, Joined);
      Lemma_Agree_Before (Key, Before, Data, Joined);
      pragma Assert (TL = LB - Block_Bytes * C0);
      if P < TL then
         --  A buffered byte: from block dd - 1 of Before, which Joined
         --  shares.
         pragma Assert (Byte_At (No_Bytes, Tail, Data, P) = Tail (P));
         pragma Assert (Tail (P) = C.Buf (P));
         pragma Assert (C.Buf (P) = Byte_At (Key, No_Bytes, Before, Q));
         pragma Assert (Q < LB);
         pragma Assert
           (Byte_At (Key, No_Bytes, Before, Q)
            = Byte_At (Key, No_Bytes, Joined, Q));
      elsif P - TL < Data'Length then
         --  A byte of Data: Joined has it after Before.
         pragma Assert
           (Byte_At (No_Bytes, Tail, Data, P) = Data (Data'First + (P - TL)));
         pragma Assert (Q - Block_Bytes * KB = Before'Length + (P - TL));
         pragma Assert
           (Byte_At (Key, No_Bytes, Joined, Q)
            = Joined (Joined'First + Before'Length + (P - TL)));
         pragma Assert
           (Joined (Joined'First + Before'Length + (P - TL))
            = Data (Data'First + (P - TL)));
      else
         --  Padding: zero in both.
         pragma Assert (Byte_At (No_Bytes, Tail, Data, P) = 0);
         pragma Assert (Q - Block_Bytes * KB >= Joined'Length);
         pragma Assert (Byte_At (Key, No_Bytes, Joined, Q) = 0);
      end if;
   end Lemma_Stream_Byte;

   --  The input still to be compressed by Update (C, Data), the buffered
   --  tail followed by Data, is the padded input of Joined from block
   --  dd - 1 of Before on, byte for byte.
   procedure Lemma_Stream_Bytes
     (C : Context; Key, Before, Data, Joined : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Valid_Key (Key)
                  and then Is_Concatenation (Joined, Before, Data)
                  and then Data'Length > 0
                  and then Buffer_Form (C, Key, Before),
        Post   =>
          (declare
              C0  : constant I64 := Block_Count (Key, No_Bytes, Before) - 1;
              BCS : constant I64 :=
                Block_Count (No_Bytes, C.Buf (0 .. C.Buf_Len - 1), Data);
           begin
              C0 + BCS = Block_Count (Key, No_Bytes, Joined)
              and then
              (for all P in 0 .. Block_Bytes * BCS - 1 =>
                 Byte_At (No_Bytes, C.Buf (0 .. C.Buf_Len - 1), Data, P)
                 = Byte_At (Key, No_Bytes, Joined, Block_Bytes * C0 + P)))
   is
      C0  : constant I64 := Block_Count (Key, No_Bytes, Before) - 1;
      BCS : constant I64 :=
        Block_Count (No_Bytes, C.Buf (0 .. C.Buf_Len - 1), Data);
   begin
      Lemma_Stream_Count (C, Key, Before, Data, Joined);
      for P in 0 .. Block_Bytes * BCS - 1 loop
         Lemma_Stream_Byte (C, Key, Before, Data, Joined, P);
         pragma Loop_Invariant
           (for all Q in 0 .. P =>
              Byte_At (No_Bytes, C.Buf (0 .. C.Buf_Len - 1), Data, Q)
              = Byte_At (Key, No_Bytes, Joined, Block_Bytes * C0 + Q));
      end loop;
   end Lemma_Stream_Bytes;

   --  The same, block by block.
   procedure Lemma_Stream_Blocks
     (C : Context; Key, Before, Data, Joined : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Valid_Key (Key)
                  and then Is_Concatenation (Joined, Before, Data)
                  and then Data'Length > 0
                  and then Buffer_Form (C, Key, Before),
        Post   =>
          (declare
              C0  : constant I64 := Block_Count (Key, No_Bytes, Before) - 1;
              BCS : constant I64 :=
                Block_Count (No_Bytes, C.Buf (0 .. C.Buf_Len - 1), Data);
           begin
              C0 + BCS = Block_Count (Key, No_Bytes, Joined)
              and then
              (for all J in 0 .. BCS - 1 =>
                 (for all X in Block_Index =>
                    Block_Of (No_Bytes, C.Buf (0 .. C.Buf_Len - 1), Data, J)
                      (X)
                    = Block_Of (Key, No_Bytes, Joined, C0 + J) (X))))
   is
   begin
      Lemma_Stream_Bytes (C, Key, Before, Data, Joined);
   end Lemma_Stream_Blocks;

   --  A counter below 2**64 advanced by less than 2**64 - itself: no
   --  carry, so the high word stays zero.
   procedure Lemma_Plus_Small (A, B : I64)
   with Ghost  => Static,
        Global => null,
        Pre    => A in 0 .. 2**40 and then B in 0 .. 2**40,
        Post   => Plus ((Lo => U64 (A), Hi => 0), U64 (B))
                  = (Lo => U64 (A + B), Hi => 0)
   is
   begin
      pragma Assert (U64 (A) + U64 (B) = U64 (A + B));
      pragma Assert (U64 (A + B) >= U64 (B));
   end Lemma_Plus_Small;

   --  Compressing the first N blocks of what Update (C, Data) compresses
   --  continues Joined's fold from block dd - 1 of Before: the blocks are
   --  the same (Lemma_Stream_Blocks) and so are the counters.
   procedure Lemma_Stream_Fold
     (C : Context; Key, Before, Data, Joined : Byte_Array; N : I64)
   with Ghost  => Static,
        Global => null,
        Pre    => Valid_Key (Key)
                  and then Is_Concatenation (Joined, Before, Data)
                  and then Data'Length > 0
                  and then Form (C, Key, Before)
                  and then C.H = Fold (Initial_H (Key'Length, C.NN),
                                       Key, No_Bytes, Joined,
                                       Block_Count (Key, No_Bytes, Before)
                                       - 1)
                  and then N in 0 .. Block_Count
                                       (No_Bytes, C.Buf (0 .. C.Buf_Len - 1),
                                        Data) - 1,
        Post   =>
          Stream_Fold (C.H, C.T, C.Buf (0 .. C.Buf_Len - 1), Data, N)
          = Fold (Initial_H (Key'Length, C.NN), Key, No_Bytes, Joined,
                  Block_Count (Key, No_Bytes, Before) - 1 + N)
   is
      pragma Annotate
        (GNATprove, Hide_Info, "Expression_Function_Body", Byte_At);
      H0 : constant Words8 := Initial_H (Key'Length, C.NN);
      C0 : constant I64 := Block_Count (Key, No_Bytes, Before) - 1;
   begin
      Lemma_Stream_Blocks (C, Key, Before, Data, Joined);
      pragma Assert
        (Stream_Fold (C.H, C.T, C.Buf (0 .. C.Buf_Len - 1), Data, 0)
         = Fold (H0, Key, No_Bytes, Joined, C0));
      for J in 1 .. N loop
         pragma Loop_Invariant
           (Stream_Fold (C.H, C.T, C.Buf (0 .. C.Buf_Len - 1), Data, J - 1)
            = Fold (H0, Key, No_Bytes, Joined, C0 + J - 1));
         Core.Lemma_Same8
           (Stream_Fold (C.H, C.T, C.Buf (0 .. C.Buf_Len - 1), Data, J - 1),
            Fold (H0, Key, No_Bytes, Joined, C0 + J - 1));
         pragma Assert
           (for all X in Block_Index =>
              Block_Of (No_Bytes, C.Buf (0 .. C.Buf_Len - 1), Data, J - 1)
                (X)
              = Block_Of (Key, No_Bytes, Joined, C0 + J - 1) (X));
         Core.Lemma_Same_Block
           (Block_Of (No_Bytes, C.Buf (0 .. C.Buf_Len - 1), Data, J - 1),
            Block_Of (Key, No_Bytes, Joined, C0 + J - 1));
         Lemma_Plus_Small (Block_Bytes * C0, Block_Bytes * J);
         pragma Assert
           (Advance (C.T, J)
            = (Lo => U64 (Block_Bytes * (C0 + J)), Hi => 0));
         pragma Assert
           (Stream_Fold (C.H, C.T, C.Buf (0 .. C.Buf_Len - 1), Data, J)
            = Fold (H0, Key, No_Bytes, Joined, C0 + J));
      end loop;
   end Lemma_Stream_Fold;

   --  Data empty: Joined has exactly Before's bytes, so it has the same
   --  context.
   procedure Lemma_Update_Empty
     (C : Context; Key, Before, Data, Joined : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Valid_Key (Key)
                  and then Is_Concatenation (Joined, Before, Data)
                  and then Data'Length = 0
                  and then C = After_Absorbing (Key, Before, C.NN),
        Post   => C = After_Absorbing (Key, Joined, C.NN)
   is
      pragma Annotate
        (GNATprove, Hide_Info, "Expression_Function_Body", Byte_At);
      H0  : constant Words8 := Initial_H (Key'Length, C.NN);
      DDB : constant I64 := Block_Count (Key, No_Bytes, Before);
      DDJ : constant I64 := Block_Count (Key, No_Bytes, Joined);
   begin
      if Joined'Length = 0 then
         return;
      end if;
      Lemma_Form (C, Key, Before);
      Lemma_Agree_Before (Key, Before, Data, Joined);
      pragma Assert (DDJ = DDB);
      Lemma_Fold_Agree (H0, Key, Before, Joined, DDB - 1);
      pragma Assert (C.H = After_Absorbing (Key, Joined, C.NN).H);
      pragma Assert (C.T = After_Absorbing (Key, Joined, C.NN).T);
      pragma Assert
        (for all J in Block_Index =>
           C.Buf (J) = After_Absorbing (Key, Joined, C.NN).Buf (J));
      pragma Assert
        (C.Buf_Len = After_Absorbing (Key, Joined, C.NN).Buf_Len);
   end Lemma_Update_Empty;

   procedure Lemma_Update
     (C : Context; Key, Before, Data, Joined : Byte_Array)
   is
      pragma Annotate
        (GNATprove, Hide_Info, "Expression_Function_Body", Byte_At);
      H0  : constant Words8 := Initial_H (Key'Length, C.NN);
      DDB : constant I64 := Block_Count (Key, No_Bytes, Before);
      DDJ : constant I64 := Block_Count (Key, No_Bytes, Joined);
   begin
      if Data'Length = 0 then
         Lemma_Update_Empty (C, Key, Before, Data, Joined);
         return;
      end if;

      Lemma_Form (C, Key, Before);
      Lemma_Block_Count (Key, Before);
      Lemma_Block_Count (Key, Joined);
      Lemma_Agree_Before (Key, Before, Data, Joined);
      Lemma_Fold_Agree (H0, Key, Before, Joined, DDB - 1);
      Lemma_Stream_Count (C, Key, Before, Data, Joined);

      declare
         Total : constant I64 := C.Buf_Len + Data'Length;
         N     : constant I64 := (Total - 1) / Block_Bytes;
      begin
         --  All blocks of the stream but its last.
         pragma Assert
           (Block_Count (No_Bytes, C.Buf (0 .. C.Buf_Len - 1), Data)
            = (Total + Block_Bytes - 1) / Block_Bytes);
         pragma Assert
           (N = Block_Count (No_Bytes, C.Buf (0 .. C.Buf_Len - 1), Data)
                - 1);
         pragma Assert (DDB - 1 + N = DDJ - 1);

         Lemma_Stream_Blocks (C, Key, Before, Data, Joined);
         Lemma_Stream_Fold (C, Key, Before, Data, Joined, N);
         Lemma_Plus_Small (Block_Bytes * (DDB - 1), Block_Bytes * N);
         pragma Assert
           (for all X in Block_Index =>
              Block_Of (No_Bytes, C.Buf (0 .. C.Buf_Len - 1), Data, N) (X)
              = Block_Of (Key, No_Bytes, Joined, DDB - 1 + N) (X));
         pragma Assert
           (Update (C, Data).H = After_Absorbing (Key, Joined, C.NN).H);
         pragma Assert
           (Update (C, Data).T = After_Absorbing (Key, Joined, C.NN).T);
         pragma Assert
           (for all X in Block_Index =>
              Update (C, Data).Buf (X)
              = After_Absorbing (Key, Joined, C.NN).Buf (X));
         pragma Assert
           (Update (C, Data).Buf_Len
            = After_Absorbing (Key, Joined, C.NN).Buf_Len);
      end;
   end Lemma_Update;

   procedure Lemma_Final (C : Context; Key, Message : Byte_Array) is
      DD : constant I64 := Block_Count (Key, No_Bytes, Message);
   begin
      Lemma_Form (C, Key, Message);
      Lemma_Block_Count (Key, Message);
      Core.Lemma_Same8
        (C.H, Fold (Initial_H (Key'Length, C.NN),
                    Key, No_Bytes, Message, DD - 1));
      pragma Assert
        (for all J in Block_Index =>
           C.Buf (J) = Block_Of (Key, No_Bytes, Message, DD - 1) (J));
      Core.Lemma_Same_Block
        (C.Buf, Block_Of (Key, No_Bytes, Message, DD - 1));
      Lemma_Plus_Small (Block_Bytes * (DD - 1), C.Buf_Len);
      pragma Assert
        (Plus (C.T, U64 (C.Buf_Len))
         = (Lo => U64 (Data_Length (No_Bytes, Message)
                       + Block_Bytes * Key_Blocks (Key)),
            Hi => 0));
      pragma Assert
        (Final_H (Key, No_Bytes, Message, C.NN)
         = Compress (C.H, C.Buf,
                     T_Lo => Plus (C.T, U64 (C.Buf_Len)).Lo,
                     T_Hi => Plus (C.T, U64 (C.Buf_Len)).Hi,
                     Last => True));
      Core.Lemma_Same8
        (Final_H (Key, No_Bytes, Message, C.NN),
         Compress (C.H, C.Buf,
                   T_Lo => Plus (C.T, U64 (C.Buf_Len)).Lo,
                   T_Hi => Plus (C.T, U64 (C.Buf_Len)).Hi,
                   Last => True));
      pragma Assert
        (for all J in 0 .. C.NN - 1 =>
           Final (C) (J) = Hash (Message, Key, C.NN) (J));
   end Lemma_Final;

end Blake2b.Spec.Incremental;
