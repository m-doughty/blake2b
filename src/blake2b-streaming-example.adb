--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  The proofs of the worked example and its witness. Static ghost code:
--  proved by GNATprove, never compiled.

package body Blake2b.Streaming.Example
  with SPARK_Mode
is

   procedure Lemma_Piece
     (C      : Contents;
      M      : Pieces;
      Length : Offset;
      I      : Positive)
   is
      Data : constant Byte_Array := Piece_Data (C, M, I);
   begin
      for J in Index range 0 .. M (I).Count - 1 loop
         Lemma_Absolute (C, M, Length, M (I).First + J, I);
         pragma Loop_Invariant
           (for all K in Index range 0 .. J =>
              Data (K) = Byte_At (C, M, Length, M (I).First + K));
      end loop;
   end Lemma_Piece;

   --  The padded input is at most 128 + Max_Length bytes, far below
   --  Max_Input.
   procedure Lemma_Room
     (S      : State;
      Key    : Byte_Array;
      L, Len : Offset)
   is
      --  S appears only in the contract (Absorbed (S)).
      pragma Unreferenced (S);
   begin
      pragma Assert (Big.Length (Max_Length + 128) <= Max_Input);
      pragma Assert
        (Big.Length (KB (Key) + L) + Big.Length (Len)
         = Big.Length (KB (Key) + L + Len));
   end Lemma_Room;

   --  Transitivity of array equality, in a context small enough that the
   --  provers unfold "=" on byte arrays cheaply.
   procedure Lemma_Eq_Trans (A, X, B : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => A = X and then X = B,
        Post   => A = B
   is
   begin
      null;
   end Lemma_Eq_Trans;

   --  The last step of Run_Loop, in a small proof context: a state whose
   --  model is the whole message's context finishes to the logical hash.
   procedure Finish
     (S      : in out State;
      Key    : Byte_Array;
      C      : Contents;
      M      : Pieces;
      Length : Offset;
      Digest : out Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => OK (Key, C, M, Length)
                  and then Is_Absorbing (S)
                  and then Digest'Length = Output_Length (S)
                  and then Model (S)
                           = Logical_After (Key, C, M, Length, Length,
                                            Output_Length (S)),
        Post   => Digest = Logical_Hash (Key, C, M, Length, Digest'Length)
   is
      Last : constant Inc.Context := Model (S);
   begin
      Lemma_Final_Of (Last, Key, C, M, Length);
      Final (S, Digest);
      Lemma_Eq_Trans (Digest, Inc.Final (Last),
                      Logical_Hash (Key, C, M, Length, Last.NN));
   end Finish;

   procedure Run_Loop
     (Key    : Byte_Array;
      C      : Contents;
      M      : Pieces;
      Length : Offset;
      Digest : out Byte_Array)
   is
      S  : State;
      NN : constant Digest_Length := Digest'Length;
      P  : Offset := 0;
   begin
      Init (S, NN, Key);
      Lemma_Init (Key, C, M, Length, NN);

      --  P is the length of the prefix absorbed so far.
      for I in M'Range loop
         pragma Loop_Invariant (P = M (I).First);
         pragma Loop_Invariant
           (Is_Absorbing (S) and then Output_Length (S) = NN);
         pragma Loop_Invariant (Absorbed (S) = Big.Length (KB (Key) + P));
         pragma Loop_Invariant
           (Model (S) = Logical_After (Key, C, M, Length, P, NN));
         Lemma_Piece (C, M, Length, I);
         declare
            Data   : constant Byte_Array := Piece_Data (C, M, I);
            Before : constant Inc.Context := Model (S);
         begin
            pragma Assert (Data'Length = M (I).Count);
            pragma Assert (Before.NN = NN);
            pragma Assert
              (Before = Logical_After (Key, C, M, Length, M (I).First,
                                       Before.NN));
            Lemma_Update_Of
              (Before, Key, C, M, Length, M (I).First, Piece_Data (C, M, I));
            Lemma_Room (S, Key, P, Data'Length);
            Update (S, Data);
            --  Model (S) = Update (Before, Data) = the next prefix's
            --  context, chained through logical equality.
            Lemma_Same_Context (Model (S), Inc.Update (Before, Data));
            Lemma_Same_Context
              (Inc.Update (Before, Piece_Data (C, M, I)),
               Logical_After (Key, C, M, Length,
                              M (I).First + Piece_Data (C, M, I)'Length,
                              Before.NN));
         end;
         P := P + M (I).Count;
         pragma Assert (if I = M'Last then P = Length);
      end loop;

      pragma Warnings
        (GNATprove, Off, """S"" is set by ""Finish"" but not used*",
         Reason => "the example is about Digest; the state ends here");
      Finish (S, Key, C, M, Length, Digest);
      pragma Warnings
        (GNATprove, On, """S"" is set by ""Finish"" but not used*");
   end Run_Loop;

   function Full_Schedule return Full_Pieces is
     ([for I in Full_Pieces'Range =>
         (Source => I - 1,
          Start  => 0,
          Count  => (if I <= 8 then 2**31 elsif I = 9 then 36 else 0),
          First  => (if I <= 9 then 2**31 * I64 (I - 1) else Max_Length))]);

   procedure Witness (Key : Byte_Array; V : Byte; Digest : out Byte_Array)
   is
   begin
      Run_Loop (Key, Filled (V), Full_Schedule, Max_Length, Digest);
   end Witness;

end Blake2b.Streaming.Example;
