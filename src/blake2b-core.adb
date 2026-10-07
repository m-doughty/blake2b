--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Interfaces; use Interfaces;

package body Blake2b.Core
  with SPARK_Mode
is

   --  Both transcriptions are constant aggregates, so the prover settles
   --  the lemma by evaluating them.
   procedure Lemma_Tables is null;

   procedure Lemma_Same (L, R : Words16) is null;
   procedure Lemma_Same8 (L, R : Words8) is null;
   procedure Lemma_Same_Block (L, R : Block) is null;

   function Initial_H (KK : Key_Length; NN : Digest_Length) return Words8 is
   begin
      Lemma_Tables;
      return
        [IV with delta
           0 => IV (0) xor 16#0101_0000#
                  xor Shift_Left (U64 (KK), 8)
                  xor U64 (NN)];
   end Initial_H;

   function Out_Byte (H : Words8; J : I64) return Byte is
     (Byte (Shift_Right (H (Chain_Index (J / 8)), Natural (8 * (J mod 8)))
            and 16#FF#));

   function Load64 (B : Block; I : Word_Index) return U64 is
      P : constant Block_Index := Block_Index (8 * I64 (I));
   begin
      return U64 (B (P))
        or Shift_Left (U64 (B (P + 1)), 8)
        or Shift_Left (U64 (B (P + 2)), 16)
        or Shift_Left (U64 (B (P + 3)), 24)
        or Shift_Left (U64 (B (P + 4)), 32)
        or Shift_Left (U64 (B (P + 5)), 40)
        or Shift_Left (U64 (B (P + 6)), 48)
        or Shift_Left (U64 (B (P + 7)), 56);
   end Load64;

   --  The sixteen message words of a block. Sixteen separate loads, not a
   --  loop: GCC then merges each byte-gather into a single 64-bit load
   --  (as a memcpy would be), where a loop is auto-vectorised into SSE
   --  byte shuffles that cost a quarter of Compress. A function of its
   --  own so that Compress's proof sees one fact, not sixteen.
   function Load_Words (B : Block) return Words16 is
     ([Load64 (B, 0), Load64 (B, 1), Load64 (B, 2), Load64 (B, 3),
       Load64 (B, 4), Load64 (B, 5), Load64 (B, 6), Load64 (B, 7),
       Load64 (B, 8), Load64 (B, 9), Load64 (B, 10), Load64 (B, 11),
       Load64 (B, 12), Load64 (B, 13), Load64 (B, 14), Load64 (B, 15)])
   with Inline,
        Global => null,
        Post   => Load_Words'Result = Spec.Words_Of (B);

   --  The four words G touches are read into locals, mixed, and written
   --  back, so the optimiser keeps them in registers.
   procedure G
     (V          : in out Words16;
      A, B, C, D : Word_Index;
      X, Y       : U64)
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", Spec.G);
      VA : U64 := V (A);
      VB : U64 := V (B);
      VC : U64 := V (C);
      VD : U64 := V (D);
   begin
      VA := VA + VB + X;
      VD := Rotate_Right (VD xor VA, 32);
      VC := VC + VD;
      VB := Rotate_Right (VB xor VC, 24);
      VA := VA + VB + Y;
      VD := Rotate_Right (VD xor VA, 16);
      VC := VC + VD;
      VB := Rotate_Right (VB xor VC, 63);
      V (A) := VA;
      V (B) := VB;
      V (C) := VC;
      V (D) := VD;
   end G;

   --  After each G, Lemma_Same records that V is logically the spec's G
   --  of the previous V, so the eight steps compose into Spec.Round by
   --  substitution. Prev is Static ghost state: proof only.
   procedure Round (V : in out Words16; M : Words16; R : Round_Number) is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", Spec.Round);
      S    : constant Schedule_Row := SIGMA (R);
      Prev : Words16 := V with Ghost => Static;
   begin
      Lemma_Tables;

      G (V, 0, 4, 8, 12, M (S (0)), M (S (1)));
      Lemma_Same (V, Spec.G (Prev, 0, 4, 8, 12, M (S (0)), M (S (1))));
      Prev := V;
      G (V, 1, 5, 9, 13, M (S (2)), M (S (3)));
      Lemma_Same (V, Spec.G (Prev, 1, 5, 9, 13, M (S (2)), M (S (3))));
      Prev := V;
      G (V, 2, 6, 10, 14, M (S (4)), M (S (5)));
      Lemma_Same (V, Spec.G (Prev, 2, 6, 10, 14, M (S (4)), M (S (5))));
      Prev := V;
      G (V, 3, 7, 11, 15, M (S (6)), M (S (7)));
      Lemma_Same (V, Spec.G (Prev, 3, 7, 11, 15, M (S (6)), M (S (7))));
      Prev := V;
      G (V, 0, 5, 10, 15, M (S (8)), M (S (9)));
      Lemma_Same (V, Spec.G (Prev, 0, 5, 10, 15, M (S (8)), M (S (9))));
      Prev := V;
      G (V, 1, 6, 11, 12, M (S (10)), M (S (11)));
      Lemma_Same (V, Spec.G (Prev, 1, 6, 11, 12, M (S (10)), M (S (11))));
      Prev := V;
      G (V, 2, 7, 8, 13, M (S (12)), M (S (13)));
      Lemma_Same (V, Spec.G (Prev, 2, 7, 8, 13, M (S (12)), M (S (13))));
      Prev := V;
      G (V, 3, 4, 9, 14, M (S (14)), M (S (15)));
      Lemma_Same (V, Spec.G (Prev, 3, 4, 9, 14, M (S (14)), M (S (15))));
   end Round;

   --  The twelve rounds are written out rather than looped: with each
   --  round number a constant, the inlined schedule lookups fold to
   --  constant indices, as in the reference implementation's unrolled
   --  ROUND (0) .. ROUND (11). Each Lemma_Same step carries the proof
   --  that V is Spec.Rounds of the initial vector after k rounds.
   procedure Compress
     (H    : in out Words8;
      B    : Block;
      T_Lo : U64;
      T_Hi : U64;
      Last : Boolean)
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", Spec.Compress);
      M    : constant Words16 := Load_Words (B);
      V    : Words16 :=
        [H (0), H (1), H (2), H (3), H (4), H (5), H (6), H (7),
         IV (0), IV (1), IV (2), IV (3),
         IV (4) xor T_Lo,
         IV (5) xor T_Hi,
         (if Last then not IV (6) else IV (6)),
         IV (7)];
      Init : constant Words16 := V with Ghost => Static;
   begin
      Lemma_Tables;
      Lemma_Same (M, Spec.Words_Of (B));
      Lemma_Same (Init, Spec.Initial_V (H, T_Lo, T_Hi, Last));

      Round (V, M, 0);
      Lemma_Same (V, Spec.Rounds (Init, M, 1));
      Round (V, M, 1);
      Lemma_Same (V, Spec.Rounds (Init, M, 2));
      Round (V, M, 2);
      Lemma_Same (V, Spec.Rounds (Init, M, 3));
      Round (V, M, 3);
      Lemma_Same (V, Spec.Rounds (Init, M, 4));
      Round (V, M, 4);
      Lemma_Same (V, Spec.Rounds (Init, M, 5));
      Round (V, M, 5);
      Lemma_Same (V, Spec.Rounds (Init, M, 6));
      Round (V, M, 6);
      Lemma_Same (V, Spec.Rounds (Init, M, 7));
      Round (V, M, 7);
      Lemma_Same (V, Spec.Rounds (Init, M, 8));
      Round (V, M, 8);
      Lemma_Same (V, Spec.Rounds (Init, M, 9));
      Round (V, M, 9);
      Lemma_Same (V, Spec.Rounds (Init, M, 10));
      Round (V, M, 10);
      Lemma_Same (V, Spec.Rounds (Init, M, 11));
      Round (V, M, 11);
      Lemma_Same (V, Spec.Rounds (Init, M, 12));
      --  The term Spec.Compress's body names: the same value, with the
      --  initial vector and message words written as the spec writes them.
      Lemma_Same
        (V, Spec.Rounds (Spec.Initial_V (H, T_Lo, T_Hi, Last),
                         Spec.Words_Of (B), 12));

      H := [for I in Chain_Index =>
              H (I) xor V (Word_Index (I)) xor V (Word_Index (I) + 8)];
   end Compress;

end Blake2b.Core;
