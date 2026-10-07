--  BLAKE2b (RFC 7693) in SPARK: the compression core.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Blake2b.Spec;

--  Every subprogram here carries a postcondition stating that it computes
--  exactly what Blake2b.Spec says, and GNATprove proves each one.
--
--  The tables are transcribed independently of the specification's: the
--  message schedule here has twelve rows, one per round, as the BLAKE2
--  reference C does, where the RFC's has ten rows indexed modulo 10. A
--  lemma proves the two transcriptions agree, so a typo in either is a
--  proof failure rather than a silent shared mistake.

private package Blake2b.Core
  with SPARK_Mode, Pure
is

   use type U64;
   use type Byte;

   IV : constant Words8 :=
     [16#6A09_E667_F3BC_C908#, 16#BB67_AE85_84CA_A73B#,
      16#3C6E_F372_FE94_F82B#, 16#A54F_F53A_5F1D_36F1#,
      16#510E_527F_ADE6_82D1#, 16#9B05_688C_2B3E_6C1F#,
      16#1F83_D9AB_FB41_BD6B#, 16#5BE0_CD19_137E_2179#];

   type Round_Number is range 0 .. 11;
   type Schedule_Row is array (Word_Index) of Word_Index;
   type Schedule is array (Round_Number) of Schedule_Row;

   SIGMA : constant Schedule :=
     [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
      [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
      [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
      [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
      [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
      [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
      [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
      [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
      [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
      [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
      [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]];

   --  The two transcriptions of each table agree.
   procedure Lemma_Tables
   with Ghost,
        Global => null,
        Post   =>
          (for all I in Chain_Index => IV (I) = Spec.IV (I))
          and then
          (for all R in Round_Number =>
             (for all I in Word_Index =>
                SIGMA (R) (I)
                = Spec.SIGMA (Spec.Sigma_Index (R mod 10)) (I)));

   --  Proof machinery (never executed: Static ghost code is not compiled
   --  into any build). Ada's "=" on arrays reaches the provers as
   --  element-wise equality, and they will not substitute element-wise
   --  equal arrays into an opaque function such as Spec.Round. Same is
   --  interpreted as logical equality, which they substitute freely;
   --  Lemma_Same converts one into the other (array extensionality).
   function Same (L, R : Words16) return Boolean
   with Ghost    => Static,
        Import,
        Global   => null,
        Annotate => (GNATprove, Logical_Equal);

   procedure Lemma_Same (L, R : Words16)
   with Ghost  => Static,
        Global => null,
        Pre    => L = R,
        Post   => Same (L, R);

   --  The same for chaining values and blocks.
   function Same8 (L, R : Words8) return Boolean
   with Ghost    => Static,
        Import,
        Global   => null,
        Annotate => (GNATprove, Logical_Equal);

   procedure Lemma_Same8 (L, R : Words8)
   with Ghost  => Static,
        Global => null,
        Pre    => L = R,
        Post   => Same8 (L, R);

   function Same_Block (L, R : Block) return Boolean
   with Ghost    => Static,
        Import,
        Global   => null,
        Annotate => (GNATprove, Logical_Equal);

   procedure Lemma_Same_Block (L, R : Block)
   with Ghost  => Static,
        Global => null,
        Pre    => L = R,
        Post   => Same_Block (L, R);

   --  Section 3.3: the initial chaining value with the parameter block.
   function Initial_H (KK : Key_Length; NN : Digest_Length) return Words8
   with Global => null,
        Post   => Initial_H'Result = Spec.Initial_H (KK, NN);

   --  Section 3.3: byte J of the digest, from h read little-endian.
   function Out_Byte (H : Words8; J : I64) return Byte
   with Inline,
        Global => null,
        Pre    => J in 0 .. Max_Digest_Bytes - 1,
        Post   => Out_Byte'Result = Spec.Out_Byte (H, J);

   --  Section 2.4: little-endian load of word I of a block.
   function Load64 (B : Block; I : Word_Index) return U64
   with Inline,
        Global => null,
        Post   => Load64'Result = Spec.Word_At (B, I);

   --  Section 3.1.
   procedure G
     (V          : in out Words16;
      A, B, C, D : Word_Index;
      X, Y       : U64)
   with Inline_Always,
        Global => null,
        Pre    => Spec.Distinct (A, B, C, D),
        Post   => V = Spec.G (V'Old, A, B, C, D, X, Y);

   --  Section 3.2: round R of F.
   procedure Round (V : in out Words16; M : Words16; R : Round_Number)
   with Inline_Always,
        Global => null,
        Post   => V = Spec.Round (V'Old, M, Spec.Round_Number (R));

   --  Section 3.2: the compression function F, updating H in place.
   procedure Compress
     (H    : in out Words8;
      B    : Block;
      T_Lo : U64;
      T_Hi : U64;
      Last : Boolean)
   with Global => null,
        Post   => H = Spec.Compress (H'Old, B, T_Lo, T_Hi, Last);

end Blake2b.Core;
