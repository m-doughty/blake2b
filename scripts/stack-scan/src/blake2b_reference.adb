--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

package body Blake2b_Reference is

   type Words8 is array (0 .. 7) of Unsigned_64;
   type Words16 is array (0 .. 15) of Unsigned_64;
   type Sigma_Row is array (0 .. 15) of Natural;

   --  Section 2.6.
   IV : constant Words8 :=
     [16#6A09E667F3BCC908#, 16#BB67AE8584CAA73B#,
      16#3C6EF372FE94F82B#, 16#A54FF53A5F1D36F1#,
      16#510E527FADE682D1#, 16#9B05688C2B3E6C1F#,
      16#1F83D9ABFB41BD6B#, 16#5BE0CD19137E2179#];

   --  Section 2.7: the ten rows; round R uses row R mod 10.
   Sigma : constant array (0 .. 9) of Sigma_Row :=
     [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
      [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
      [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
      [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
      [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
      [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
      [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
      [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
      [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
      [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]];

   --  Section 3.1: G, with R1 .. R4 = 32, 24, 16, 63.
   procedure Mix_G
     (V : in out Words16; A, B, C, D : Natural; X, Y : Unsigned_64) is
   begin
      V (A) := V (A) + V (B) + X;
      V (D) := Rotate_Right (V (D) xor V (A), 32);
      V (C) := V (C) + V (D);
      V (B) := Rotate_Right (V (B) xor V (C), 24);
      V (A) := V (A) + V (B) + Y;
      V (D) := Rotate_Right (V (D) xor V (A), 16);
      V (C) := V (C) + V (D);
      V (B) := Rotate_Right (V (B) xor V (C), 63);
   end Mix_G;

   --  Section 3.2: F, with the high word of the offset counter zero.
   procedure Compress
     (H : in out Words8; Block : Bytes; T : Unsigned_64; Last : Boolean)
   is
      M : Words16 := [others => 0];
      V : Words16;
   begin
      --  Section 2.4: the block as sixteen little-endian words.
      for I in M'Range loop
         for B in 0 .. 7 loop
            M (I) := M (I)
              or Shift_Left (Unsigned_64 (Block (Block'First + 8 * I + B)),
                             8 * B);
         end loop;
      end loop;
      for I in 0 .. 7 loop
         V (I) := H (I);
         V (I + 8) := IV (I);
      end loop;
      V (12) := V (12) xor T;
      if Last then
         V (14) := not V (14);
      end if;
      for R in 0 .. 11 loop
         declare
            S : Sigma_Row renames Sigma (R mod 10);
         begin
            Mix_G (V, 0, 4, 8, 12, M (S (0)), M (S (1)));
            Mix_G (V, 1, 5, 9, 13, M (S (2)), M (S (3)));
            Mix_G (V, 2, 6, 10, 14, M (S (4)), M (S (5)));
            Mix_G (V, 3, 7, 11, 15, M (S (6)), M (S (7)));
            Mix_G (V, 0, 5, 10, 15, M (S (8)), M (S (9)));
            Mix_G (V, 1, 6, 11, 12, M (S (10)), M (S (11)));
            Mix_G (V, 2, 7, 8, 13, M (S (12)), M (S (13)));
            Mix_G (V, 3, 4, 9, 14, M (S (14)), M (S (15)));
         end;
      end loop;
      for I in 0 .. 7 loop
         H (I) := H (I) xor V (I) xor V (I + 8);
      end loop;
   end Compress;

   --  Section 3.3.
   function Chain_Values (Key : Bytes; Message : Bytes) return Word_Array
   is
      KK     : constant Natural := Key'Length;
      LL     : constant Natural := Message'Length;
      KB     : constant Natural := (if KK > 0 then 1 else 0);
      DD     : constant Natural := Natural'Max (1, KB + (LL + 127) / 128);
      Result : Word_Array (0 .. 8 * DD - 1);
      H      : Words8 := IV;
      Block  : Bytes (0 .. 127);
      T      : Unsigned_64;
   begin
      H (0) := H (0) xor 16#0101_0000# xor Shift_Left (Unsigned_64 (KK), 8)
               xor 64;
      for N in 0 .. DD - 1 loop
         Block := [others => 0];
         if N < KB then
            for J in 0 .. KK - 1 loop
               Block (J) := Key (Key'First + J);
            end loop;
         else
            for J in 0 .. 127 loop
               if 128 * (N - KB) + J < LL then
                  Block (J) := Message (Message'First + 128 * (N - KB) + J);
               end if;
            end loop;
         end if;
         if N < DD - 1 then
            T := Unsigned_64 (128 * (N + 1));
         else
            T := Unsigned_64 (LL + 128 * KB);
         end if;
         Compress (H, Block, T, Last => N = DD - 1);
         for I in 0 .. 7 loop
            Result (8 * N + I) := H (I);
         end loop;
      end loop;
      return Result;
   end Chain_Values;

end Blake2b_Reference;
