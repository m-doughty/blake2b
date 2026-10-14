--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

pragma Assertion_Policy (Check);

with Ada.Real_Time; use Ada.Real_Time;
with Ada.Text_IO;   use Ada.Text_IO;
with Ada.Unchecked_Deallocation;
with Interfaces;    use Interfaces;

with Blake2b;         use Blake2b;
with Blake2b.Hashing;
with Oracles;
with Test_Support;    use Test_Support;

package body Long_Suite is

   type Bytes_Access is access Byte_Array;
   procedure Free is new Ada.Unchecked_Deallocation (Byte_Array, Bytes_Access);

   --  The largest piece each side generates and absorbs at once.
   Max_Ada_Piece : constant I64 := 64 * 2**20;
   Max_C_Piece   : constant I64 := 16 * 2**20;

   --  The stream's content, a function of position alone, so that every
   --  implementation sees the same bytes wherever it cuts the stream:
   --  byte P is byte P mod 8 (little-endian) of the splitmix64 output for
   --  word P / 8 under Seed.
   function Word (Seed, W : U64) return U64 is
      Z : U64 := Seed + (W + 1) * 16#9E37_79B9_7F4A_7C15#;
   begin
      Z := (Z xor Shift_Right (Z, 30)) * 16#BF58_476D_1CE4_E5B9#;
      Z := (Z xor Shift_Right (Z, 27)) * 16#94D0_49BB_1331_11EB#;
      return Z xor Shift_Right (Z, 31);
   end Word;

   --  Buf := the stream's bytes Pos .. Pos + Buf'Length - 1.
   procedure Fill (Buf : out Byte_Array; Seed : U64; Pos : U64) is
      P : U64 := Pos;
      W : U64 :=
        Shift_Right (Word (Seed, Pos / 8), Natural (8 * (Pos mod 8)));
   begin
      for I in Buf'Range loop
         if P mod 8 = 0 then
            W := Word (Seed, P / 8);
         end if;
         Buf (I) := Byte (W and 16#FF#);
         W := Shift_Right (W, 8);
         P := P + 1;
      end loop;
   end Fill;

   --  The implementation's next piece, at most Left bytes: often empty,
   --  one byte or about one block, otherwise up to Max_Ada_Piece. A
   --  piece never crosses a power of two from 2**31 on, so the
   --  implementation is cut exactly at 2**31, 2**32, ... (where the old
   --  2**31-byte limit and the 32-bit boundaries lie; the 64-bit byte
   --  counter's low word turns over only at 2**64, which no test reaches),
   --  while the oracles' random cuts straddle those points.
   function Ada_Piece (G : in out Generator; Pos, Left : U64) return I64 is
      Pick : constant U64 := Below (G, 16);
      Mark : U64 := 2**31;
      N    : U64;
   begin
      N :=
        (case Pick is
           when 0      => 0,
           when 1      => 1,
           when 2      => 127,
           when 3      => 128,
           when 4      => 129,
           when 5      => 2**20,
           when others => Below (G, U64 (Max_Ada_Piece)) + 1);
      while Mark <= Pos loop
         Mark := Mark * 2;
      end loop;
      return I64 (U64'Min (N, U64'Min (Left, Mark - Pos)));
   end Ada_Piece;

   --  The oracles' next piece, at most Left bytes: sometimes empty or
   --  short, otherwise up to Max_C_Piece, with no alignment.
   function C_Piece (G : in out Generator; Left : U64) return I64 is
      Pick : constant U64 := Below (G, 16);
      N    : U64;
   begin
      N :=
        (case Pick is
           when 0      => 0,
           when 1      => Below (G, 256),
           when others => Below (G, U64 (Max_C_Piece)) + 1);
      return I64 (U64'Min (N, Left));
   end C_Piece;

   function Seconds (Since : Time) return String is
     (Duration'Image (To_Duration (Clock - Since)) & " s");

   procedure Check_Stream
     (Total : U64; KK : Key_Length; NN : Digest_Length; Seed : U64)
   is
      Tag  : constant String :=
        "stream of" & Total'Image & " bytes, kk=" & KK'Image & " nn="
        & NN'Image;
      G    : Generator := Make (Seed);
      Key  : constant Byte_Array := Random_Bytes (G, KK);
      Buf  : Bytes_Access := new Byte_Array (0 .. Max_Ada_Piece - 1);
      Got  : Byte_Array (0 .. NN - 1);
      Ref  : Byte_Array (0 .. NN - 1);
      Mono : Byte_Array (0 .. NN - 1);
   begin
      Section ("long " & Tag & ", vs reference C and Monocypher");

      --  The implementation, in its own pieces.
      declare
         Pieces : Natural := 0;
         Pos    : U64 := 0;
         Start  : constant Time := Clock;
         S      : Blake2b.Hashing.State;
         Cuts   : Generator := Make (Seed xor 16#ADA_C075#);
      begin
         Blake2b.Hashing.Init (S, NN, Key);
         while Pos < Total loop
            declare
               N : constant I64 := Ada_Piece (Cuts, Pos, Total - Pos);
            begin
               Fill (Buf (0 .. N - 1), Seed, Pos);
               Blake2b.Hashing.Update (S, Buf (0 .. N - 1));
               Pos := Pos + U64 (N);
               Pieces := Pieces + 1;
            end;
         end loop;
         Blake2b.Hashing.Final (S, Got);
         Put_Line ("   implementation:" & Pieces'Image & " Updates,"
                   & Seconds (Start) & " (generation included)");
      end;

      --  Both C oracles, fed the same pieces, cut elsewhere.
      declare
         Pieces : Natural := 0;
         Pos    : U64 := 0;
         Start  : constant Time := Clock;
         R      : Oracles.Reference_State;
         M      : Oracles.Monocypher_State;
         Cuts   : Generator := Make (Seed xor 16#C_C075#);
      begin
         Oracles.Init (R, NN, Key);
         Oracles.Init (M, NN, Key);
         while Pos < Total loop
            declare
               N : constant I64 := C_Piece (Cuts, Total - Pos);
            begin
               Fill (Buf (0 .. N - 1), Seed, Pos);
               Oracles.Update (R, Buf (0 .. N - 1));
               Oracles.Update (M, Buf (0 .. N - 1));
               Pos := Pos + U64 (N);
               Pieces := Pieces + 1;
            end;
         end loop;
         Oracles.Final (R, Ref);
         Oracles.Final (M, Mono);
         Put_Line ("   reference C and Monocypher:" & Pieces'Image
                   & " updates each," & Seconds (Start)
                   & " (generation included)");
      end;
      Free (Buf);

      Put_Line ("   digest " & To_Hex (Got));
      if Got = Ref then
         Pass;
      else
         Fail (Tag & ": got " & To_Hex (Got) & ", reference C "
               & To_Hex (Ref));
      end if;
      if Got = Mono then
         Pass;
      else
         Fail (Tag & ": got " & To_Hex (Got) & ", Monocypher "
               & To_Hex (Mono));
      end if;
   end Check_Stream;

   procedure Run is
   begin
      Check_Stream (Total => 2**32 + 129, KK => 0, NN => 64,
                    Seed => 16#1_0000_0081#);
      Check_Stream (Total => 2**34 + 36, KK => 64, NN => 32,
                    Seed => 16#4_0000_0024#);
   end Run;

end Long_Suite;
