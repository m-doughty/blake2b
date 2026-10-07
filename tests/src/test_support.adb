--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Ada.Text_IO; use Ada.Text_IO;
with Interfaces;  use Interfaces;

package body Test_Support is

   Max_Reported : constant := 25;

   Pass_Count : Natural := 0;
   Fail_Count : Natural := 0;

   procedure Section (Name : String) is
   begin
      Put_Line ("== " & Name);
   end Section;

   procedure Pass is
   begin
      Pass_Count := Pass_Count + 1;
   end Pass;

   procedure Fail (What : String) is
   begin
      Fail_Count := Fail_Count + 1;
      if Fail_Count <= Max_Reported then
         Put_Line ("   FAIL: " & What);
      elsif Fail_Count = Max_Reported + 1 then
         Put_Line ("   (further failures counted, not printed)");
      end if;
   end Fail;

   function Passes return Natural is (Pass_Count);
   function Failures return Natural is (Fail_Count);

   procedure Summary is
   begin
      Put_Line ("passed:" & Pass_Count'Image & "  failed:" & Fail_Count'Image);
   end Summary;

   Hex_Digits : constant String := "0123456789abcdef";

   function Nibble (C : Character) return Byte is
   begin
      case C is
         when '0' .. '9' =>
            return Byte (Character'Pos (C) - Character'Pos ('0'));
         when 'a' .. 'f' =>
            return Byte (Character'Pos (C) - Character'Pos ('a') + 10);
         when 'A' .. 'F' =>
            return Byte (Character'Pos (C) - Character'Pos ('A') + 10);
         when others =>
            raise Constraint_Error with "not a hex digit: '" & C & "'";
      end case;
   end Nibble;

   function From_Hex (S : String) return Byte_Array is
   begin
      if S'Length mod 2 /= 0 then
         raise Constraint_Error with "odd-length hex string";
      end if;
      return Result : Byte_Array (0 .. I64 (S'Length / 2) - 1) do
         for I in Result'Range loop
            declare
               P : constant Positive := S'First + 2 * Natural (I);
            begin
               Result (I) := Nibble (S (P)) * 16 + Nibble (S (P + 1));
            end;
         end loop;
      end return;
   end From_Hex;

   function To_Hex (B : Byte_Array) return String is
      Result : String (1 .. 2 * B'Length);
      P      : Positive := 1;
   begin
      for X of B loop
         Result (P)     := Hex_Digits (Natural (X / 16) + 1);
         Result (P + 1) := Hex_Digits (Natural (X mod 16) + 1);
         P := P + 2;
      end loop;
      return Result;
   end To_Hex;

   function Counting (Length : I64) return Byte_Array is
     [for I in 0 .. Length - 1 => Byte (I mod 256)];

   function Rebase (B : Byte_Array; First : Index) return Byte_Array is
      Result : Byte_Array (First .. First + B'Length - 1);
   begin
      Result := B;
      return Result;
   end Rebase;

   function Make (Seed : U64) return Generator is ((State => Seed));

   procedure Next (G : in out Generator; Value : out U64) is
      Z : U64;
   begin
      G.State := G.State + 16#9E37_79B9_7F4A_7C15#;
      Z := G.State;
      Z := (Z xor Shift_Right (Z, 30)) * 16#BF58_476D_1CE4_E5B9#;
      Z := (Z xor Shift_Right (Z, 27)) * 16#94D0_49BB_1331_11EB#;
      Value := Z xor Shift_Right (Z, 31);
   end Next;

   function Below (G : in out Generator; Bound : U64) return U64 is
      V : U64;
   begin
      Next (G, V);
      return V mod Bound;
   end Below;

   function Random_Bytes (G : in out Generator; Length : I64)
      return Byte_Array
   is
      Result : Byte_Array (0 .. Length - 1);
      V      : U64 := 0;
   begin
      for I in Result'Range loop
         if I mod 8 = 0 then
            Next (G, V);
         end if;
         Result (I) := Byte (V and 16#FF#);
         V := Shift_Right (V, 8);
      end loop;
      return Result;
   end Random_Bytes;

   function Chunk_Size (G : in out Generator; Left : I64) return I64 is
      Edges : constant array (0 .. 9) of I64 :=
        [0, 1, 2, 63, 64, 127, 128, 129, 255, 256];
      Pick  : constant U64 := Below (G, 12);
   begin
      if Pick < 10 then
         return I64'Min (Edges (Integer (Pick)), Left);
      else
         return I64 (Below (G, U64 (Left) + 1));
      end if;
   end Chunk_Size;

end Test_Support;
