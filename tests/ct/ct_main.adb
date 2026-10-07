--  Constant-time check: runs every entry point with the key and message
--  marked secret ("undefined") for Valgrind's memcheck. Run as
--
--    scripts/check-constant-time.sh
--
--  Any branch or memory index computed from secret bytes is reported and
--  fails the run. Lengths are public (BLAKE2b's control flow depends on
--  them by design); contents are not.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Ada.Command_Line;
with Interfaces.C;
with System;

with Blake2b;         use Blake2b;
with Blake2b.Hashing;

procedure CT_Main is

   procedure Poison (Addr : System.Address; Len : Interfaces.C.size_t)
   with Import, Convention => C, External_Name => "ct_poison";

   procedure Unpoison (Addr : System.Address; Len : Interfaces.C.size_t)
   with Import, Convention => C, External_Name => "ct_unpoison";

   procedure Negative_Control
   with Import, Convention => C, External_Name => "ct_negative_control";

   procedure Mark_Secret (B : Byte_Array) is
   begin
      if B'Length > 0 then
         Poison (B (B'First)'Address, Interfaces.C.size_t (B'Length));
      end if;
   end Mark_Secret;

   procedure Mark_Public (B : Byte_Array) is
   begin
      if B'Length > 0 then
         Unpoison (B (B'First)'Address, Interfaces.C.size_t (B'Length));
      end if;
   end Mark_Public;

   Sizes : constant array (1 .. 9) of I64 :=
     [0, 1, 64, 127, 128, 129, 255, 1_000, 4_096];
   Keys  : constant array (1 .. 3) of Key_Length := [0, 32, 64];

   S : Blake2b.Hashing.State;

begin
   if Ada.Command_Line.Argument_Count > 1
     or else (Ada.Command_Line.Argument_Count = 1
              and then Ada.Command_Line.Argument (1) /= "--negative-control")
   then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   for Size of Sizes loop
      for KK of Keys loop
         declare
            Message : constant Byte_Array (0 .. Size - 1) :=
              [others => 16#5A#];
            Key     : constant Byte_Array (0 .. KK - 1) := [others => 16#A5#];
            Digest  : Byte_Array (0 .. 63);
         begin
            Mark_Secret (Message);
            Mark_Secret (Key);

            Blake2b.Hashing.Hash (Message, Key, Digest);
            Mark_Public (Digest);

            Blake2b.Hashing.Hash
              (Message (0 .. Size / 2 - 1), Message (Size / 2 .. Size - 1),
               Key, Digest);
            Mark_Public (Digest);

            Blake2b.Hashing.Init (S, 64, Key);
            Blake2b.Hashing.Update (S, Message (0 .. Size / 3 - 1));
            Blake2b.Hashing.Update (S, Message (Size / 3 .. Size - 1));
            Blake2b.Hashing.Final (S, Digest);
            Mark_Public (Digest);
         end;
      end loop;
   end loop;

   --  Exercise the same hashing workload before the deliberately unsafe
   --  branch, so the negative control also checks the normal call paths.
   if Ada.Command_Line.Argument_Count = 1 then
      Negative_Control;
   end if;
end CT_Main;
