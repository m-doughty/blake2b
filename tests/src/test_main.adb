--  blake2b test runner.
--
--  Usage: test_main [--small] [--contracts] [path/to/blake2-kat.json]
--
--    --small      fewer, shorter random cases, and every cut into three
--                 pieces only up to 64 bytes (the other key and digest
--                 lengths up to 129): for the matrix cell built
--                 with contracts enabled, which executes every loop
--                 invariant (each a fold over all previous blocks, so
--                 quadratic in length).
--    --contracts  the library was built with contracts enabled: also
--                 check that misuse is rejected by the preconditions.
--
--         test_main --vectors <file.json>
--
--    checks only the vectors in <file.json> (laid out like
--    blake2-kat.json, any key and digest lengths): the third-oracle run,
--    with vectors from scripts/cpython-vectors.py.
--
--         test_main --long
--
--    runs only the long streams (2**32 + 129 and 2**34 + 36 bytes, about
--    20 GiB hashed by the implementation and by each C oracle; see
--    long_suite.ads). Not part of the default run or of the build
--    matrix. Build the release profile first (alr -n build --release).
--
--  The known-answer file defaults to data/blake2-kat.json, relative to
--  the tests/ directory. Exits non-zero if any check fails.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Ada.Command_Line;      use Ada.Command_Line;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;

with Impl_Suite;
with Long_Suite;
with Spec_Suite;
with Test_Support;

procedure Test_Main is
   Small     : Boolean := False;
   Contracts : Boolean := False;
   Long      : Boolean := False;
   Vectors   : Unbounded_String;
   Kat_Path  : Unbounded_String :=
     To_Unbounded_String ("data/blake2-kat.json");
begin
   declare
      I : Positive := 1;
   begin
      while I <= Argument_Count loop
         if Argument (I) = "--small" then
            Small := True;
         elsif Argument (I) = "--contracts" then
            Contracts := True;
         elsif Argument (I) = "--long" then
            Long := True;
         elsif Argument (I) = "--vectors" and then I < Argument_Count then
            I := I + 1;
            Vectors := To_Unbounded_String (Argument (I));
         else
            Kat_Path := To_Unbounded_String (Argument (I));
         end if;
         I := I + 1;
      end loop;
   end;

   if Long then
      Long_Suite.Run;
      Test_Support.Summary;
      Set_Exit_Status
        (if Test_Support.Failures = 0 then Success else Failure);
      return;
   end if;

   if Length (Vectors) > 0 then
      Impl_Suite.Vectors (To_String (Vectors));
      Test_Support.Summary;
      Set_Exit_Status
        (if Test_Support.Failures = 0 then Success else Failure);
      return;
   end if;

   Spec_Suite.Run (To_String (Kat_Path));
   if Small then
      Impl_Suite.Run
        (To_String (Kat_Path), Random_Count => 2_000, Max_Length => 300,
         Cut_Length => 64, Cut_Subset => 129, Contracts => Contracts);
   else
      Impl_Suite.Run
        (To_String (Kat_Path), Random_Count => 100_000, Max_Length => 4_096,
         Cut_Length => 300, Cut_Subset => 300, Contracts => Contracts);
   end if;

   Test_Support.Summary;
   Set_Exit_Status (if Test_Support.Failures = 0 then Success else Failure);
end Test_Main;
