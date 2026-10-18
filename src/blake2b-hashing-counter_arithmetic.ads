--  The 128-bit counter of Blake2b.Hashing, in a unit of its own.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  Its own unit so that it is proved under the default step budget:
--  blake2b-hashing.adb has ten times as many steps for its theorems, and
--  under that budget a prover can run on for hours on a false counter
--  goal, so a dropped carry (the mutants carry and plus-carry) could not
--  be shown caught.
private package Blake2b.Hashing.Counter_Arithmetic
  with SPARK_Mode
is

   package Inc renames Blake2b.Spec.Incremental;

   function Value (Hi, Lo : U64) return Big_Natural is
     (Big.Word (Hi) * Two_64 + Big.Word (Lo))
   with Ghost;

   --  (Hi, Lo) := (Hi, Lo) + N: the 128-bit counter, carry included. Its
   --  contract states the addition twice, as arithmetic on mathematical
   --  integers and as the model's Plus (the reference implementation's
   --  increment), so a carry mistake in either one fails the proof.
   --  Inline_Always, so that it runs inside the scrubbed frame of the
   --  hardened subprogram that calls it (see Blake2b.Hashing).
   procedure Add_Counter (Hi, Lo : in out U64; N : U64)
   with Inline_Always,
        Global => null,
        Pre    => Value (Hi, Lo) + Big.Word (N) < Two_128,
        Post   =>
          (Executable =>
             Value (Hi, Lo) = Value (Hi'Old, Lo'Old) + Big.Word (N)
             and then (if N mod Block_Bytes = 0
                         and then Lo'Old mod Block_Bytes = 0
                       then Lo mod Block_Bytes = 0),
           Static     =>
             Lo = Inc.Plus ((Lo => Lo'Old, Hi => Hi'Old), N).Lo
             and then Hi = Inc.Plus ((Lo => Lo'Old, Hi => Hi'Old), N).Hi);

end Blake2b.Hashing.Counter_Arithmetic;
