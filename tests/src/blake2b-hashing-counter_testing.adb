--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  Compiled without -gnata (see blake2b_tests.gpr): Add_Counter's
--  contract, written with ghost big integers the library's profiles do not
--  compile, would otherwise be expanded here by the inlining.

with Blake2b.Hashing.Counter_Arithmetic;

package body Blake2b.Hashing.Counter_Testing is

   procedure Add_Counter (Hi, Lo : in out U64; N : U64) is
   begin
      Counter_Arithmetic.Add_Counter (Hi, Lo, N);
   end Add_Counter;

end Blake2b.Hashing.Counter_Testing;
