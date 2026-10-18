--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

package body Blake2b.Hashing.Counter_Arithmetic
  with SPARK_Mode
is

   procedure Add_Counter (Hi, Lo : in out U64; N : U64) is
   begin
      Lo := Lo + N;
      if Lo < N then
         Hi := Hi + 1;
      end if;
   end Add_Counter;

end Blake2b.Hashing.Counter_Arithmetic;
