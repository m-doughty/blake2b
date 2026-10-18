--  Test-only window into Blake2b.Hashing.Counter_Arithmetic, a private
--  unit. Lives in the tests crate, never in the library.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

package Blake2b.Hashing.Counter_Testing is

   --  Counter_Arithmetic.Add_Counter, so that the tests can reach the
   --  counter's carry directly: through the public interface it takes
   --  2**64 bytes. The caller keeps (Hi, Lo) + N below 2**128.
   procedure Add_Counter (Hi, Lo : in out U64; N : U64);

end Blake2b.Hashing.Counter_Testing;
