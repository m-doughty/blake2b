--  Validation of the specification itself (Blake2b.Spec) against the
--  published test vectors and two independent C implementations. The
--  proof shows the implementation equals the specification; this suite
--  is what shows the specification equals BLAKE2b.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

package Spec_Suite is

   procedure Run (Kat_Path : String);

end Spec_Suite;
