--  Test-only window into Blake2b.Hashing.State. Lives in the tests crate,
--  never in the library.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Blake2b.Spec.Incremental;

package Blake2b.Hashing.Testing is

   --  Every component that can hold key- or input-derived data is zero.
   function Is_Wiped (S : State) return Boolean;

   --  Blake2b.Hashing.Model, which is Static ghost code (proved, never
   --  compiled), restated so that the tests can execute it: the hash in
   --  progress as Blake2b.Spec.Incremental describes it. Keep the two
   --  definitions identical.
   function Model_Of (S : State) return Spec.Incremental.Context
   with Ghost;

end Blake2b.Hashing.Testing;
