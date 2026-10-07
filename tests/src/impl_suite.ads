--  Tests of the implementation (Blake2b.Hashing) against the published
--  vectors, both C oracles and the executable specification.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

package Impl_Suite is

   --  Random_Count seeded random cases of up to Max_Length bytes:
   --  100_000 of up to 4 KiB for the full suite, fewer and smaller for
   --  the contracts build, which executes every loop invariant.
   --  Contracts: the library was built with contracts enabled, so misuse
   --  (Update before Init, a wrong digest length) must be rejected.
   procedure Run
     (Kat_Path     : String;
      Random_Count : Natural;
      Max_Length   : Natural;
      Contracts    : Boolean);

   --  Third oracle: checks the implementation AND the specification
   --  against every "blake2b" vector in a file laid out like
   --  blake2-kat.json, with any key and digest lengths (for instance the
   --  output of scripts/cpython-vectors.py). The file's digest is not
   --  pinned: it is generated, not vendored.
   procedure Vectors (Path : String);

end Impl_Suite;
