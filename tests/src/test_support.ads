--  Shared test-harness support: pass/fail accounting, hex conversion and
--  a deterministic random generator.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Blake2b; use Blake2b;

package Test_Support is

   use type U64;

   --  Accounting. Fail prints the first Max_Reported failures in full and
   --  counts the rest.
   procedure Section (Name : String);
   procedure Pass;
   procedure Fail (What : String);
   function Passes return Natural;
   function Failures return Natural;
   procedure Summary;

   --  Hex. From_Hex returns an array indexed from 0.
   function From_Hex (S : String) return Byte_Array;
   function To_Hex (B : Byte_Array) return String;

   --  The input pattern of the BLAKE2 known-answer tests: 0, 1, 2, ...
   --  modulo 256, indexed from 0.
   function Counting (Length : I64) return Byte_Array;

   --  A copy of B whose index range starts at First.
   function Rebase (B : Byte_Array; First : Index) return Byte_Array
   with Pre => B'Length = 0 or else First <= Index'Last - (B'Length - 1);

   --  splitmix64: small, fast, statistically sound, and identical on
   --  every platform, so a failing case is replayed from its seed.
   type Generator is private;

   function Make (Seed : U64) return Generator;
   procedure Next (G : in out Generator; Value : out U64);
   function Below (G : in out Generator; Bound : U64) return U64
   with Pre => Bound > 0;
   function Random_Bytes (G : in out Generator; Length : I64)
      return Byte_Array;

   --  A piece size for incremental tests, at most Left: usually one of
   --  the edge sizes around a block (0, 1, 2, 63, 64, 127, 128, 129, 255,
   --  256), sometimes any size.
   function Chunk_Size (G : in out Generator; Left : I64) return I64
   with Pre => Left >= 0;

private

   type Generator is record
      State : U64 := 0;
   end record;

end Test_Support;
