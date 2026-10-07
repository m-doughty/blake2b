--  Reader for the BLAKE2 team's published known-answer tests,
--  testvectors/blake2-kat.json, vendored byte-for-byte under data/.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Blake2b; use Blake2b;

package Kat_Json is

   --  SHA-256 of the vendored file (see ref/SOURCES.md). The suite
   --  refuses to run against a file with any other digest, so a
   --  line-ending conversion or an accidental edit cannot go unnoticed.
   Pinned_SHA256 : constant String :=
     "5031ac14800798ae15cee79c04d65e326a575f2c968c7e2846a79bd07a1c0e61";

   --  Lower-case hex SHA-256 of the file at Path.
   function File_Digest (Path : String) return String;

   --  Calls Visit for every entry whose "hash" is "blake2b": 256 unkeyed
   --  and 256 keyed (key 00 .. 3f), inputs 00 .. n - 1 for n in 0 .. 255,
   --  64-byte outputs. Count is the number of entries visited.
   generic
      with procedure Visit (Input, Key, Expected : Byte_Array);
   procedure For_Each_Blake2b (Path : String; Count : out Natural);

end Kat_Json;
