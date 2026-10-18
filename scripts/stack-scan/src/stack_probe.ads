--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  Measurement support for scripts/check-stack-scan.sh: not part of
--  the library, and never built with it. It reads and clears the stack
--  below the caller's frame, and counts known 64-bit patterns in what it
--  read.

with Interfaces; use Interfaces;

package Stack_Probe is

   type Word_Array is array (Natural range <>) of Unsigned_64;
   type Word_Array_Access is access Word_Array;

   --  The stack region below the caller's frame, Dest'Length words long:
   --  with Snap False, every word of it is set to zero; with Snap True, it
   --  is copied, unread by anything else, into Dest (Dest (0) is its
   --  lowest address, the deepest). Both modes are the same procedure, so
   --  that called from the same frame they cover the same addresses.
   procedure Region (Snap : Boolean; Dest : Word_Array_Access);
   pragma No_Inline (Region);
   pragma Machine_Attribute (Region, "noipa");

   --  SplitMix64's output function: distinct seeds give distinct,
   --  patternless 64-bit values (it is a bijection).
   function Mix (Seed : Unsigned_64) return Unsigned_64;

   --  Occurrences in Snap, read as little-endian bytes, of each word of
   --  Class: Aligned at offsets that are a multiple of 8 bytes, Unaligned
   --  at the other offsets; Distinct is the number of words of Class found
   --  at least once.
   procedure Count
     (Snap      : Word_Array;
      Class     : Word_Array;
      Aligned   : out Natural;
      Unaligned : out Natural;
      Distinct  : out Natural);

   --  How many bytes at the top of Snap (from its highest address down to
   --  its deepest nonzero byte) hold something other than zero: after a
   --  scrub, the depth of stack the call in between wrote.
   function Touched (Snap : Word_Array) return Natural;

   --  Prints one line: Prefix, then touched=<Touched (Snap)> class=<Name>
   --  aligned=<n> unaligned=<n> distinct=<n> (see Count) depths=<list>:
   --  for each of the first eight hits, D#K, where D is the depth of its
   --  first byte below the top of the region (the hit lies D bytes below
   --  the helper's frame) and K the index in Class of the word found, or
   --  "-" if there is none.
   procedure Put_Hits
     (Prefix : String; Snap : Word_Array; Name : String; Class : Word_Array);

end Stack_Probe;
