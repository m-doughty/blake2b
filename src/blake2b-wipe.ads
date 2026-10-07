--  BLAKE2b (RFC 7693) in SPARK: zeroisation.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  Overwrites secret-derived data with zeroes in a way the compiler may
--  not optimise away (the pattern SPARKNaCl uses, after Regehr et al.):
--
--  * No_Inline: inlined into a caller, the stores would be dead (the
--    object is never read again) and could be deleted;
--  * Machine_Attribute "noipa": no interprocedural analysis either, so
--    the caller cannot learn that a call only writes a dead object and
--    drop the call;
--  * pragma Inspection_Point in the body: the zeroes must be in memory
--    at that point.
--
--  The postconditions are proved, but they speak only about the value
--  of the object. What a proof cannot say -- that no copy survives in a
--  register or a spill slot -- is addressed separately: the subprograms
--  that handle secrets are compiled with GCC's stack scrubbing and
--  zeroing of every call-used register (see Blake2b.Hashing).

private package Blake2b.Wipe
  with SPARK_Mode, Pure
is

   use type U64;
   use type Byte;

   procedure Sanitize_Words8 (R : out Words8)
   with Global => null,
        No_Inline,
        Post   => (for all I in Chain_Index => R (I) = 0);

   procedure Sanitize_Block (R : out Block)
   with Global => null,
        No_Inline,
        Post   => (for all I in Block_Index => R (I) = 0);

   pragma Warnings
     (GNATprove, Off, "pragma ""Machine_Attribute"" ignored*",
      Reason => "code-generation attribute: no effect on proof");
   pragma Machine_Attribute (Sanitize_Words8, "noipa");
   pragma Machine_Attribute (Sanitize_Block, "noipa");
   pragma Warnings
     (GNATprove, On, "pragma ""Machine_Attribute"" ignored*");

end Blake2b.Wipe;
