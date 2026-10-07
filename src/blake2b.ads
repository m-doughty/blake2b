--  BLAKE2b (RFC 7693) in SPARK.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Interfaces;

package Blake2b
  with SPARK_Mode, Pure
is

   --  Types shared by the implementation (Blake2b.Core) and the ghost
   --  specification (Blake2b.Spec).
   --
   --  Byte arrays are indexed by a subtype of a 64-bit signed integer,
   --  as in SPARKNaCl, so that 'Length is representable for every array
   --  and offset arithmetic (First + J, 128 * N) cannot overflow: an
   --  array spanning the whole of Natural would have a length of 2**31,
   --  which Natural cannot hold.

   subtype Byte is Interfaces.Unsigned_8;
   subtype U64 is Interfaces.Unsigned_64;

   type I64 is range -2**63 .. 2**63 - 1;
   subtype Index is I64 range 0 .. 2**31 - 1;

   type Byte_Array is array (Index range <>) of Byte;

   --  An empty byte array: the empty prefix of a one-part hash, and the
   --  empty key of an unkeyed one. Shared by the implementation and the
   --  specification, so a one-part hash is literally the same term in
   --  both.
   No_Bytes : constant Byte_Array (1 .. 0) := [others => 0];

   --  RFC 7693, section 2.1: BLAKE2b's block size, and its limits on key
   --  and digest length, in bytes.
   Block_Bytes      : constant := 128;
   Max_Key_Bytes    : constant := 64;
   Max_Digest_Bytes : constant := 64;

   subtype Key_Length is I64 range 0 .. Max_Key_Bytes;
   subtype Digest_Length is I64 range 1 .. Max_Digest_Bytes;

   subtype Block_Index is Index range 0 .. Block_Bytes - 1;
   subtype Block is Byte_Array (Block_Index);

   --  The 16-word working vector v and message block m (section 3.2).
   type Word_Index is range 0 .. 15;
   type Words16 is array (Word_Index) of U64;

   --  The 8-word chaining value h.
   type Chain_Index is range 0 .. 7;
   type Words8 is array (Chain_Index) of U64;

end Blake2b;
