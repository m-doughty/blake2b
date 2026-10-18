--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  A plain transcription of RFC 7693 (sections 2.4 and 3.1 to 3.3),
--  independent of the library, for the driver of scripts/check-stack-scan.sh:
--  it gives the chaining value after every compression of a hash, so that
--  those values can be looked for on the stack. The driver checks its last
--  value against the library's digest before using it.

with Interfaces; use Interfaces;

with Stack_Probe; use Stack_Probe;

package Blake2b_Reference is

   type Bytes is array (Natural range <>) of Unsigned_8;

   --  The chaining value h after each compression of BLAKE2b with a
   --  64-byte digest, keyed with Key (empty for an unkeyed hash), of
   --  Message: eight words per compression, in order (the key block's
   --  first when there is a key); the last eight are the final h, whose
   --  little-endian bytes are the digest.
   function Chain_Values (Key : Bytes; Message : Bytes) return Word_Array
   with Pre => Key'Length <= 64;

end Blake2b_Reference;
