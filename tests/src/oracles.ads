--  Two independent C implementations of BLAKE2b, vendored under ref/ and
--  used only by the test suite as oracles: the BLAKE2 team's reference
--  code and Monocypher. Neither is ever linked into the library.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Blake2b; use Blake2b;

package Oracles is

   --  BLAKE2 reference implementation (ref/blake2b-ref.c).
   function Reference
     (Message, Key : Byte_Array; NN : Digest_Length) return Byte_Array
   with Pre  => Key'Length <= Max_Key_Bytes,
        Post => Reference'Result'First = 0
                and then Reference'Result'Length = NN;

   --  Monocypher (ref/monocypher.c), crypto_blake2b_keyed.
   function Monocypher
     (Message, Key : Byte_Array; NN : Digest_Length) return Byte_Array
   with Pre  => Key'Length <= Max_Key_Bytes,
        Post => Monocypher'Result'First = 0
                and then Monocypher'Result'Length = NN;

end Oracles;
