--  Two independent C implementations of BLAKE2b, vendored under ref/ and
--  used only by the test suite as oracles: the BLAKE2 team's reference
--  code and Monocypher. Neither is ever linked into the library.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Interfaces;
with Interfaces.C;

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

   --  The two implementations' own incremental interfaces, for messages
   --  longer than any Byte_Array (Index'Last is 2**31 - 1). Init checks
   --  that the C structure is the size declared below.

   --  blake2b_init/_init_key, blake2b_update, blake2b_final.
   type Reference_State is limited private;

   procedure Init
     (S : out Reference_State; NN : Digest_Length; Key : Byte_Array)
   with Pre => Key'Length <= Max_Key_Bytes;
   procedure Update (S : in out Reference_State; Data : Byte_Array);
   procedure Final (S : in out Reference_State; Digest : out Byte_Array)
   with Pre => Digest'Length in 1 .. Max_Digest_Bytes;

   --  crypto_blake2b_keyed_init, crypto_blake2b_update,
   --  crypto_blake2b_final.
   type Monocypher_State is limited private;

   procedure Init
     (S : out Monocypher_State; NN : Digest_Length; Key : Byte_Array)
   with Pre => Key'Length <= Max_Key_Bytes;
   procedure Update (S : in out Monocypher_State; Data : Byte_Array);
   procedure Final (S : in out Monocypher_State; Digest : out Byte_Array)
   with Pre => Digest'Length in 1 .. Max_Digest_Bytes;

private

   use Interfaces.C;

   subtype C_U64 is Interfaces.Unsigned_64;

   type Words_2 is array (0 .. 1) of C_U64 with Convention => C;
   type Words_8 is array (0 .. 7) of C_U64 with Convention => C;
   type Words_16 is array (0 .. 15) of C_U64 with Convention => C;
   type Bytes_128 is array (0 .. 127) of unsigned_char
   with Convention => C;

   --  blake2b_state, as declared in ref/blake2.h.
   type C_Reference_State is record
      H         : Words_8;
      T         : Words_2;
      F         : Words_2;
      Buf       : Bytes_128;
      Buflen    : size_t;
      Outlen    : size_t;
      Last_Node : unsigned_char;
   end record
   with Convention => C;

   type Reference_State is limited record
      C  : C_Reference_State;
      NN : Digest_Length := Max_Digest_Bytes;
   end record;

   --  crypto_blake2b_ctx, as declared in ref/monocypher.h.
   type C_Monocypher_Ctx is record
      Hash         : Words_8;
      Input_Offset : Words_2;
      Input        : Words_16;
      Input_Idx    : size_t;
      Hash_Size    : size_t;
   end record
   with Convention => C;

   type Monocypher_State is limited record
      C  : C_Monocypher_Ctx;
      NN : Digest_Length := Max_Digest_Bytes;
   end record;

end Oracles;
