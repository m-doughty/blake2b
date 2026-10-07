--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Interfaces.C; use Interfaces.C;
with System;

package body Oracles is

   --  int blake2b (void *out, size_t outlen, const void *in,
   --               size_t inlen, const void *key, size_t keylen);
   function C_Blake2b
     (Output  : System.Address;
      Out_Len : size_t;
      Input   : System.Address;
      In_Len  : size_t;
      Key     : System.Address;
      Key_Len : size_t) return int
   with Import, Convention => C, External_Name => "blake2b";

   --  void crypto_blake2b_keyed (uint8_t *hash, size_t hash_size,
   --                             const uint8_t *key, size_t key_size,
   --                             const uint8_t *message,
   --                             size_t message_size);
   procedure C_Monocypher
     (Hash         : System.Address;
      Hash_Size    : size_t;
      Key          : System.Address;
      Key_Size     : size_t;
      Message      : System.Address;
      Message_Size : size_t)
   with Import, Convention => C, External_Name => "crypto_blake2b_keyed";

   --  Both C APIs accept a null pointer for a zero-length input.
   function Address_Of (B : Byte_Array) return System.Address is
     (if B'Length = 0 then System.Null_Address else B (B'First)'Address);

   function Reference
     (Message, Key : Byte_Array; NN : Digest_Length) return Byte_Array
   is
      Result : Byte_Array (0 .. NN - 1) := [others => 0];
      Status : int;
   begin
      Status :=
        C_Blake2b
          (Output  => Result (0)'Address,
           Out_Len => size_t (NN),
           Input   => Address_Of (Message),
           In_Len  => size_t (Message'Length),
           Key     => Address_Of (Key),
           Key_Len => size_t (Key'Length));
      if Status /= 0 then
         raise Program_Error
           with "reference blake2b() returned" & Status'Image;
      end if;
      return Result;
   end Reference;

   function Monocypher
     (Message, Key : Byte_Array; NN : Digest_Length) return Byte_Array
   is
      Result : Byte_Array (0 .. NN - 1) := [others => 0];
   begin
      C_Monocypher
        (Hash         => Result (0)'Address,
         Hash_Size    => size_t (NN),
         Key          => Address_Of (Key),
         Key_Size     => size_t (Key'Length),
         Message      => Address_Of (Message),
         Message_Size => size_t (Message'Length));
      return Result;
   end Monocypher;

end Oracles;
