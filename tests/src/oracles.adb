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

   ------------------------------------------------------------------------
   --  Incremental interfaces. Ada never reads the C structures' fields:
   --  only their size and alignment matter, and the size is checked
   --  against the C compiler's on every Init.
   ------------------------------------------------------------------------

   function C_Reference_State_Size return size_t
   with Import, Convention => C,
        External_Name => "oracles_reference_state_size";

   function C_Monocypher_Ctx_Size return size_t
   with Import, Convention => C,
        External_Name => "oracles_monocypher_ctx_size";

   --  int blake2b_init (blake2b_state *S, size_t outlen);
   function C_Blake2b_Init
     (S : access C_Reference_State; Out_Len : size_t) return int
   with Import, Convention => C, External_Name => "blake2b_init";

   --  int blake2b_init_key (blake2b_state *S, size_t outlen,
   --                        const void *key, size_t keylen);
   function C_Blake2b_Init_Key
     (S       : access C_Reference_State;
      Out_Len : size_t;
      Key     : System.Address;
      Key_Len : size_t) return int
   with Import, Convention => C, External_Name => "blake2b_init_key";

   --  int blake2b_update (blake2b_state *S, const void *in, size_t inlen);
   function C_Blake2b_Update
     (S      : access C_Reference_State;
      Input  : System.Address;
      In_Len : size_t) return int
   with Import, Convention => C, External_Name => "blake2b_update";

   --  int blake2b_final (blake2b_state *S, void *out, size_t outlen);
   function C_Blake2b_Final
     (S       : access C_Reference_State;
      Output  : System.Address;
      Out_Len : size_t) return int
   with Import, Convention => C, External_Name => "blake2b_final";

   --  void crypto_blake2b_keyed_init (crypto_blake2b_ctx *ctx,
   --                                  size_t hash_size,
   --                                  const uint8_t *key, size_t key_size);
   procedure C_Monocypher_Init
     (Ctx       : access C_Monocypher_Ctx;
      Hash_Size : size_t;
      Key       : System.Address;
      Key_Size  : size_t)
   with Import, Convention => C,
        External_Name => "crypto_blake2b_keyed_init";

   --  void crypto_blake2b_update (crypto_blake2b_ctx *ctx,
   --                              const uint8_t *message,
   --                              size_t message_size);
   procedure C_Monocypher_Update
     (Ctx          : access C_Monocypher_Ctx;
      Message      : System.Address;
      Message_Size : size_t)
   with Import, Convention => C, External_Name => "crypto_blake2b_update";

   --  void crypto_blake2b_final (crypto_blake2b_ctx *ctx, uint8_t *hash);
   procedure C_Monocypher_Final
     (Ctx : access C_Monocypher_Ctx; Hash : System.Address)
   with Import, Convention => C, External_Name => "crypto_blake2b_final";

   procedure Check_Status (Status : int; What : String) is
   begin
      if Status /= 0 then
         raise Program_Error
           with "reference " & What & " returned" & Status'Image;
      end if;
   end Check_Status;

   --  An object of the Ada type (Object_Size, padding included) has the
   --  size of the C structure.
   procedure Check_Size (What : String; Ada_Bits : Natural; C_Bytes : size_t)
   is
   begin
      if size_t (Ada_Bits / 8) /= C_Bytes then
         raise Program_Error
           with What & " is" & C_Bytes'Image & " bytes in C,"
                & Natural'Image (Ada_Bits / 8) & " in Ada";
      end if;
   end Check_Size;

   procedure Init
     (S : out Reference_State; NN : Digest_Length; Key : Byte_Array)
   is
      Local : aliased C_Reference_State;
   begin
      Check_Size ("blake2b_state", C_Reference_State'Object_Size,
                  C_Reference_State_Size);
      --  blake2b_init_key rejects an empty key: blake2b() itself calls
      --  blake2b_init then.
      if Key'Length = 0 then
         Check_Status (C_Blake2b_Init (Local'Access, size_t (NN)),
                       "blake2b_init");
      else
         Check_Status
           (C_Blake2b_Init_Key
              (Local'Access, size_t (NN), Key (Key'First)'Address,
               size_t (Key'Length)),
            "blake2b_init_key");
      end if;
      S.C := Local;
      S.NN := NN;
   end Init;

   procedure Update (S : in out Reference_State; Data : Byte_Array) is
      Local : aliased C_Reference_State := S.C;
   begin
      Check_Status
        (C_Blake2b_Update
           (Local'Access, Address_Of (Data), size_t (Data'Length)),
         "blake2b_update");
      S.C := Local;
   end Update;

   procedure Final (S : in out Reference_State; Digest : out Byte_Array) is
      Local  : aliased C_Reference_State := S.C;
      Result : Byte_Array (0 .. S.NN - 1) := [others => 0];
   begin
      if Digest'Length /= S.NN then
         raise Program_Error with "digest length differs from Init's";
      end if;
      Check_Status
        (C_Blake2b_Final (Local'Access, Result (0)'Address, size_t (S.NN)),
         "blake2b_final");
      S.C := Local;
      Digest := Result;
   end Final;

   procedure Init
     (S : out Monocypher_State; NN : Digest_Length; Key : Byte_Array)
   is
      Local : aliased C_Monocypher_Ctx;
   begin
      Check_Size ("crypto_blake2b_ctx", C_Monocypher_Ctx'Object_Size,
                  C_Monocypher_Ctx_Size);
      C_Monocypher_Init
        (Local'Access, size_t (NN), Address_Of (Key), size_t (Key'Length));
      S.C := Local;
      S.NN := NN;
   end Init;

   procedure Update (S : in out Monocypher_State; Data : Byte_Array) is
      Local : aliased C_Monocypher_Ctx := S.C;
   begin
      C_Monocypher_Update
        (Local'Access, Address_Of (Data), size_t (Data'Length));
      S.C := Local;
   end Update;

   procedure Final (S : in out Monocypher_State; Digest : out Byte_Array) is
      Local  : aliased C_Monocypher_Ctx := S.C;
      Result : Byte_Array (0 .. S.NN - 1) := [others => 0];
   begin
      if Digest'Length /= S.NN then
         raise Program_Error with "digest length differs from Init's";
      end if;
      C_Monocypher_Final (Local'Access, Result (0)'Address);
      S.C := Local;
      Digest := Result;
   end Final;

end Oracles;
