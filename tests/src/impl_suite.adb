--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

pragma Assertion_Policy (Check);

with Ada.Assertions; use Ada.Assertions;
with Interfaces;     use Interfaces;

with Blake2b;         use Blake2b;
with Blake2b.Hashing;
with Blake2b.Hashing.Testing;
with Blake2b.Spec;
with Blake2b.Spec.Incremental;
with Kat_Json;
with Oracles;
with Test_Support;    use Test_Support;

package body Impl_Suite is

   function One_Shot
     (Message, Key : Byte_Array; NN : Digest_Length) return Byte_Array
   is
      Digest : Byte_Array (0 .. NN - 1);
   begin
      Blake2b.Hashing.Hash (Message, Key, Digest);
      return Digest;
   end One_Shot;

   procedure Expect
     (Name : String; Got : Byte_Array; Expected : Byte_Array) is
   begin
      if Got = Expected then
         Pass;
      else
         Fail (Name & ": got " & To_Hex (Got) & " expected "
               & To_Hex (Expected));
      end if;
   end Expect;

   --  The implementation also agrees with the executable specification.
   procedure Expect_Spec
     (Name : String; Message, Key : Byte_Array; Got : Byte_Array) is
   begin
      pragma Assert (Got = Blake2b.Spec.Hash (Message, Key, Got'Length));
      Pass;
   exception
      when Assertion_Error =>
         Fail (Name & ": implementation /= specification");
   end Expect_Spec;

   procedure RFC_Vector is
      ABC : constant Byte_Array := [16#61#, 16#62#, 16#63#];
   begin
      Section ("implementation: RFC 7693 Appendix A");
      Expect ("BLAKE2b-512(""abc"")", One_Shot (ABC, No_Bytes, 64),
              From_Hex ("ba80a53f981c4d0d6a2797b69f12f6e9"
                        & "4c212f14685ac4b74b12bb6fdbffa2d1"
                        & "7d87c5392aab792dc252d5de4533cc95"
                        & "18d38aa8dbf1925ab92386edd4009923"));
   end RFC_Vector;

   procedure Visit_Kat (Input, Key, Expected : Byte_Array) is
   begin
      Expect ("KAT in=" & Input'Length'Image & " key=" & Key'Length'Image,
              One_Shot (Input, Key, 64), Expected);
   end Visit_Kat;

   procedure Kat_File (Path : String) is
      procedure Each is new Kat_Json.For_Each_Blake2b (Visit_Kat);
      Count : Natural;
   begin
      Section ("implementation: blake2-kat.json (BLAKE2 team)");
      if Kat_Json.File_Digest (Path) /= Kat_Json.Pinned_SHA256 then
         Fail (Path & " does not have the pinned SHA-256; refusing it");
         return;
      end if;
      Each (Path, Count);
      if Count = 512 then
         Pass;
      else
         Fail ("expected 512 blake2b entries, found" & Count'Image);
      end if;
   end Kat_File;

   Key_Lengths    : constant array (1 .. 5) of Key_Length :=
     [0, 1, 32, 63, 64];
   Digest_Lengths : constant array (1 .. 6) of Digest_Length :=
     [1, 20, 32, 48, 63, 64];

   function Case_Seed (L : I64; KK : Key_Length; NN : Digest_Length)
      return U64
   is
     (16#1A9_1E00_0000_0000#
      xor Shift_Left (U64 (L), 16) xor Shift_Left (U64 (KK), 8)
      xor U64 (NN));

   procedure Oracle_Grid (Max_Length : I64) is
   begin
      Section ("implementation vs reference C, Monocypher and the "
               & "specification: lengths 0.." & Max_Length'Image
               & " x 5 key lengths x 6 digest lengths");
      for L in I64 range 0 .. Max_Length loop
         for KK of Key_Lengths loop
            for NN of Digest_Lengths loop
               declare
                  G   : Generator := Make (Case_Seed (L, KK, NN));
                  M   : constant Byte_Array := Random_Bytes (G, L);
                  K   : constant Byte_Array := Random_Bytes (G, KK);
                  Got : constant Byte_Array := One_Shot (M, K, NN);
                  Tag : constant String :=
                    "len=" & L'Image & " kk=" & KK'Image & " nn="
                    & NN'Image;
               begin
                  Expect (Tag & " vs reference", Got,
                          Oracles.Reference (M, K, NN));
                  Expect (Tag & " vs Monocypher", Got,
                          Oracles.Monocypher (M, K, NN));
                  Expect_Spec (Tag, M, K, Got);
               end;
            end loop;
         end loop;
      end loop;
   end Oracle_Grid;

   procedure Random_Cases (Count : Natural; Max_Length : Natural) is
      G : Generator := Make (16#5EED_0F_B1AE_2B#);
   begin
      Section ("implementation vs reference C:" & Count'Image
               & " seeded random cases, lengths 0.." & Max_Length'Image);
      for Trial in 1 .. Count loop
         declare
            L   : constant I64 := I64 (Below (G, U64 (Max_Length) + 1));
            KK  : constant Key_Length := Key_Length (Below (G, 65));
            NN  : constant Digest_Length :=
              Digest_Length (Below (G, 64) + 1);
            M   : constant Byte_Array := Random_Bytes (G, L);
            K   : constant Byte_Array := Random_Bytes (G, KK);
            Got : constant Byte_Array := One_Shot (M, K, NN);
         begin
            Expect ("random trial" & Trial'Image & " len=" & L'Image
                    & " kk=" & KK'Image & " nn=" & NN'Image,
                    Got, Oracles.Reference (M, K, NN));
         end;
      end loop;
   end Random_Cases;

   procedure Two_Part is
      G : Generator := Make (16#2_9A27#);
   begin
      Section ("implementation: Hash (Prefix, Message) vs reference C on "
               & "the concatenation");
      for Trial in 1 .. 2_000 loop
         declare
            L      : constant I64 := I64 (Below (G, 700));
            KK     : constant Key_Length := Key_Length (Below (G, 65));
            NN     : constant Digest_Length :=
              Digest_Length (Below (G, 64) + 1);
            M      : constant Byte_Array := Random_Bytes (G, L);
            K      : constant Byte_Array := Random_Bytes (G, KK);
            Split  : constant I64 := I64 (Below (G, U64 (L) + 1));
            Digest : Byte_Array (0 .. NN - 1);
         begin
            Blake2b.Hashing.Hash
              (Prefix  => M (0 .. Split - 1),
               Message => M (Split .. L - 1),
               Key     => K,
               Digest  => Digest);
            Expect ("two-part trial" & Trial'Image & " len=" & L'Image
                    & " split=" & Split'Image,
                    Digest, Oracles.Reference (M, K, NN));
         end;
      end loop;
   end Two_Part;

   procedure Odd_Bounds is
      G : Generator := Make (16#0DD_1A9E#);
   begin
      Section ("implementation: index bounds do not matter");
      for Trial in 1 .. 1_000 loop
         declare
            L      : constant I64 := I64 (Below (G, 400));
            KK     : constant Key_Length := Key_Length (Below (G, 65));
            NN     : constant Digest_Length :=
              Digest_Length (Below (G, 64) + 1);
            M      : constant Byte_Array := Random_Bytes (G, L);
            K      : constant Byte_Array := Random_Bytes (G, KK);
            Base   : constant Byte_Array := Oracles.Reference (M, K, NN);
            High_M : constant Index :=
              (if L = 0 then Index'Last else Index'Last - (L - 1));
            High_K : constant Index :=
              (if KK = 0 then Index'Last else Index'Last - (KK - 1));
            Low_D  : Byte_Array (123 .. 123 + NN - 1);
            High_D : Byte_Array (Index'Last - (NN - 1) .. Index'Last);
         begin
            Blake2b.Hashing.Hash (Rebase (M, 1_000), Rebase (K, 77), Low_D);
            Expect ("bounds low trial" & Trial'Image, Low_D, Base);
            Blake2b.Hashing.Hash
              (Rebase (M, High_M), Rebase (K, High_K), High_D);
            Expect ("bounds high trial" & Trial'Image, High_D, Base);
         end;
      end loop;
      declare
         Top_Empty : constant Byte_Array (Index'Last .. Index'Last - 1) :=
           [others => 0];
         Digest    : Byte_Array (0 .. 63);
      begin
         Blake2b.Hashing.Hash (Top_Empty, Top_Empty, Digest);
         Expect ("empty message and key at Index'Last", Digest,
                 Oracles.Reference (No_Bytes, No_Bytes, 64));
      end;
   end Odd_Bounds;

   procedure Incremental (Count : Natural; Max_Length : Natural) is
      G : Generator := Make (16#1_C2E_3E27#);
      S : Blake2b.Hashing.State;
   begin
      Section ("implementation: Init/Update/Final vs one-shot,"
               & Count'Image & " random chunkings");
      if Blake2b.Hashing.Is_Empty (S) then
         Pass;
      else
         Fail ("a default-initialised state is not Empty");
      end if;

      for Trial in 1 .. Count loop
         declare
            L      : constant I64 := I64 (Below (G, U64 (Max_Length) + 1));
            KK     : constant Key_Length := Key_Length (Below (G, 65));
            NN     : constant Digest_Length :=
              Digest_Length (Below (G, 64) + 1);
            M      : constant Byte_Array := Random_Bytes (G, L);
            K      : constant Byte_Array := Random_Bytes (G, KK);
            Digest : Byte_Array (0 .. NN - 1);
            Pos    : I64 := 0;
         begin
            --  Every few trials, abandon a hash half-way and start
            --  again: re-initialisation must not depend on the old state.
            if Trial mod 7 = 0 then
               Blake2b.Hashing.Init (S, 64, K);
               Blake2b.Hashing.Update (S, M (0 .. L / 2 - 1));
               if Trial mod 14 = 0 then
                  Blake2b.Hashing.Clear (S);
               end if;
            end if;
            Blake2b.Hashing.Init (S, NN, K);
            while Pos < L loop
               declare
                  N : constant I64 := Chunk_Size (G, L - Pos);
               begin
                  Blake2b.Hashing.Update (S, M (Pos .. Pos + N - 1));
                  Pos := Pos + N;
               end;
            end loop;
            Blake2b.Hashing.Update (S, No_Bytes);
            Blake2b.Hashing.Final (S, Digest);
            Expect ("incremental trial" & Trial'Image & " len=" & L'Image
                    & " kk=" & KK'Image & " nn=" & NN'Image,
                    Digest, One_Shot (M, K, NN));
            if Blake2b.Hashing.Is_Finalized (S) then
               Pass;
            else
               Fail ("Final did not leave the state Finalized");
            end if;
         end;
      end loop;

      --  One large Update, crossing many blocks at once.
      declare
         M      : constant Byte_Array := Random_Bytes (G, 1_048_577);
         Digest : Byte_Array (0 .. 63);
      begin
         Blake2b.Hashing.Init (S, 64, No_Bytes);
         Blake2b.Hashing.Update (S, M);
         Blake2b.Hashing.Final (S, Digest);
         Expect ("incremental: one 1 MiB + 1 byte update", Digest,
                 Oracles.Reference (M, No_Bytes, 64));
      end;
   end Incremental;

   --  The implementation computes the incremental model step for step,
   --  as the proved postconditions of Init, Update and Final say: checked
   --  here by execution too, over random messages cut into random pieces
   --  (empty ones included). After every piece the state is also the
   --  model's After_Absorbing of everything absorbed so far.
   procedure Incremental_Model (Count : Natural) is
      package Inc renames Blake2b.Spec.Incremental;
      use type Inc.Context;
      G : Generator := Make (16#3_DE1_C0DE#);
      S : Blake2b.Hashing.State;
   begin
      Section ("implementation: incremental steps vs the model,"
               & Count'Image & " random chunkings");
      for Trial in 1 .. Count loop
         declare
            L      : constant I64 := I64 (Below (G, 700));
            KK     : constant Key_Length := Key_Length (Below (G, 65));
            NN     : constant Digest_Length :=
              Digest_Length (Below (G, 64) + 1);
            M      : constant Byte_Array := Random_Bytes (G, L);
            K      : constant Byte_Array := Random_Bytes (G, KK);
            Tag    : constant String :=
              "model trial" & Trial'Image & " len=" & L'Image & " kk="
              & KK'Image & " nn=" & NN'Image;
            Digest : Byte_Array (0 .. NN - 1);
            Pos    : I64 := 0;
            Bad    : Boolean := False;
         begin
            Blake2b.Hashing.Init (S, NN, K);
            begin
               pragma Assert
                 (Blake2b.Hashing.Testing.Model_Of (S) = Inc.Init (K, NN));
            exception
               when Assertion_Error =>
                  Bad := True;
                  Fail (Tag & ": Init /= model");
            end;
            loop
               declare
                  N      : constant I64 := Chunk_Size (G, L - Pos);
                  Before : constant Inc.Context :=
                    Blake2b.Hashing.Testing.Model_Of (S)
                  with Ghost;
               begin
                  Blake2b.Hashing.Update (S, M (Pos .. Pos + N - 1));
                  begin
                     pragma Assert
                       (Blake2b.Hashing.Testing.Model_Of (S)
                        = Inc.Update (Before, M (Pos .. Pos + N - 1)));
                     pragma Assert
                       (Blake2b.Hashing.Testing.Model_Of (S)
                        = Inc.After_Absorbing (K, M (0 .. Pos + N - 1), NN));
                  exception
                     when Assertion_Error =>
                        Bad := True;
                        Fail (Tag & ": Update of" & N'Image & " bytes at"
                              & Pos'Image & " /= model");
                  end;
                  Pos := Pos + N;
               end;
               exit when Pos = L;
            end loop;
            declare
               Last : constant Inc.Context :=
                 Blake2b.Hashing.Testing.Model_Of (S)
               with Ghost;
            begin
               Blake2b.Hashing.Final (S, Digest);
               pragma Assert (Digest = Inc.Final (Last));
            exception
               when Assertion_Error =>
                  Bad := True;
                  Fail (Tag & ": Final /= model");
            end;
            if not Bad then
               Pass;
            end if;
            Expect (Tag, Digest, Oracles.Reference (M, K, NN));
         end;
      end loop;
   end Incremental_Model;

   --  Final and Clear leave nothing key- or input-derived in the state.
   procedure Wiping is
      G : Generator := Make (16#3_19E#);
      S : Blake2b.Hashing.State;
   begin
      Section ("implementation: Final and Clear wipe the state");
      for Trial in 1 .. 200 loop
         declare
            L      : constant I64 := I64 (Below (G, 600));
            KK     : constant Key_Length := Key_Length (Below (G, 65));
            M      : constant Byte_Array := Random_Bytes (G, L);
            K      : constant Byte_Array := Random_Bytes (G, KK);
            Digest : Byte_Array (0 .. 31);
         begin
            Blake2b.Hashing.Init (S, 32, K);
            Blake2b.Hashing.Update (S, M);
            if Trial mod 2 = 0 then
               Blake2b.Hashing.Final (S, Digest);
               if Blake2b.Hashing.Testing.Is_Wiped (S)
                 and then Blake2b.Hashing.Is_Finalized (S)
               then
                  Pass;
               else
                  Fail ("state not wiped after Final, trial" & Trial'Image);
               end if;
            else
               Blake2b.Hashing.Clear (S);
               if Blake2b.Hashing.Testing.Is_Wiped (S)
                 and then Blake2b.Hashing.Is_Empty (S)
               then
                  Pass;
               else
                  Fail ("state not wiped after Clear, trial" & Trial'Image);
               end if;
            end if;
         end;
      end loop;
   end Wiping;

   procedure Visit_External (Input, Key, Expected : Byte_Array) is
      NN  : constant Digest_Length := Expected'Length;
      Tag : constant String :=
        "len=" & Input'Length'Image & " kk=" & Key'Length'Image
        & " nn=" & NN'Image;
   begin
      Expect ("vector " & Tag, One_Shot (Input, Key, NN), Expected);
      Expect_Spec ("vector " & Tag, Input, Key, Expected);
   end Visit_External;

   procedure Vectors (Path : String) is
      procedure Each is new Kat_Json.For_Each_Blake2b (Visit_External);
      Count : Natural;
   begin
      Section ("implementation and specification vs " & Path);
      Each (Path, Count);
      if Count > 0 then
         Section ("  " & Count'Image & " vectors checked");
      else
         Fail ("no blake2b vectors in " & Path);
      end if;
   end Vectors;

   --  With contracts compiled in, the typestate preconditions reject
   --  misuse instead of computing nonsense.
   procedure Misuse is
      S      : Blake2b.Hashing.State;
      Digest : Byte_Array (0 .. 31);
      Wrong  : Byte_Array (0 .. 15);
   begin
      Section ("contracts: misuse is rejected");
      begin
         Blake2b.Hashing.Update (S, [1, 2, 3]);
         Fail ("Update on an Empty state was accepted");
      exception
         when Assertion_Error =>
            Pass;
      end;
      Blake2b.Hashing.Init (S, 32, No_Bytes);
      begin
         Blake2b.Hashing.Final (S, Wrong);
         Fail ("Final with a 16-byte digest for a 32-byte hash accepted");
      exception
         when Assertion_Error =>
            Pass;
      end;
      Blake2b.Hashing.Final (S, Digest);
      begin
         Blake2b.Hashing.Final (S, Digest);
         Fail ("Final on a Finalized state was accepted");
      exception
         when Assertion_Error =>
            Pass;
      end;
      declare
         Long_Key : constant Byte_Array (0 .. 64) := [others => 7];
      begin
         Blake2b.Hashing.Hash (No_Bytes, Long_Key, Digest);
         Fail ("a 65-byte key was accepted");
      exception
         when Assertion_Error =>
            Pass;
      end;
   end Misuse;

   procedure Run
     (Kat_Path     : String;
      Random_Count : Natural;
      Max_Length   : Natural;
      Contracts    : Boolean) is
   begin
      RFC_Vector;
      Kat_File (Kat_Path);
      Oracle_Grid (I64'Min (1_024, I64 (Max_Length)));
      Random_Cases (Random_Count, Max_Length);
      Two_Part;
      Odd_Bounds;
      Incremental (Random_Count / 5, Natural'Min (Max_Length, 2_000));
      Incremental_Model (Natural'Min (2_000, Random_Count / 5));
      Wiping;
      if Contracts then
         Misuse;
      end if;
   end Run;

end Impl_Suite;
