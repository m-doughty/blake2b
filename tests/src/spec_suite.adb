--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

pragma Assertion_Policy (Check);

with Ada.Assertions; use Ada.Assertions;
with Interfaces;     use Interfaces;

with Blake2b;      use Blake2b;
with Blake2b.Spec;
with Blake2b.Spec.Incremental;
with Kat_Json;
with Oracles;
with Test_Support; use Test_Support;

package body Spec_Suite is

   --  An empty array. (Spec.Empty is ghost: usable only in assertions.)
   No_Bytes : constant Byte_Array (1 .. 0) := [others => 0];

   --  The specification is ghost code, so non-ghost code may evaluate it
   --  only inside an assertion. Every check below is a pragma Assert
   --  whose failure is caught, recorded and reported.

   procedure Check_Expected
     (Name     : String;
      Message  : Byte_Array;
      Key      : Byte_Array;
      NN       : Digest_Length;
      Expected : Byte_Array) is
   begin
      pragma Assert (Blake2b.Spec.Hash (Message, Key, NN) = Expected);
      Pass;
   exception
      when Assertion_Error =>
         Fail (Name & ": specification /= " & To_Hex (Expected));
   end Check_Expected;

   --  Section 1: RFC 7693, Appendix A. BLAKE2b-512 ("abc").
   procedure RFC_Vector is
      ABC : constant Byte_Array := [16#61#, 16#62#, 16#63#];
   begin
      Section ("specification: RFC 7693 Appendix A");
      Check_Expected
        ("BLAKE2b-512(""abc"")", ABC, No_Bytes, 64,
         From_Hex ("ba80a53f981c4d0d6a2797b69f12f6e9"
                   & "4c212f14685ac4b74b12bb6fdbffa2d1"
                   & "7d87c5392aab792dc252d5de4533cc95"
                   & "18d38aa8dbf1925ab92386edd4009923"));
   end RFC_Vector;

   --  Section 2: the BLAKE2 team's 512 BLAKE2b known answers.
   procedure Visit_Kat (Input, Key, Expected : Byte_Array) is
   begin
      Check_Expected
        ("KAT in=" & Input'Length'Image & " bytes, key="
         & Key'Length'Image & " bytes",
         Input, Key, 64, Expected);
   end Visit_Kat;

   procedure Kat_File (Path : String) is
      procedure Each is new Kat_Json.For_Each_Blake2b (Visit_Kat);
      Count : Natural;
   begin
      Section ("specification: blake2-kat.json (BLAKE2 team)");
      if Kat_Json.File_Digest (Path) /= Kat_Json.Pinned_SHA256 then
         Fail (Path & " does not have the pinned SHA-256 "
               & Kat_Json.Pinned_SHA256 & "; refusing to use it");
         return;
      end if;
      Pass;
      Each (Path, Count);
      if Count = 512 then
         Pass;
      else
         Fail ("expected 512 blake2b entries, found" & Count'Image);
      end if;
   end Kat_File;

   --  Section 3: agreement with both C implementations over every
   --  message length 0 .. 1024 crossed with key lengths 0, 1, 32, 63,
   --  64 and digest lengths 1, 20, 32, 48, 63, 64 -- the combinations
   --  the published vectors (all 64-byte digests, 0- or 64-byte keys)
   --  never exercise.
   Key_Lengths    : constant array (1 .. 5) of Key_Length :=
     [0, 1, 32, 63, 64];
   Digest_Lengths : constant array (1 .. 6) of Digest_Length :=
     [1, 20, 32, 48, 63, 64];

   function Case_Seed (L : I64; KK : Key_Length; NN : Digest_Length)
      return U64
   is
     (16#B1AE_2B00_0000_0000#
      xor Shift_Left (U64 (L), 16) xor Shift_Left (U64 (KK), 8)
      xor U64 (NN));

   procedure Oracle_Grid is
   begin
      Section ("specification vs reference C and Monocypher: lengths "
               & "0..1024 x 5 key lengths x 6 digest lengths");
      for L in I64 range 0 .. 1024 loop
         for KK of Key_Lengths loop
            for NN of Digest_Lengths loop
               declare
                  G   : Generator := Make (Case_Seed (L, KK, NN));
                  M   : constant Byte_Array := Random_Bytes (G, L);
                  K   : constant Byte_Array := Random_Bytes (G, KK);
                  Ref : constant Byte_Array := Oracles.Reference (M, K, NN);
                  Mon : constant Byte_Array :=
                    Oracles.Monocypher (M, K, NN);
                  Tag : constant String :=
                    "len=" & L'Image & " kk=" & KK'Image & " nn="
                    & NN'Image & " seed=" & Case_Seed (L, KK, NN)'Image;
               begin
                  if Ref = Mon then
                     Pass;
                  else
                     Fail (Tag & ": the two C oracles disagree");
                  end if;
                  Check_Expected (Tag, M, K, NN, Ref);
               end;
            end loop;
         end loop;
      end loop;
   end Oracle_Grid;

   --  Section 4: the two-part specification equals the one-part one on
   --  the concatenation, for every split point of random messages.
   procedure Two_Part is
      G : Generator := Make (16#7A0_7A27#);
   begin
      Section ("specification: Hash2 (P, M) = Hash (P & M)");
      for Trial in 1 .. 400 loop
         declare
            L     : constant I64 := I64 (Below (G, 600));
            KK    : constant Key_Length := Key_Length (Below (G, 65));
            NN    : constant Digest_Length :=
              Digest_Length (Below (G, 64) + 1);
            M     : constant Byte_Array := Random_Bytes (G, L);
            K     : constant Byte_Array := Random_Bytes (G, KK);
            Split : constant I64 := I64 (Below (G, U64 (L) + 1));
         begin
            begin
               pragma Assert
                 (Blake2b.Spec.Hash2
                    (M (0 .. Split - 1), M (Split .. L - 1), K, NN)
                  = Blake2b.Spec.Hash (M, K, NN));
               Pass;
            exception
               when Assertion_Error =>
                  Fail ("two-part trial" & Trial'Image & " len=" & L'Image
                        & " split=" & Split'Image);
            end;
         end;
      end loop;
   end Two_Part;

   --  Section 5: the result never depends on where an array's indices
   --  start, including empty arrays at the very top of the index range.
   procedure Odd_Bounds is
      G : Generator := Make (16#0DD_B0B5#);
   begin
      Section ("specification: index bounds do not matter");
      for Trial in 1 .. 200 loop
         declare
            L      : constant I64 := I64 (Below (G, 300));
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
         begin
            Check_Expected
              ("bounds low trial" & Trial'Image,
               Rebase (M, 1_000), Rebase (K, 77), NN, Base);
            Check_Expected
              ("bounds high trial" & Trial'Image,
               Rebase (M, High_M), Rebase (K, High_K), NN, Base);
         end;
      end loop;
      declare
         Top_Empty : constant Byte_Array (Index'Last .. Index'Last - 1) :=
           [others => 0];
      begin
         Check_Expected
           ("empty message and key at Index'Last", Top_Empty, Top_Empty,
            64, Oracles.Reference (No_Bytes, No_Bytes, 64));
      end;
   end Odd_Bounds;

   --  Section 6: the incremental model (Blake2b.Spec.Incremental), run
   --  over random messages cut into random pieces, empty ones included.
   --  After every piece the context is After_Absorbing of everything
   --  absorbed so far, and Final gives Spec.Hash: what Lemma_Update and
   --  Lemma_Final prove, checked here by execution as well.
   procedure Incremental_Model (Count : Natural) is
      package Inc renames Blake2b.Spec.Incremental;
      use type Inc.Context;
      G : Generator := Make (16#1_C2E_5BEC#);
   begin
      Section ("specification: incremental model vs Hash,"
               & Count'Image & " random chunkings");
      for Trial in 1 .. Count loop
         declare
            L   : constant I64 := I64 (Below (G, 700));
            KK  : constant Key_Length := Key_Length (Below (G, 65));
            NN  : constant Digest_Length :=
              Digest_Length (Below (G, 64) + 1);
            M   : constant Byte_Array := Random_Bytes (G, L);
            K   : constant Byte_Array := Random_Bytes (G, KK);
            Tag : constant String :=
              "model trial" & Trial'Image & " len=" & L'Image & " kk="
              & KK'Image & " nn=" & NN'Image;
            C   : Inc.Context := Inc.Init (K, NN) with Ghost;
            Pos : I64 := 0;
            Bad : Boolean := False;
         begin
            loop
               declare
                  N : constant I64 := Chunk_Size (G, L - Pos);
               begin
                  C := Inc.Update (C, M (Pos .. Pos + N - 1));
                  Pos := Pos + N;
               end;
               begin
                  pragma Assert
                    (C = Inc.After_Absorbing (K, M (0 .. Pos - 1), NN));
               exception
                  when Assertion_Error =>
                     Bad := True;
                     Fail (Tag & ": context after" & Pos'Image
                           & " bytes /= After_Absorbing");
               end;
               exit when Pos = L;
            end loop;
            begin
               pragma Assert (Inc.Final (C) = Blake2b.Spec.Hash (M, K, NN));
            exception
               when Assertion_Error =>
                  Bad := True;
                  Fail (Tag & ": Final /= Hash");
            end;
            if not Bad then
               Pass;
            end if;
         end;
      end loop;
   end Incremental_Model;

   procedure Run (Kat_Path : String) is
   begin
      RFC_Vector;
      Kat_File (Kat_Path);
      Oracle_Grid;
      Two_Part;
      Odd_Bounds;
      Incremental_Model (2_000);
   end Run;

end Spec_Suite;
