--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

pragma Assertion_Policy (Check);

with Ada.Assertions; use Ada.Assertions;
with Ada.Numerics.Big_Numbers.Big_Integers;
use Ada.Numerics.Big_Numbers.Big_Integers;
with Interfaces;     use Interfaces;

with Blake2b;         use Blake2b;
with Blake2b.Hashing;
with Blake2b.Hashing.Counter_Testing;
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

   --  Every way to cut one message into three pieces, empty ones
   --  included: Init, Update (M (0 .. I - 1)), Update (M (I .. J - 1)),
   --  Update (M (J .. L - 1)), Final, for every 0 <= I <= J <= L. Each
   --  digest is checked against the digest of the whole message, which
   --  the reference C, Monocypher and the specification must agree on
   --  first (computed once per message: the oracles are not the subject
   --  here, the cut points are). One pass per cut pair.
   procedure Cut_Pairs (L : I64; KK : Key_Length; NN : Digest_Length) is
      G        : Generator :=
        Make (16#C07_9A12_0000_0000#
              xor Shift_Left (U64 (L), 16) xor Shift_Left (U64 (KK), 8)
              xor U64 (NN));
      M        : constant Byte_Array := Random_Bytes (G, L);
      K        : constant Byte_Array := Random_Bytes (G, KK);
      Expected : constant Byte_Array := Oracles.Reference (M, K, NN);
      Tag      : constant String :=
        "cuts len=" & L'Image & " kk=" & KK'Image & " nn=" & NN'Image;
      S        : Blake2b.Hashing.State;
      Digest   : Byte_Array (0 .. NN - 1);
   begin
      Expect (Tag & ": Monocypher vs reference",
              Oracles.Monocypher (M, K, NN), Expected);
      Expect_Spec (Tag & ": reference", M, K, Expected);
      for I in 0 .. L loop
         for J in I .. L loop
            Blake2b.Hashing.Init (S, NN, K);
            Blake2b.Hashing.Update (S, M (0 .. I - 1));
            Blake2b.Hashing.Update (S, M (I .. J - 1));
            Blake2b.Hashing.Update (S, M (J .. L - 1));
            Blake2b.Hashing.Final (S, Digest);
            --  No message is built unless the case fails: there are
            --  millions of them.
            if Digest = Expected then
               Pass;
            else
               Fail (Tag & " at" & I'Image & J'Image & ": got "
                     & To_Hex (Digest) & " expected " & To_Hex (Expected));
            end if;
         end loop;
      end loop;
   end Cut_Pairs;

   --  The lengths where a block boundary falls (with or without a key,
   --  which takes the whole first block) and the ends of the range.
   Cut_Lengths : constant array (Positive range <>) of I64 :=
     [0, 1, 2, 63, 64, 65, 127, 128, 129, 191, 192, 193, 255, 256, 257,
      300];
   Cut_Keys    : constant array (1 .. 5) of Key_Length := [0, 1, 32, 63, 64];
   Cut_Digests : constant array (1 .. 3) of Digest_Length := [1, 32, 64];

   --  Max_Length bounds the exhaustive sweep (two key/digest pairs at
   --  every length); the other key and digest lengths run on Cut_Lengths
   --  up to Max_Subset.
   procedure Cut_Point_Grid (Max_Length : I64; Max_Subset : I64) is
   begin
      Section ("implementation: Init, 3 Updates, Final at every pair of "
               & "cut points, lengths 0.." & Max_Length'Image
               & ", unkeyed nn=64 and kk=64 nn=32, vs reference C, "
               & "Monocypher and the specification");
      for L in I64 range 0 .. Max_Length loop
         Cut_Pairs (L, 0, 64);
         Cut_Pairs (L, 64, 32);
      end loop;

      Section ("implementation: every pair of cut points, lengths"
               & " at block boundaries up to" & Max_Subset'Image
               & " x 5 key lengths x 3 digest lengths (less the two "
               & "pairs swept above)");
      for L of Cut_Lengths loop
         if L <= Max_Subset then
            for KK of Cut_Keys loop
               for NN of Cut_Digests loop
                  --  Skip what the exhaustive sweep has done.
                  if L > Max_Length
                    or else not ((KK = 0 and then NN = 64)
                                 or else (KK = 64 and then NN = 32))
                  then
                     Cut_Pairs (L, KK, NN);
                  end if;
               end loop;
            end loop;
         end if;
      end loop;
   end Cut_Point_Grid;

   --  The block boundaries named explicitly, each message fed in fixed
   --  patterns of pieces: whole, empty first or last, runs of empty
   --  Updates, a lone first or last byte, cuts either side of the first
   --  block edge, single bytes, and single bytes with an empty Update
   --  after each. An empty piece is alternately a null slice of the
   --  message at the current position and a null array at Index'Last.
   procedure Boundaries is
      type Piece_List is array (Positive range <>) of I64;

      Lengths : constant array (1 .. 6) of I64 :=
        [127, 128, 129, 255, 256, 257];
      type Key_Digest is record
         KK : Key_Length;
         NN : Digest_Length;
      end record;
      Pairs   : constant array (1 .. 3) of Key_Digest :=
        [(0, 64), (1, 1), (64, 32)];

      Top_Empty : constant Byte_Array (Index'Last .. Index'Last - 1) :=
        [others => 0];

      procedure Check
        (What   : String;
         M, K   : Byte_Array;
         NN     : Digest_Length;
         Pieces : Piece_List;
         Wanted : Byte_Array)
      is
         S       : Blake2b.Hashing.State;
         Digest  : Byte_Array (0 .. NN - 1);
         Pos     : I64 := 0;
         Empties : Natural := 0;
      begin
         Blake2b.Hashing.Init (S, NN, K);
         for N of Pieces loop
            if N = 0 then
               if Empties mod 2 = 0 then
                  Blake2b.Hashing.Update (S, M (Pos .. Pos - 1));
               else
                  Blake2b.Hashing.Update (S, Top_Empty);
               end if;
               Empties := Empties + 1;
            else
               Blake2b.Hashing.Update (S, M (Pos .. Pos + N - 1));
               Pos := Pos + N;
            end if;
         end loop;
         if Pos /= M'Length then
            Fail (What & ": the pieces cover" & Pos'Image & " of"
                  & M'Length'Image & " bytes (harness error)");
            return;
         end if;
         Blake2b.Hashing.Final (S, Digest);
         Expect (What, Digest, Wanted);
      end Check;

   begin
      Section ("implementation: block boundaries 127/128/129 and "
               & "255/256/257 in fixed piece patterns, empty Updates, "
               & "single bytes");
      for L of Lengths loop
         for P of Pairs loop
            declare
               G        : Generator :=
                 Make (16#B0_0DA1_0000_0000# xor Shift_Left (U64 (L), 16)
                       xor Shift_Left (U64 (P.KK), 8) xor U64 (P.NN));
               M        : constant Byte_Array := Random_Bytes (G, L);
               K        : constant Byte_Array := Random_Bytes (G, P.KK);
               NN       : constant Digest_Length := P.NN;
               Expected : constant Byte_Array := Oracles.Reference (M, K, NN);
               Tag      : constant String :=
                 "len=" & L'Image & " kk=" & P.KK'Image & " nn="
                 & NN'Image;
               Singles  : constant Piece_List (1 .. Natural (L)) :=
                 [others => 1];
               Spaced   : constant Piece_List (1 .. 2 * Natural (L)) :=
                 [for I in 1 .. 2 * Natural (L) =>
                    (if I mod 2 = 1 then 1 else 0)];
            begin
               Expect (Tag & ": Monocypher vs reference",
                       Oracles.Monocypher (M, K, NN), Expected);
               Expect_Spec (Tag & ": reference", M, K, Expected);

               Check (Tag & " whole", M, K, NN, [1 => L], Expected);
               Check (Tag & " empty first", M, K, NN, [0, L], Expected);
               Check (Tag & " empty last", M, K, NN, [L, 0], Expected);
               Check (Tag & " empty runs", M, K, NN,
                      [0, 0, 0, L, 0, 0, 0], Expected);
               Check (Tag & " lone first byte", M, K, NN, [1, L - 1],
                      Expected);
               Check (Tag & " lone last byte", M, K, NN, [L - 1, 1],
                      Expected);
               for Cut of Piece_List'[127, 128, 129] loop
                  if Cut <= L then
                     Check (Tag & " cut at" & Cut'Image & " with empty run",
                            M, K, NN, [Cut, 0, 0, 0, L - Cut], Expected);
                  end if;
               end loop;
               Check (Tag & " single bytes", M, K, NN, Singles, Expected);
               Check (Tag & " single bytes, empty Update after each",
                      M, K, NN, Spaced, Expected);
            end;
         end loop;
      end loop;

      --  The empty message: no Update at all, and only empty Updates.
      for P of Pairs loop
         declare
            G        : Generator := Make (16#E3_0E00# + U64 (P.KK));
            K        : constant Byte_Array := Random_Bytes (G, P.KK);
            Expected : constant Byte_Array :=
              Oracles.Reference (No_Bytes, K, P.NN);
            Tag      : constant String :=
              "len= 0 kk=" & P.KK'Image & " nn=" & P.NN'Image;
         begin
            Expect (Tag & ": Monocypher vs reference",
                    Oracles.Monocypher (No_Bytes, K, P.NN), Expected);
            Expect_Spec (Tag & ": reference", No_Bytes, K, Expected);
            Check (Tag & " no Update", No_Bytes, K, P.NN, [1 .. 0 => 0],
                   Expected);
            Check (Tag & " only empty Updates", No_Bytes, K, P.NN,
                   [0, 0, 0, 0, 0], Expected);
         end;
      end loop;
   end Boundaries;

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

   --  The 128-bit counter's addition, called directly (through the public
   --  interface a carry takes 2**64 bytes), and the model's Plus: fixed
   --  cases worked out by hand at and around the carry, then random
   --  cases checked against arithmetic on mathematical integers.
   procedure Counter_Carry (Count : Natural) is
      package Inc renames Blake2b.Spec.Incremental;
      use type Inc.Counter;
      package Words is new Unsigned_Conversions (U64);
      Two_64 : constant Big_Integer := Words.To_Big_Integer (U64'Last) + 1;
      Top    : constant U64 := U64'Last;

      --  (Hi, Lo) + N must give (Hi2, Lo2), from Add_Counter and Plus.
      procedure Case_Of (Hi, Lo, N, Hi2, Lo2 : U64) is
         H : U64 := Hi;
         L : U64 := Lo;
         Name : constant String :=
           "(" & Hi'Image & "," & Lo'Image & ") +" & N'Image;
      begin
         Blake2b.Hashing.Counter_Testing.Add_Counter (H, L, N);
         if H = Hi2 and then L = Lo2 then
            Pass;
         else
            Fail ("Add_Counter " & Name & ": got (" & H'Image & ","
                  & L'Image & ")");
         end if;
         begin
            pragma Assert
              (Inc.Plus ((Lo => Lo, Hi => Hi), N) = (Lo => Lo2, Hi => Hi2));
            Pass;
         exception
            when Assertion_Error =>
               Fail ("Plus " & Name & " /= (" & Hi2'Image & ","
                     & Lo2'Image & ")");
         end;
      end Case_Of;

      G : Generator := Make (16#C0_7E_C4_44#);
   begin
      Section ("implementation and model: the 128-bit counter's carry");
      Case_Of (0, 0, 128, 0, 128);
      Case_Of (3, 5, 0, 3, 5);
      Case_Of (0, Top, 1, 1, 0);
      Case_Of (0, Top - 127, 128, 1, 0);
      Case_Of (0, Top, 128, 1, 127);
      Case_Of (7, Top - 1, 1, 7, Top);
      Case_Of (7, Top - 1, 2, 8, 0);
      Case_Of (3, 2**63, 2**63, 4, 0);
      Case_Of (Top - 1, Top, 1, Top, 0);
      Case_Of (Top - 1, Top, Top, Top, Top - 1);
      for I in 1 .. Count loop
         declare
            Hi, Lo, N : U64;
            H, L      : U64;
         begin
            Next (G, Hi);
            Hi := Hi mod Top;            --  so that no sum reaches 2**128
            Next (G, Lo);
            if I mod 2 = 0 then          --  half of them near the carry
               Lo := Top - Below (G, 256);
            end if;
            N := (if I mod 3 = 0 then Below (G, 257) else 128);
            H := Hi;
            L := Lo;
            Blake2b.Hashing.Counter_Testing.Add_Counter (H, L, N);
            if Words.To_Big_Integer (H) * Two_64 + Words.To_Big_Integer (L)
               = Words.To_Big_Integer (Hi) * Two_64
                 + Words.To_Big_Integer (Lo) + Words.To_Big_Integer (N)
            then
               Pass;
            else
               Fail ("Add_Counter: (" & Hi'Image & "," & Lo'Image & ") +"
                     & N'Image & " gave (" & H'Image & "," & L'Image & ")");
            end if;
            begin
               pragma Assert
                 (Inc.Plus ((Lo => Lo, Hi => Hi), N) = (Lo => L, Hi => H));
               Pass;
            exception
               when Assertion_Error =>
                  Fail ("Plus: (" & Hi'Image & "," & Lo'Image & ") +"
                        & N'Image & " /= Add_Counter's result");
            end;
         end;
      end loop;
   end Counter_Carry;

   procedure Run
     (Kat_Path     : String;
      Random_Count : Natural;
      Max_Length   : Natural;
      Cut_Length   : Natural;
      Cut_Subset   : Natural;
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
      Cut_Point_Grid (I64 (Cut_Length), I64 (Cut_Subset));
      Boundaries;
      Wiping;
      Counter_Carry (Natural'Min (10_000, Random_Count));
      if Contracts then
         Misuse;
      end if;
   end Run;

end Impl_Suite;
