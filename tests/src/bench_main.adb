--  blake2b benchmark.
--
--  Usage: bench_main           throughput table: this implementation vs
--                              the BLAKE2 reference C, same compiler and
--                              optimisation level, at 64 B .. 1 MiB
--         bench_main --check   determinism gate: hashes a fixed corpus,
--                              compares every digest with the reference
--                              C, and compares a digest of all the digests
--                              with the value pinned below; exits non-zero
--                              on any difference
--         bench_main --workload ada|c
--                              hashes 32 MiB once with this implementation
--                              or the reference C and exits: the run that
--                              CI measures with callgrind, where the
--                              instruction-count ratio is deterministic
--
--  Wall-clock figures are reported, not gated: they vary with the machine.
--  The deterministic, gated performance figure is the instruction-count
--  ratio measured with callgrind on Linux CI.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Ada.Command_Line; use Ada.Command_Line;
with Ada.Real_Time;    use Ada.Real_Time;
with Ada.Text_IO;      use Ada.Text_IO;
with Interfaces;       use Interfaces;
with Interfaces.C;
with System;

with Blake2b;         use Blake2b;
with Blake2b.Hashing;
with Test_Support;    use Test_Support;

procedure Bench_Main is

   use type Interfaces.C.int;

   --  The reference C, called directly with preallocated buffers so the
   --  comparison measures hashing, not wrapper allocation.
   function C_Blake2b
     (Output  : System.Address;
      Out_Len : Interfaces.C.size_t;
      Input   : System.Address;
      In_Len  : Interfaces.C.size_t;
      Key     : System.Address;
      Key_Len : Interfaces.C.size_t) return Interfaces.C.int
   with Import, Convention => C, External_Name => "blake2b";

   --  The digest of the --check corpus. Identical on every platform and
   --  at every optimisation level, or the gate fails.
   Pinned_Check : constant String :=
     "5c13c782ee413736a8ecb38a47fac7951a0896d77fbefb93ef879bc246e6504b"
     & "8a84b2995fe0e76f80d69cb0772d4ef3b60c56aeabb17829d11ad8a26e6afc3d";

   --  Keeps every computed digest observable, so no loop is optimised
   --  away.
   Sink : Byte := 0 with Volatile;

   type Seconds is array (Positive range <>) of Duration;

   function Median (Samples : Seconds) return Duration is
      A : Seconds := Samples;
   begin
      for I in A'First + 1 .. A'Last loop
         declare
            X : constant Duration := A (I);
            J : Natural := I - 1;
         begin
            while J >= A'First and then A (J) > X loop
               A (J + 1) := A (J);
               J := J - 1;
            end loop;
            A (J + 1) := X;
         end;
      end loop;
      return A ((A'First + A'Last) / 2);
   end Median;

   function Address_Of (B : Byte_Array) return System.Address is
     (if B'Length = 0 then System.Null_Address else B (B'First)'Address);

   function Time_Ada (M : Byte_Array; Iterations : Positive)
      return Duration
   is
      Digest : Byte_Array (0 .. 63);
      Start  : constant Time := Clock;
   begin
      for I in 1 .. Iterations loop
         Blake2b.Hashing.Hash (M, No_Bytes, Digest);
         Sink := Sink xor Digest (I64 (I mod 64));
      end loop;
      return To_Duration (Clock - Start);
   end Time_Ada;

   function Time_C (M : Byte_Array; Iterations : Positive) return Duration
   is
      Digest : Byte_Array (0 .. 63);
      Start  : constant Time := Clock;
   begin
      for I in 1 .. Iterations loop
         if C_Blake2b (Digest (0)'Address, 64, Address_Of (M),
                       Interfaces.C.size_t (M'Length),
                       System.Null_Address, 0) /= 0
         then
            raise Program_Error with "reference blake2b() failed";
         end if;
         Sink := Sink xor Digest (I64 (I mod 64));
      end loop;
      return To_Duration (Clock - Start);
   end Time_C;

   function Time_Incremental (M : Byte_Array; Iterations : Positive)
      return Duration
   is
      Chunk  : constant I64 := 4_096;
      S      : Blake2b.Hashing.State;
      Digest : Byte_Array (0 .. 63);
      Start  : constant Time := Clock;
   begin
      for I in 1 .. Iterations loop
         Blake2b.Hashing.Init (S, 64, No_Bytes);
         declare
            Pos : I64 := M'First;
         begin
            while Pos <= M'Last loop
               Blake2b.Hashing.Update
                 (S, M (Pos .. I64'Min (Pos + Chunk - 1, M'Last)));
               Pos := Pos + Chunk;
            end loop;
         end;
         Blake2b.Hashing.Final (S, Digest);
         Sink := Sink xor Digest (I64 (I mod 64));
      end loop;
      return To_Duration (Clock - Start);
   end Time_Incremental;

   function MB_Per_S (Bytes : I64; Iterations : Positive; T : Duration)
      return String
   is
      Rate : constant Long_Float :=
        Long_Float (Bytes) * Long_Float (Iterations)
        / Long_Float (T) / 1_000_000.0;
      Whole : constant Long_Integer := Long_Integer (Rate);
   begin
      return Whole'Image;
   end MB_Per_S;

   procedure Throughput is
      Sizes : constant array (1 .. 4) of I64 :=
        [64, 1_024, 65_536, 1_048_576];
      Runs  : constant := 7;
      G     : Generator := Make (16#BE_4C_4#);
   begin
      Put_Line ("BLAKE2b-512, unkeyed, one-shot. Median of"
                & Runs'Image & " runs; MB/s (10**6 bytes per second).");
      Put_Line ("     size     Ada MB/s     ref C MB/s   Ada time / C time");
      for Size of Sizes loop
         declare
            M          : constant Byte_Array := Random_Bytes (G, Size);
            Iterations : constant Positive :=
              Positive (I64'Max (1, 64 * 1_048_576 / Size));
            Ada_T, C_T : Seconds (1 .. Runs);
         begin
            for R in 1 .. Runs loop
               Ada_T (R) := Time_Ada (M, Iterations);
               C_T (R) := Time_C (M, Iterations);
            end loop;
            declare
               A     : constant Duration := Median (Ada_T);
               C     : constant Duration := Median (C_T);
               Ratio : constant Long_Integer :=
                 Long_Integer (1000.0 * Long_Float (A) / Long_Float (C));
            begin
               Put_Line (Size'Image & "    " & MB_Per_S (Size, Iterations, A)
                         & "    " & MB_Per_S (Size, Iterations, C)
                         & "    " & Ratio'Image & " / 1000");
            end;
         end;
      end loop;

      declare
         M          : constant Byte_Array := Random_Bytes (G, 1_048_576);
         Iterations : constant Positive := 64;
         T          : Seconds (1 .. Runs);
      begin
         for R in 1 .. Runs loop
            T (R) := Time_Incremental (M, Iterations);
         end loop;
         Put_Line ("incremental, 1 MiB in 4 KiB updates: "
                   & MB_Per_S (1_048_576, Iterations, Median (T))
                   & " MB/s");
      end;
   end Throughput;

   procedure Check is
      G      : Generator := Make (16#C_4EC_D16E57#);
      Acc    : Blake2b.Hashing.State;
      Result : Byte_Array (0 .. 63);
      Bad    : Natural := 0;
   begin
      Blake2b.Hashing.Init (Acc, 64, No_Bytes);
      for N in I64 range 0 .. 2_048 loop
         declare
            M   : constant Byte_Array := Random_Bytes (G, N);
            K   : constant Byte_Array := Random_Bytes (G, N mod 65);
            NN  : constant Digest_Length := 1 + N mod 64;
            D   : Byte_Array (0 .. NN - 1);
            Ref : Byte_Array (0 .. NN - 1) := [others => 0];
         begin
            Blake2b.Hashing.Hash (M, K, D);
            if C_Blake2b (Ref (0)'Address, Interfaces.C.size_t (NN),
                          Address_Of (M), Interfaces.C.size_t (M'Length),
                          Address_Of (K), Interfaces.C.size_t (K'Length))
               /= 0
              or else D /= Ref
            then
               Bad := Bad + 1;
               Put_Line ("mismatch with the reference C at length"
                         & N'Image);
            end if;
            Blake2b.Hashing.Update (Acc, D);
         end;
      end loop;
      Blake2b.Hashing.Final (Acc, Result);

      Put_Line ("determinism digest: " & To_Hex (Result));
      Put_Line ("pinned:             " & Pinned_Check);
      if Bad = 0 and then To_Hex (Result) = Pinned_Check then
         Put_Line ("check: PASS");
      else
         Put_Line ("check: FAIL");
         Set_Exit_Status (Failure);
      end if;
   end Check;

   --  One large hash. The input is filled with a constant (a memset): the
   --  work BLAKE2b does does not depend on the data, and a cheap fill
   --  keeps the measured instruction count about the hashing alone.
   procedure Workload (Which : String) is
      type Bytes_Access is access Byte_Array;
      Size   : constant I64 := 32 * 1_048_576;
      M      : constant Bytes_Access := new Byte_Array (0 .. Size - 1);
      Digest : Byte_Array (0 .. 63);
   begin
      M.all := [others => 16#A5#];
      if Which = "ada" then
         Blake2b.Hashing.Hash (M.all, No_Bytes, Digest);
      elsif Which = "c" then
         if C_Blake2b (Digest (0)'Address, 64, M.all (0)'Address,
                       Interfaces.C.size_t (Size), System.Null_Address, 0)
            /= 0
         then
            raise Program_Error with "reference blake2b() failed";
         end if;
      else
         raise Constraint_Error with "--workload takes ada or c";
      end if;
      Sink := Digest (0);
   end Workload;

begin
   if Argument_Count >= 1 and then Argument (1) = "--check" then
      Check;
   elsif Argument_Count >= 2 and then Argument (1) = "--workload" then
      Workload (Argument (2));
   else
      Throughput;
   end if;
end Bench_Main;
