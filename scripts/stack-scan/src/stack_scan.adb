--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  The measurement driver of scripts/check-stack-scan.sh, built against a
--  copy of the library: unmodified, with injected spills, or with injected
--  raises (see the script).
--
--  Usage: stack_scan <KiB> <spacer KiB> <step> <k|u> <length> <normal|raise>
--           [warm]
--    step    the call measured, one of
--              hash1   Blake2b.Hashing.Hash (Message, Key, Digest), on
--                      message bytes 0 .. length - 1;
--              hash2   Blake2b.Hashing.Hash (Prefix, Message, Key, Digest),
--                      Prefix bytes 0 .. 7 and Message bytes 8 .. length - 1
--                      (length >= 8);
--              init    Init (S, 64, Key);
--              update  Update (S, message bytes 0 .. length - 1), after
--                      Init (S, 64, Key);
--              final   Final (S, Digest), after Init (S, 64, Key) and
--                      Update (S, message bytes 0 .. length - 1);
--              clear   Clear (S), on the state final's run would finish (a
--                      hash abandoned before Final);
--    k | u   keyed with a 64-byte key, or unkeyed;
--    mode    normal (a build without an injected raise): two runs,
--            baseline (no call; must find nothing) and normal; raise (a
--            build with the injected raises, for hash1, hash2, update and
--            final only): baseline, raise (the inputs below, which fire an
--            injected raise) and normal (as in mode normal, where none
--            fires).
--    warm    (update in mode normal only) the measured call is the second
--            of its kind in the process: before the region is cleared, the
--            same Update is made on a second state set up as the first
--            (Init, then the same message), and discarded. So the measured
--            call runs with the caches warm and with the lazy bindings of
--            this Update resolved, and its inputs, state and canaries are
--            those of the call without warm. (Neither kind of call is the
--            process's first into the C library; scripts/check-stack-scan.sh
--            separates the resolver with an LD_BIND_NOW run.) The scenario is then named
--            <step>-<k|u>-<length>-warm.
--  The raise run's inputs: for hash1, hash2 and final, a message of 1,920
--  bytes keyed or 2,048 unkeyed, so that the last compression has the
--  final flag and the byte counter 2,048; for update, Update (S, message
--  bytes 1,900 .. 2,399) keyed or (2,028 .. 2,527) unkeyed, after the
--  rest of the message was absorbed before it, so that this call's first
--  compression (the buffered block topped up) has the byte counter 2,048.
--
--  For each run it clears KiB KiB of stack below one helper frame, makes
--  the call from that frame, copies the same region and counts the canary
--  words in it. The calls that set up the state (Init and Update before
--  the measured one, and with warm the first of the two calls) run before
--  the region is cleared. The call goes
--  through Call, which holds the handler for an injected Program_Error,
--  and Inner, whose frame holds an unused spacer of <spacer KiB> KiB: the
--  handler's own calls into the run-time run just below Call's frame,
--  inside the spacer, and so do not overwrite what the measured call and
--  the exception's propagation left below it. Every input, output and
--  state is on the heap, so the driver's own frames hold no canary.
--
--  The canaries are 64-bit SplitMix64 values. Classes:
--    K  the eight words of the key, as BLAKE2b loads the key block (none
--       when unkeyed);
--    M  message word J (message bytes 8 J .. 8 J + 7, little-endian, as
--       BLAKE2b loads them), for every whole word of the message the run
--       absorbs (message bytes are the bytes of Mix (M seed + J));
--    H  the chaining value after each compression of the whole message
--       (Blake2b_Reference; the last eight words are the digest).
--  Output, one line per run and class (see Stack_Probe.Put_Hits):
--    hits scenario=<step>-<k|u>-<length>[-warm] run=<r> raised=<yes|no>
--      touched=<bytes> class=<K|M|H> aligned=<n> unaligned=<n>
--      distinct=<n> depths=<list>
--  and, after the normal run of final and clear, the same counts over the
--  bytes of the state object itself (which the call must have wiped):
--    state scenario=... run=normal raised=no touched=... class=...
--  After a normal run that writes a digest (hash1, hash2, final), the
--  digest must equal the reference's; otherwise it stops with an error.

with Ada.Command_Line;
with Ada.Text_IO;
with Interfaces; use Interfaces;
with System;

with Blake2b;
with Blake2b.Hashing;

with Blake2b_Reference;
with Stack_Probe; use Stack_Probe;

procedure Stack_Scan is

   use type System.Bit_Order;
   use type Blake2b.I64;

   type Step_Kind is (Hash1, Hash2, Init, Update, Final, Clear);
   type Run_Kind is (Baseline, Raise_Run, Normal);
   type Name_Access is access constant String;
   Baseline_Name : aliased constant String := "baseline";
   Raise_Name    : aliased constant String := "raise";
   Normal_Name   : aliased constant String := "normal";
   Run_Names : constant array (Run_Kind) of Name_Access :=
     [Baseline  => Baseline_Name'Access,
      Raise_Run => Raise_Name'Access,
      Normal    => Normal_Name'Access];

   --  Canary seeds, far apart.
   K_Seed : constant Unsigned_64 := 16#D000#;
   M_Seed : constant Unsigned_64 := 16#C000#;

   Key_Bytes    : constant := 64;
   Digest_Bytes : constant := 64;
   Prefix_Bytes : constant := 8;

   type Bytes_Access is access Blake2b.Byte_Array;
   type State_Access is access Blake2b.Hashing.State;

   --  The key (empty when unkeyed), the message absorbed before the
   --  measured call (Pre), the message bytes the measured call hashes or
   --  absorbs (Data, after Prefix for hash2), the digest and the state.
   Key_In     : Bytes_Access;
   Pre_In     : Bytes_Access;
   Prefix_In  : Bytes_Access;
   Data_In    : Bytes_Access;
   Digest_Out : Bytes_Access;
   St         : State_Access;

   Snap : Word_Array_Access;

   --  The arguments.
   Step     : Step_Kind;
   Keyed    : Boolean;
   Length   : Natural;
   Do_Raise : Boolean;
   Warm     : Boolean := False;

   --  The geometry of the current run: message bytes 0 .. Pre_Len - 1 are
   --  absorbed before the call, Data_First .. Data_First + Data_Len - 1 by
   --  it; Total bytes of the message are absorbed by the end of the call.
   Pre_Len, Data_First, Data_Len, Total : Natural := 0;

   function Mix_Byte (Seed : Unsigned_64; P : Natural) return Unsigned_8 is
     (Unsigned_8
        (Shift_Right (Mix (Seed + Unsigned_64 (P / 8)), 8 * (P mod 8))
         and 16#FF#));

   --  Byte P of the message, and of the key.
   function Message_Byte (P : Natural) return Unsigned_8 is
     (Mix_Byte (M_Seed, P));
   function Key_Byte (P : Natural) return Unsigned_8 is
     (Mix_Byte (K_Seed, P));

   --  Message bytes First .. First + Count - 1, on the heap.
   function Message_Part (First, Count : Natural) return Bytes_Access is
      Result : constant Bytes_Access :=
        new Blake2b.Byte_Array (1 .. Blake2b.I64 (Count));
   begin
      for I in Result'Range loop
         Result (I) := Message_Byte (First + Natural (I) - 1);
      end loop;
      return Result;
   end Message_Part;

   procedure Set_Geometry (Run : Run_Kind) is
   begin
      Pre_Len := 0;
      Data_First := 0;
      Data_Len := 0;
      if Run = Raise_Run then
         case Step is
            when Hash1 | Hash2 | Final =>
               Total := (if Keyed then 1920 else 2048);
            when Update =>
               Pre_Len := (if Keyed then 1900 else 2028);
               Total := Pre_Len + 500;
            when Init | Clear =>
               raise Program_Error;
         end case;
      else
         Total := (if Step = Init then 0 else Length);
      end if;
      case Step is
         when Hash1 =>
            Data_Len := Total;
         when Hash2 =>
            Data_First := Prefix_Bytes;
            Data_Len := Total - Prefix_Bytes;
         when Update =>
            Data_First := Pre_Len;
            Data_Len := Total - Pre_Len;
         when Final | Clear =>
            Pre_Len := Total;
         when Init =>
            null;
      end case;
   end Set_Geometry;

   --  The inputs of run Run on the heap, and the state the measured call
   --  starts from (the calls that set it up are made here, and with Warm
   --  the first of the two measured calls, on a state of its own).
   procedure Prepare (Run : Run_Kind)
   with No_Inline;
   pragma Machine_Attribute (Prepare, "noipa");

   procedure Prepare (Run : Run_Kind) is
      Warm_St : State_Access;
   begin
      Set_Geometry (Run);
      Key_In :=
        new Blake2b.Byte_Array (1 .. (if Keyed then Key_Bytes else 0));
      for I in Key_In'Range loop
         Key_In (I) := Key_Byte (Natural (I) - 1);
      end loop;
      Pre_In := Message_Part (0, Pre_Len);
      Prefix_In := Message_Part (0, (if Step = Hash2 then Prefix_Bytes else 0));
      Data_In := Message_Part (Data_First, Data_Len);
      Digest_Out := new Blake2b.Byte_Array'(1 .. Digest_Bytes => 0);
      St := new Blake2b.Hashing.State;
      if Step in Update | Final | Clear then
         Blake2b.Hashing.Init (St.all, Digest_Bytes, Key_In.all);
         Blake2b.Hashing.Update (St.all, Pre_In.all);
      end if;
      --  The first call (Warm is only accepted with step update): the
      --  same Update, from the same state, on a second state, which is
      --  then dropped (as every run's heap objects are), so the measured
      --  call's state and canaries are unchanged.
      if Warm and then Run /= Baseline then
         Warm_St := new Blake2b.Hashing.State;
         Blake2b.Hashing.Init (Warm_St.all, Digest_Bytes, Key_In.all);
         Blake2b.Hashing.Update (Warm_St.all, Pre_In.all);
         Blake2b.Hashing.Update (Warm_St.all, Data_In.all);
      end if;
   end Prepare;

   type Volatile_Words is array (Natural range <>) of Unsigned_64
   with Volatile_Components;

   Spacer_Words : Natural := 0;

   --  The measured call, below a spacer of Spacer_Words words.
   procedure Inner
   with No_Inline;
   pragma Machine_Attribute (Inner, "noipa");

   procedure Inner is
      Spacer : Volatile_Words (0 .. Spacer_Words);
      pragma Warnings
        (Off, Spacer, Reason => "written only so that it is allocated");
   begin
      --  One volatile store, so that the spacer is allocated; it writes
      --  the zero the clearing left there.
      Spacer (Spacer'First) := 0;
      case Step is
         when Hash1 =>
            Blake2b.Hashing.Hash (Data_In.all, Key_In.all, Digest_Out.all);
         when Hash2 =>
            Blake2b.Hashing.Hash
              (Prefix_In.all, Data_In.all, Key_In.all, Digest_Out.all);
         when Init =>
            Blake2b.Hashing.Init (St.all, Digest_Bytes, Key_In.all);
         when Update =>
            Blake2b.Hashing.Update (St.all, Data_In.all);
         when Final =>
            Blake2b.Hashing.Final (St.all, Digest_Out.all);
         when Clear =>
            Blake2b.Hashing.Clear (St.all);
      end case;
   end Inner;

   --  The handler for the injected exception.
   procedure Call (Raised : out Boolean)
   with No_Inline;
   pragma Machine_Attribute (Call, "noipa");

   procedure Call (Raised : out Boolean) is
   begin
      Raised := False;
      Inner;
   exception
      when Program_Error =>
         Raised := True;
   end Call;

   --  The helper frame: the clearing, the call and the copy are all made
   --  from it, so they reach the same stack addresses.
   procedure Helper (Run : Run_Kind; Raised : out Boolean)
   with No_Inline;
   pragma Machine_Attribute (Helper, "noipa");

   procedure Helper (Run : Run_Kind; Raised : out Boolean) is
   begin
      Raised := False;
      Prepare (Run);
      Region (False, Snap);
      if Run /= Baseline then
         Call (Raised);
      end if;
      Region (True, Snap);
   end Helper;

   function Img (N : Natural) return String is
      S : constant String := Natural'Image (N);
   begin
      return S (S'First + 1 .. S'Last);
   end Img;

   function Scenario return String is
     (Ada.Command_Line.Argument (3) & "-" & Ada.Command_Line.Argument (4)
      & "-" & Ada.Command_Line.Argument (5) & (if Warm then "-warm" else ""));

   procedure Fail (Message : String) is
   begin
      Ada.Text_IO.Put_Line ("error: " & Message);
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end Fail;

   KiB    : Positive;
   Raised : Boolean;
begin
   if System.Default_Bit_Order /= System.Low_Order_First then
      Fail ("big-endian target: not supported");
      return;
   end if;
   if Ada.Command_Line.Argument_Count not in 6 | 7
     or else (Ada.Command_Line.Argument (4) /= "k"
              and then Ada.Command_Line.Argument (4) /= "u")
     or else (Ada.Command_Line.Argument (6) /= "raise"
              and then Ada.Command_Line.Argument (6) /= "normal")
     or else (Ada.Command_Line.Argument_Count = 7
              and then Ada.Command_Line.Argument (7) /= "warm")
   then
      Fail ("usage: stack_scan <KiB> <spacer KiB>"
            & " <hash1|hash2|init|update|final|clear> <k|u> <length>"
            & " <normal|raise> [warm]");
      return;
   end if;
   Warm := Ada.Command_Line.Argument_Count = 7;
   KiB := Positive'Value (Ada.Command_Line.Argument (1));
   Spacer_Words := 128 * Natural'Value (Ada.Command_Line.Argument (2));
   Step := Step_Kind'Value (Ada.Command_Line.Argument (3));
   Keyed := Ada.Command_Line.Argument (4) = "k";
   Length := Natural'Value (Ada.Command_Line.Argument (5));
   Do_Raise := Ada.Command_Line.Argument (6) = "raise";
   if Step = Hash2 and then Length < Prefix_Bytes then
      Fail ("hash2 needs a length of at least" & Prefix_Bytes'Image);
      return;
   end if;
   if Do_Raise and then Step in Init | Clear then
      Fail ("init and clear have no raise run");
      return;
   end if;
   if Warm and then (Step /= Update or else Do_Raise) then
      Fail ("warm is for update in mode normal only");
      return;
   end if;
   Snap := new Word_Array (0 .. 128 * KiB - 1);

   for Run in Run_Kind loop
      if Run = Raise_Run and then not Do_Raise then
         goto Next_Run;
      end if;
      Helper (Run, Raised);
      declare
         K : Word_Array (0 .. (if Keyed then Key_Bytes / 8 else 0) - 1);
         M : Word_Array (0 .. Total / 8 - 1);
         Key_Ref : Blake2b_Reference.Bytes (0 .. K'Length * 8 - 1);
         Message : Blake2b_Reference.Bytes (0 .. Total - 1);
      begin
         for J in K'Range loop
            K (J) := Mix (K_Seed + Unsigned_64 (J));
         end loop;
         for J in M'Range loop
            M (J) := Mix (M_Seed + Unsigned_64 (J));
         end loop;
         for J in Key_Ref'Range loop
            Key_Ref (J) := Key_Byte (J);
         end loop;
         for J in Message'Range loop
            Message (J) := Message_Byte (J);
         end loop;
         declare
            H : constant Word_Array :=
              Blake2b_Reference.Chain_Values (Key_Ref, Message);
            Prefix : constant String :=
              "scenario=" & Scenario & " run=" & Run_Names (Run).all
              & " raised=" & (if Raised then "yes" else "no");
         begin
            if Run = Normal and then Step in Hash1 | Hash2 | Final then
               for J in 0 .. Digest_Bytes - 1 loop
                  if Unsigned_64 (Digest_Out (Blake2b.I64 (J) + 1))
                    /= (Shift_Right (H (H'Last - 7 + J / 8), 8 * (J mod 8))
                        and 16#FF#)
                  then
                     Fail ("the digest disagrees with the reference ("
                           & Scenario & ", byte " & Img (J) & ")");
                     return;
                  end if;
               end loop;
            end if;
            Put_Hits ("hits " & Prefix, Snap.all, "K", K);
            Put_Hits ("hits " & Prefix, Snap.all, "M", M);
            Put_Hits ("hits " & Prefix, Snap.all, "H", H);
            if Run = Normal and then Step in Final | Clear then
               declare
                  State_Words : Word_Array
                    (0 .. Natural (St.all'Size / 64) - 1)
                  with Import, Address => St.all'Address;
               begin
                  Put_Hits ("state " & Prefix, State_Words, "K", K);
                  Put_Hits ("state " & Prefix, State_Words, "M", M);
                  Put_Hits ("state " & Prefix, State_Words, "H", H);
               end;
            end if;
         end;
      end;
      <<Next_Run>>
   end loop;
end Stack_Scan;
