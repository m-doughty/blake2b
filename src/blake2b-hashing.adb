--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Blake2b.Core;
with Blake2b.Wipe;

package body Blake2b.Hashing
  with SPARK_Mode
is

   use type Byte;

   --  Block N of the padded input d (RFC 7693, section 3.3): the key
   --  block, or the 128 bytes of Prefix followed by Message starting at
   --  data offset 128 * (N - KB), zero-padded. Two slice copies at most;
   --  a 128-byte copy is small next to a compression.
   procedure Fill_Block
     (Key, Prefix, Message : Byte_Array;
      N                    : I64;
      Buf                  : out Block)
   with Global => null,
        Pre    => Spec.Valid_Key (Key)
                  and then N in 0 .. Spec.Block_Count (Key, Prefix, Message)
                                     - 1,
        Post   =>
          (for all J in Block_Index =>
             Buf (J) = Spec.Byte_At (Key, Prefix, Message,
                                     Block_Bytes * N + J))
   is
      KB : constant I64 := (if Key'Length > 0 then 1 else 0);
   begin
      Buf := [others => 0];
      if N < KB then
         Buf (0 .. Key'Length - 1) := Key;
      else
         declare
            D0 : constant I64 := Block_Bytes * (N - KB);
            PL : constant I64 := Prefix'Length;
            ML : constant I64 := Message'Length;
            Lo : constant I64 := I64'Max (D0, PL);
            Hi : constant I64 := I64'Min (D0 + Block_Bytes, PL + ML);
         begin
            --  Data offsets D0 .. D0 + 127 that fall inside Prefix.
            if D0 < PL then
               declare
                  P_Hi : constant I64 := I64'Min (D0 + Block_Bytes, PL);
               begin
                  Buf (0 .. P_Hi - D0 - 1) :=
                    Prefix (Prefix'First + D0 .. Prefix'First + P_Hi - 1);
               end;
            end if;
            --  Those that fall inside Message.
            if Lo < Hi then
               Buf (Lo - D0 .. Hi - D0 - 1) :=
                 Message (Message'First + (Lo - PL)
                          .. Message'First + (Hi - PL) - 1);
            end if;
         end;
      end if;
   end Fill_Block;

   --  The one-shot hash itself; both public Hash procedures call it. It
   --  is the single place secrets pass through on the one-shot path, so
   --  it carries the hardening attributes (a pragma Machine_Attribute
   --  cannot single out one of two overloads).
   procedure Digest_Of
     (Prefix  : Byte_Array;
      Message : Byte_Array;
      Key     : Byte_Array;
      Digest  : out Byte_Array)
   with Global => null,
        Pre    => Key'Length <= Max_Key_Bytes
                  and then Digest'Length in 1 .. Max_Digest_Bytes,
        Post   => Digest
                  = Spec.Hash2 (Prefix, Message, Key, Digest'Length);
   --  GCC stack scrubbing: the stack this call (and everything it calls)
   --  used is zeroed on return. And the call-used registers it touched.
   pragma Warnings
     (GNATprove, Off, "pragma ""Machine_Attribute"" ignored*",
      Reason => "code-generation attribute: no effect on proof");
   --  Every call-used register, including those only callees used (see
   --  the spec's private part).
   pragma Machine_Attribute (Digest_Of, "strub", "internal");
   pragma Machine_Attribute (Digest_Of, "zero_call_used_regs", "all");
   pragma Warnings
     (GNATprove, On, "pragma ""Machine_Attribute"" ignored*");

   procedure Digest_Of
     (Prefix  : Byte_Array;
      Message : Byte_Array;
      Key     : Byte_Array;
      Digest  : out Byte_Array)
   is
      NN  : constant Digest_Length := Digest'Length;
      KB  : constant I64 := (if Key'Length > 0 then 1 else 0);
      L   : constant I64 := Prefix'Length + Message'Length;
      DD  : constant I64 :=
        (if KB + (L + (Block_Bytes - 1)) / Block_Bytes = 0 then 1
         else KB + (L + (Block_Bytes - 1)) / Block_Bytes);
      H   : Words8 := Core.Initial_H (Key'Length, NN);
      Buf : Block;
   begin
      pragma Assert (DD = Spec.Block_Count (Key, Prefix, Message));

      --  Blocks 0 .. dd - 2: non-final, offset counter (i + 1) * 128.
      for N in 0 .. DD - 2 loop
         pragma Loop_Invariant
           (H = Spec.Fold (Spec.Initial_H (Key'Length, NN),
                           Key, Prefix, Message, N));
         Core.Lemma_Same8
           (H, Spec.Fold (Spec.Initial_H (Key'Length, NN),
                          Key, Prefix, Message, N));
         Fill_Block (Key, Prefix, Message, N, Buf);
         Core.Lemma_Same_Block
           (Buf, Spec.Block_Of (Key, Prefix, Message, N));
         Core.Compress
           (H, Buf,
            T_Lo => U64 (Block_Bytes * (N + 1)),
            T_Hi => 0,
            Last => False);
      end loop;
      pragma Assert
        (H = Spec.Fold (Spec.Initial_H (Key'Length, NN),
                        Key, Prefix, Message, DD - 1));

      --  Block dd - 1: final, offset counter ll (+ 128 when keyed).
      Core.Lemma_Same8
        (H, Spec.Fold (Spec.Initial_H (Key'Length, NN),
                       Key, Prefix, Message, DD - 1));
      Fill_Block (Key, Prefix, Message, DD - 1, Buf);
      Core.Lemma_Same_Block
        (Buf, Spec.Block_Of (Key, Prefix, Message, DD - 1));
      Core.Compress
        (H, Buf,
         T_Lo => U64 (L + Block_Bytes * KB),
         T_Hi => 0,
         Last => True);
      Core.Lemma_Same8 (H, Spec.Final_H (Key, Prefix, Message, NN));

      Digest :=
        [for J in Digest'Range => Core.Out_Byte (H, J - Digest'First)];

      --  The chaining value and the last block are as secret as the key
      --  and message they came from. Wiping values that are never read
      --  again is the point, so flow analysis's "no effect" is expected.
      pragma Warnings
        (GNATprove, Off, "statement has no effect",
         Reason => "zeroisation of secrets that are not read again");
      pragma Warnings
        (GNATprove, Off, """H"" is set by ""Sanitize_Words8""*",
         Reason => "zeroisation of secrets that are not read again");
      pragma Warnings
        (GNATprove, Off, """Buf"" is set by ""Sanitize_Block""*",
         Reason => "zeroisation of secrets that are not read again");
      Wipe.Sanitize_Words8 (H);
      Wipe.Sanitize_Block (Buf);
      pragma Warnings (GNATprove, On, "statement has no effect");
      pragma Warnings
        (GNATprove, On, """H"" is set by ""Sanitize_Words8""*");
      pragma Warnings
        (GNATprove, On, """Buf"" is set by ""Sanitize_Block""*");
   end Digest_Of;

   procedure Hash
     (Prefix  : Byte_Array;
      Message : Byte_Array;
      Key     : Byte_Array;
      Digest  : out Byte_Array) is
   begin
      Digest_Of (Prefix, Message, Key, Digest);
   end Hash;

   procedure Hash
     (Message : Byte_Array;
      Key     : Byte_Array;
      Digest  : out Byte_Array) is
   begin
      Digest_Of (No_Bytes, Message, Key, Digest);
   end Hash;
   ----------------------------------------------------------------------
   --  Incremental hashing
   ----------------------------------------------------------------------

   package Inc renames Spec.Incremental;
   use type Inc.Counter;

   function Value (Hi, Lo : U64) return Big_Natural is
     (Big.Word (Hi) * Two_64 + Big.Word (Lo))
   with Ghost;

   --  (Hi, Lo) := (Hi, Lo) + N: the 128-bit counter, carry included. Its
   --  contract states the addition twice, as arithmetic on mathematical
   --  integers and as the model's Plus (the reference implementation's
   --  increment), so a carry mistake in either one fails the proof.
   procedure Add_Counter (Hi, Lo : in out U64; N : U64)
   with Global => null,
        Pre    => Value (Hi, Lo) + Big.Word (N) < Two_128,
        Post   =>
          (Executable =>
             Value (Hi, Lo) = Value (Hi'Old, Lo'Old) + Big.Word (N)
             and then (if N mod Block_Bytes = 0
                         and then Lo'Old mod Block_Bytes = 0
                       then Lo mod Block_Bytes = 0),
           Static     =>
             Lo = Inc.Plus ((Lo => Lo'Old, Hi => Hi'Old), N).Lo
             and then Hi = Inc.Plus ((Lo => Lo'Old, Hi => Hi'Old), N).Hi)
   is
   begin
      Lo := Lo + N;
      if Lo < N then
         Hi := Hi + 1;
      end if;
   end Add_Counter;

   --  Valid states the input limit in 64-bit arithmetic; this lemma says
   --  it is the mathematical one: (Hi, Lo) + Len <= 2**128 - 1 exactly
   --  when Hi < 2**64 - 1 or Lo + Len <= 2**64 - 1.
   procedure Lemma_Bound (Hi, Lo : U64; Len : Buffer_Length)
   with Ghost,
        Global => null,
        Post   =>
          (Hi < U64'Last or else Lo <= U64'Last - U64 (Len))
          = (Value (Hi, Lo) + Big.Length (Len) <= Max_Input)
   is
   begin
      if Hi < U64'Last then
         pragma Assert (Big.Word (Hi) <= Two_64 - 2);
         pragma Assert
           (Value (Hi, Lo) <= (Two_64 - 2) * Two_64 + (Two_64 - 1));
      else
         pragma Assert
           (Value (Hi, Lo) = (Two_64 - 1) * Two_64 + Big.Word (Lo));
      end if;
   end Lemma_Bound;

   --  Advancing the counter one block at a time, as Update does, reaches
   --  the model's Advance: (T + 128 K) + 128 = T + 128 (K + 1), modulo
   --  2**128, carries included.
   procedure Lemma_Advance_Step (T : Inc.Counter; K : I64)
   with Ghost  => Static,
        Global => null,
        Pre    => K in 0 .. 2**26 - 1,
        Post   => Inc.Plus (Inc.Advance (T, K), Block_Bytes)
                  = Inc.Advance (T, K + 1)
   is
      A  : constant U64 := U64 (Block_Bytes * K);
      L1 : constant U64 := T.Lo + A;
   begin
      pragma Assert (U64 (Block_Bytes * (K + 1)) = A + Block_Bytes);
      if L1 < A then
         --  The first addition carried, so the second cannot.
         pragma Assert (L1 + Block_Bytes >= Block_Bytes);
         pragma Assert (T.Lo + (A + Block_Bytes) < A + Block_Bytes);
      else
         pragma Assert
           ((L1 + Block_Bytes < Block_Bytes)
            = (T.Lo + (A + Block_Bytes) < A + Block_Bytes));
      end if;
   end Lemma_Advance_Step;

   --  Zeroes everything in the state that is derived from the key or the
   --  input. S is the caller's object, so these stores cannot be removed
   --  as dead.
   procedure Wipe_State (S : in out State)
   with Global => null,
        Post   => S.H = [Chain_Index => 0]
                  and then S.Buf = [Block_Index => 0]
                  and then S.T_Lo = 0 and then S.T_Hi = 0
                  and then S.Buf_Len = 0
                  and then S.Phase = S.Phase'Old
   is
   begin
      Wipe.Sanitize_Words8 (S.H);
      Wipe.Sanitize_Block (S.Buf);
      S.T_Lo := 0;
      S.T_Hi := 0;
      S.Buf_Len := 0;
   end Wipe_State;

   procedure Init
     (S      : out State;
      Length : Digest_Length;
      Key    : Byte_Array) is
   begin
      S.H := Core.Initial_H (Key'Length, Length);
      S.T_Lo := 0;
      S.T_Hi := 0;
      S.Buf := [others => 0];
      S.NN := Length;
      S.Phase := Absorbing;
      --  A key is absorbed as a full, zero-padded block (RFC 7693,
      --  section 3.3), held back in the buffer like any other last block.
      if Key'Length > 0 then
         S.Buf (0 .. Key'Length - 1) := Key;
         S.Buf_Len := Block_Bytes;
      else
         S.Buf_Len := 0;
      end if;
      pragma Assert
        (Static =>
           (for all J in Block_Index =>
              Model (S).Buf (J) = Inc.Init (Key, Length).Buf (J)));
   end Init;

   --  As the reference implementation's blake2b_update: top up the
   --  buffer; if more input follows, compress it; compress whole blocks
   --  straight from Data while more than a block remains; buffer the
   --  remaining 1 .. 128 bytes. The last block is always left for Final.
   --
   --  Proof: block k of what this call compresses is block k of the
   --  stream "buffered bytes, then Data" (Inc.Stream_Fold), with counter
   --  T + 128 (k + 1); C0 and Tail0 are the context and buffered bytes on
   --  entry, the exact terms Inc.Update (Model (S)'Old, Data) is made of.
   procedure Update (S : in out State; Data : Byte_Array) is
      Old_Absorbed : constant Big_Natural := Absorbed (S) with Ghost;
      C0           : constant Inc.Context := Model (S)
      with Ghost => Static;
      Tail0        : constant Byte_Array := C0.Buf (0 .. C0.Buf_Len - 1)
      with Ghost => Static;
      Blocks       : I64 := 0 with Ghost => Static;
      Pos          : I64 := Data'First;
      Left         : I64 := Data'Length;
   begin
      if Left = 0 then
         return;
      end if;

      if Left > Block_Bytes - S.Buf_Len then
         declare
            Fill : constant I64 := Block_Bytes - S.Buf_Len;
         begin
            S.Buf (S.Buf_Len .. Block_Bytes - 1) :=
              Data (Pos .. Pos + Fill - 1);
            Pos := Pos + Fill;
            Left := Left - Fill;
         end;
         pragma Assert
           (Counter (S) + To_Big_Integer (Block_Bytes)
              + Big.Length (Left)
            = Old_Absorbed + Big.Length (Data'Length));
         pragma Assert (Value (S.T_Hi, S.T_Lo) = Counter (S));

         --  The topped-up buffer is block 0 of the stream.
         pragma Assert
           (Static =>
              (for all J in Block_Index =>
                 S.Buf (J) = Spec.Block_Of (No_Bytes, Tail0, Data, 0) (J)));
         Core.Lemma_Same_Block
           (S.Buf, Spec.Block_Of (No_Bytes, Tail0, Data, 0));
         Lemma_Advance_Step (C0.T, 0);
         Add_Counter (S.T_Hi, S.T_Lo, Block_Bytes);
         Core.Compress (S.H, S.Buf, S.T_Lo, S.T_Hi, Last => False);
         Blocks := 1;
         pragma Assert
           (Static => S.H = Inc.Stream_Fold (C0.H, C0.T, Tail0, Data, 1));
         S.Buf_Len := 0;
         pragma Assert
           (Left >= 1 and then Pos = Data'First + (Data'Length - Left));
         pragma Assert
           (Counter (S) + Big.Length (Left)
            = Old_Absorbed + Big.Length (Data'Length));

         while Left > Block_Bytes loop
            pragma Loop_Invariant
              (Left in Block_Bytes + 1 .. Data'Length
               and then Pos = Data'First + (Data'Length - Left));
            pragma Loop_Invariant
              (S.Buf_Len = 0
               and then S.T_Lo mod Block_Bytes = 0
               and then S.NN = S.NN'Loop_Entry
               and then S.Phase = Absorbing);
            pragma Loop_Invariant
              (Counter (S) + Big.Length (Left)
               = Old_Absorbed + Big.Length (Data'Length));
            pragma Loop_Invariant
              (Static =>
                 Block_Bytes * Blocks = C0.Buf_Len + (Pos - Data'First)
                 and then Blocks in 1 .. 2**25
                 and then S.H
                          = Inc.Stream_Fold (C0.H, C0.T, Tail0, Data, Blocks)
                 and then S.T_Lo = Inc.Advance (C0.T, Blocks).Lo
                 and then S.T_Hi = Inc.Advance (C0.T, Blocks).Hi);

            Core.Lemma_Same8
              (S.H, Inc.Stream_Fold (C0.H, C0.T, Tail0, Data, Blocks));
            pragma Assert
              (Static =>
                 (for all J in Block_Index =>
                    Data (Pos + J)
                    = Spec.Block_Of (No_Bytes, Tail0, Data, Blocks) (J)));
            Core.Lemma_Same_Block
              (Data (Pos .. Pos + Block_Bytes - 1),
               Spec.Block_Of (No_Bytes, Tail0, Data, Blocks));
            Lemma_Advance_Step (C0.T, Blocks);
            Add_Counter (S.T_Hi, S.T_Lo, Block_Bytes);
            Core.Compress
              (S.H, Data (Pos .. Pos + Block_Bytes - 1),
               S.T_Lo, S.T_Hi, Last => False);
            Blocks := Blocks + 1;
            pragma Assert
              (Static =>
                 S.H = Inc.Stream_Fold (C0.H, C0.T, Tail0, Data, Blocks));
            Pos := Pos + Block_Bytes;
            Left := Left - Block_Bytes;
         end loop;
      end if;

      --  Both paths meet here with 1 .. 128 - Buf_Len bytes left over,
      --  and every block of the stream but the last compressed.
      pragma Assert
        (Left in 1 .. Block_Bytes - S.Buf_Len
         and then Pos = Data'First + (Data'Length - Left));
      pragma Assert
        (Counter (S) + Big.Length (S.Buf_Len)
           + Big.Length (Left)
         = Old_Absorbed + Big.Length (Data'Length));
      pragma Assert
        (Static =>
           Blocks = (C0.Buf_Len + Data'Length - 1) / Block_Bytes
           and then S.H = Inc.Stream_Fold (C0.H, C0.T, Tail0, Data, Blocks)
           and then S.T_Lo = Inc.Advance (C0.T, Blocks).Lo
           and then S.T_Hi = Inc.Advance (C0.T, Blocks).Hi
           and then Block_Bytes * Blocks + S.Buf_Len
                    = C0.Buf_Len + (Pos - Data'First)
           and then (for all J in 0 .. S.Buf_Len - 1 =>
                       S.Buf (J)
                       = Spec.Block_Of (No_Bytes, Tail0, Data, Blocks) (J)));

      S.Buf (S.Buf_Len .. S.Buf_Len + Left - 1) :=
        Data (Pos .. Pos + Left - 1);
      S.Buf_Len := S.Buf_Len + Left;
      Lemma_Bound (S.T_Hi, S.T_Lo, S.Buf_Len);

      --  The buffer now holds the stream's last block, zero beyond it:
      --  the bytes kept from before, the bytes just copied from Data, and
      --  the padding.
      pragma Assert
        (Static =>
           (for all J in 0 .. S.Buf_Len - Left - 1 =>
              S.Buf (J)
              = Spec.Block_Of (No_Bytes, Tail0, Data, Blocks) (J)));
      pragma Assert
        (Static =>
           (for all J in S.Buf_Len - Left .. S.Buf_Len - 1 =>
              S.Buf (J) = Data (Pos + (J - (S.Buf_Len - Left)))));
      pragma Assert
        (Static =>
           (for all J in S.Buf_Len - Left .. S.Buf_Len - 1 =>
              Spec.Block_Of (No_Bytes, Tail0, Data, Blocks) (J)
              = Data (Pos + (J - (S.Buf_Len - Left)))));
      pragma Assert
        (Static =>
           (for all J in S.Buf_Len .. Block_Bytes - 1 =>
              Spec.Block_Of (No_Bytes, Tail0, Data, Blocks) (J) = 0));
      pragma Assert
        (Static =>
           (for all J in Block_Index =>
              (if J < S.Buf_Len then S.Buf (J) else 0)
              = Spec.Block_Of (No_Bytes, Tail0, Data, Blocks) (J)));

      --  So the state is the model's Update, field by field.
      pragma Assert (Is_Absorbing (S));
      pragma Assert
        (Static =>
           S.Buf_Len = C0.Buf_Len + Data'Length - Block_Bytes * Blocks);
      pragma Assert (Static => Model (S).H = Inc.Update (C0, Data).H);
      pragma Assert (Static => Model (S).T = Inc.Update (C0, Data).T);
      pragma Assert
        (Static =>
           (for all J in Block_Index =>
              Model (S).Buf (J) = Inc.Update (C0, Data).Buf (J)));
      pragma Assert
        (Static => Model (S).Buf_Len = Inc.Update (C0, Data).Buf_Len);
   end Update;

   procedure Final (S : in out State; Digest : out Byte_Array) is
      C0 : constant Inc.Context := Model (S) with Ghost => Static;
   begin
      Lemma_Bound (S.T_Hi, S.T_Lo, S.Buf_Len);
      --  The last block: counter = every input byte (RFC 7693, section
      --  3.3), zero-padded, compressed with the final flag.
      Add_Counter (S.T_Hi, S.T_Lo, U64 (S.Buf_Len));
      S.Buf (S.Buf_Len .. Block_Bytes - 1) := [others => 0];
      pragma Assert
        (Static => (for all J in Block_Index => S.Buf (J) = C0.Buf (J)));
      Core.Lemma_Same_Block (S.Buf, C0.Buf);
      Core.Compress (S.H, S.Buf, S.T_Lo, S.T_Hi, Last => True);
      --  (Proof-only assertions here must not call functions returning
      --  unconstrained arrays, such as Inc.Final: GNAT still sets up the
      --  secondary stack for them before discarding the Static code.)
      pragma Assert
        (Static =>
           S.H = Spec.Compress
                   (C0.H, C0.Buf,
                    T_Lo => Inc.Plus (C0.T, U64 (C0.Buf_Len)).Lo,
                    T_Hi => Inc.Plus (C0.T, U64 (C0.Buf_Len)).Hi,
                    Last => True));
      Digest :=
        [for J in Digest'Range => Core.Out_Byte (S.H, J - Digest'First)];
      Wipe_State (S);
      S.Phase := Finalized;
   end Final;

   procedure Clear (S : in out State) is
   begin
      Wipe_State (S);
      S.Phase := Empty;
   end Clear;

   ----------------------------------------------------------------------
   --  Proofs for clients
   ----------------------------------------------------------------------

   procedure Lemma_Update
     (S : State; Key, Before, Data, Joined : Byte_Array) is
   begin
      Inc.Lemma_Update (Model (S), Key, Before, Data, Joined);

      --  Has_Absorbed bounds the input far below RFC 7693's limit: the
      --  counter's high word is zero.
      pragma Assert (S.T_Hi = 0);
      pragma Assert (Counter (S) = Big.Word (S.T_Lo));
      pragma Assert (Counter (S) <= Two_64 - 1);
      pragma Assert (Big.Length (S.Buf_Len) <= Two_64 - 1);
      pragma Assert (Big.Length (Data'Length) <= Two_64 - 1);
      pragma Assert (Two_64 * Two_64 >= 4 * Two_64);
   end Lemma_Update;

   procedure Lemma_Final (S : State; Key, Message : Byte_Array) is
   begin
      Inc.Lemma_Final (Model (S), Key, Message);
   end Lemma_Final;

   procedure Theorem_Incremental
     (Message : Byte_Array;
      Key     : Byte_Array;
      Cuts    : Cut_Points;
      Digest  : out Byte_Array)
   is
      F : constant I64 := Message'First;
      S : State;
      P : I64 := 0;
   begin
      Init (S, Digest'Length, Key);
      pragma Assert (Has_Absorbed (S, Key, Message (F .. F - 1)));

      --  One piece per cut: the bytes from offset P up to the cut.
      for I in Cuts'Range loop
         pragma Loop_Invariant
           (P in 0 .. Message'Length
            and then (if I > Cuts'First then P = Cuts (I - 1) else P = 0)
            and then Is_Absorbing (S)
            and then Output_Length (S) = Digest'Length
            and then Has_Absorbed (S, Key, Message (F .. F + P - 1)));
         Lemma_Update
           (S, Key,
            Before => Message (F .. F + P - 1),
            Data   => Message (F + P .. F + Cuts (I) - 1),
            Joined => Message (F .. F + Cuts (I) - 1));
         Update (S, Message (F + P .. F + Cuts (I) - 1));
         P := Cuts (I);
      end loop;

      --  The rest of the message.
      Lemma_Update
        (S, Key,
         Before => Message (F .. F + P - 1),
         Data   => Message (F + P .. Message'Last),
         Joined => Message);
      Update (S, Message (F + P .. Message'Last));

      Lemma_Final (S, Key, Message);
      pragma Warnings
        (GNATprove, Off, """S"" is set by ""Final"" but not used*",
         Reason => "the theorem is about Digest; the state ends here");
      Final (S, Digest);
      pragma Warnings
        (GNATprove, On, """S"" is set by ""Final"" but not used*");
   end Theorem_Incremental;

end Blake2b.Hashing;
