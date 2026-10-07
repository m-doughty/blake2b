--  BLAKE2b (RFC 7693) in SPARK: the specification.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  The specification is executable in every build, whatever the build's
--  own assertion policy: the test suite runs it against the published
--  test vectors and two independent C implementations, which is how the
--  transcription below is validated. (Proof shows the implementation
--  equals this specification; only testing can show this specification
--  equals BLAKE2b.)
pragma Assertion_Policy (Ghost => Check);

with Interfaces; use Interfaces;

--  A literal transcription of RFC 7693, written for reading against the
--  RFC rather than for speed. Section numbers refer to the RFC.
--
--  Ghost: implementation code can reference this package only from
--  contracts and assertions, never to compute a result.
--
--  Inputs are described at the byte level: the RFC's padded input d is
--  the key padded to a block (if keyed) followed by the data padded to
--  whole blocks, and Byte_At gives byte J of it directly, without ever
--  building the concatenation. The data is two parts, Prefix then
--  Message; the one-part hash is the two-part one with an empty Prefix.

package Blake2b.Spec
  with SPARK_Mode, Ghost, Pure
is

   --  Section 2.6: the initialisation vector (the SHA-512 IV).
   IV : constant Words8 :=
     [16#6A09_E667_F3BC_C908#, 16#BB67_AE85_84CA_A73B#,
      16#3C6E_F372_FE94_F82B#, 16#A54F_F53A_5F1D_36F1#,
      16#510E_527F_ADE6_82D1#, 16#9B05_688C_2B3E_6C1F#,
      16#1F83_D9AB_FB41_BD6B#, 16#5BE0_CD19_137E_2179#];

   --  Section 2.7: the message schedule SIGMA.
   type Sigma_Index is range 0 .. 9;
   type Sigma_Row is array (Word_Index) of Word_Index;
   type Sigma_Table is array (Sigma_Index) of Sigma_Row;

   SIGMA : constant Sigma_Table :=
     [[0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15],
      [14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3],
      [11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4],
      [7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8],
      [9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13],
      [2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9],
      [12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11],
      [13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10],
      [6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5],
      [10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0]];

   --  Section 3.1: the mixing function G, with BLAKE2b's rotation
   --  constants (R1, R2, R3, R4) = (32, 24, 16, 63) from section 2.1.
   function Distinct (A, B, C, D : Word_Index) return Boolean is
     (A /= B and then A /= C and then A /= D
      and then B /= C and then B /= D and then C /= D);

   function G
     (V : Words16; A, B, C, D : Word_Index; X, Y : U64) return Words16
   is
     (declare
         VA1 : constant U64 := V (A) + V (B) + X;
         VD1 : constant U64 := Rotate_Right (V (D) xor VA1, 32);
         VC1 : constant U64 := V (C) + VD1;
         VB1 : constant U64 := Rotate_Right (V (B) xor VC1, 24);
         VA2 : constant U64 := VA1 + VB1 + Y;
         VD2 : constant U64 := Rotate_Right (VD1 xor VA2, 16);
         VC2 : constant U64 := VC1 + VD2;
         VB2 : constant U64 := Rotate_Right (VB1 xor VC2, 63);
      begin
         [V with delta A => VA2, B => VB2, C => VC2, D => VD2])
   with Pre => Distinct (A, B, C, D);

   --  Proof structure: the bodies of G and Round are hidden by default,
   --  so the provers treat them as opaque functions and compose them by
   --  substitution. Each body is revealed only where it is the thing
   --  being proved (Unhide_Info in Blake2b.Core.G and Blake2b.Core.Round).
   pragma Annotate (GNATprove, Hide_Info, "Expression_Function_Body", G);

   --  Section 3.2: one round of the compression function F, using
   --  s = SIGMA[i mod 10] for round i.
   type Round_Number is range 0 .. 11;

   function Round (V, M : Words16; R : Round_Number) return Words16 is
     (declare
         S  : constant Sigma_Row := SIGMA (Sigma_Index (R mod 10));
         V1 : constant Words16 :=
           G (V, 0, 4, 8, 12, M (S (0)), M (S (1)));
         V2 : constant Words16 :=
           G (V1, 1, 5, 9, 13, M (S (2)), M (S (3)));
         V3 : constant Words16 :=
           G (V2, 2, 6, 10, 14, M (S (4)), M (S (5)));
         V4 : constant Words16 :=
           G (V3, 3, 7, 11, 15, M (S (6)), M (S (7)));
         V5 : constant Words16 :=
           G (V4, 0, 5, 10, 15, M (S (8)), M (S (9)));
         V6 : constant Words16 :=
           G (V5, 1, 6, 11, 12, M (S (10)), M (S (11)));
         V7 : constant Words16 :=
           G (V6, 2, 7, 8, 13, M (S (12)), M (S (13)));
         V8 : constant Words16 :=
           G (V7, 3, 4, 9, 14, M (S (14)), M (S (15)));
      begin
         V8);
   pragma Annotate
     (GNATprove, Hide_Info, "Expression_Function_Body", Round);

   --  The first N rounds, applied in order (BLAKE2b uses all 12).
   function Rounds (V, M : Words16; N : Natural) return Words16 is
     (if N = 0 then V
      else Round (Rounds (V, M, N - 1), M, Round_Number (N - 1)))
   with Pre                => N <= 12,
        Subprogram_Variant => (Decreases => N);

   --  Section 2.4: words are read from bytes little-endian. Word I of a
   --  block is bytes 8I .. 8I + 7.
   function Word_At (B : Block; I : Word_Index) return U64 is
     (declare
         P : constant Block_Index := Block_Index (8 * I64 (I));
      begin
         U64 (B (P))
         or Shift_Left (U64 (B (P + 1)), 8)
         or Shift_Left (U64 (B (P + 2)), 16)
         or Shift_Left (U64 (B (P + 3)), 24)
         or Shift_Left (U64 (B (P + 4)), 32)
         or Shift_Left (U64 (B (P + 5)), 40)
         or Shift_Left (U64 (B (P + 6)), 48)
         or Shift_Left (U64 (B (P + 7)), 56));

   function Words_Of (B : Block) return Words16 is
     [for I in Word_Index => Word_At (B, I)];

   --  Section 3.2: the working vector's initial value. The offset
   --  counter t is 128 bits: T_Lo is t mod 2**64 and T_Hi is t >> 64.
   --  On the last block, v[14] is inverted (XOR with all ones).
   function Initial_V
     (H : Words8; T_Lo, T_Hi : U64; Last : Boolean) return Words16
   is
     [H (0), H (1), H (2), H (3), H (4), H (5), H (6), H (7),
      IV (0), IV (1), IV (2), IV (3),
      IV (4) xor T_Lo,
      IV (5) xor T_Hi,
      (if Last then IV (6) xor U64'Last else IV (6)),
      IV (7)];

   --  Section 3.2: the compression function F. The only place block
   --  bytes become words.
   function Compress
     (H : Words8; B : Block; T_Lo, T_Hi : U64; Last : Boolean)
      return Words8
   is
     (declare
         V : constant Words16 :=
           Rounds (Initial_V (H, T_Lo, T_Hi, Last), Words_Of (B), 12);
      begin
         [for I in Chain_Index =>
            H (I) xor V (Word_Index (I)) xor V (Word_Index (I) + 8)]);
   pragma Annotate
     (GNATprove, Hide_Info, "Expression_Function_Body", Compress);

   --  Section 3.3: the parameter block folded into h[0]:
   --  h[0] := h[0] ^ 0x01010000 ^ (kk << 8) ^ nn.
   function Initial_H (KK : Key_Length; NN : Digest_Length) return Words8
   is
     [IV with delta
        0 => IV (0) xor 16#0101_0000#
               xor Shift_Left (U64 (KK), 8)
               xor U64 (NN)];

   --  The one bound the inputs need beyond their types: a key of at most
   --  64 bytes. (Prefix and Message are each at most 2**31 bytes by
   --  their index type, so every offset below stays well inside I64.)
   function Valid_Key (Key : Byte_Array) return Boolean is
     (Key'Length <= Max_Key_Bytes);

   --  Section 3.3: kk > 0 contributes one padded key block, and the data
   --  (ll bytes) contributes ceil (ll / 128) blocks. An unkeyed empty
   --  input still has one (all-zero) block: dd = 1.
   function Key_Blocks (Key : Byte_Array) return I64 is
     (if Key'Length > 0 then 1 else 0);

   function Data_Length (Prefix, Message : Byte_Array) return I64 is
     (Prefix'Length + Message'Length);

   function Block_Count (Key, Prefix, Message : Byte_Array) return I64 is
     (declare
         D : constant I64 :=
           Key_Blocks (Key)
           + (Data_Length (Prefix, Message) + (Block_Bytes - 1))
             / Block_Bytes;
      begin
         (if D = 0 then 1 else D))
   with Pre  => Valid_Key (Key),
        Post => Block_Count'Result in 1 .. 2**26;

   --  Byte J of the padded input d: the key, zero-padded to a full block
   --  (only when keyed), then Prefix, then Message, then zeroes.
   function Byte_At
     (Key, Prefix, Message : Byte_Array; J : I64) return Byte
   is
     (declare
         KB : constant I64 := Block_Bytes * Key_Blocks (Key);
      begin
         (if J < KB then
            (if J < Key'Length then Key (Key'First + J) else 0)
          elsif J - KB < Prefix'Length then
             Prefix (Prefix'First + (J - KB))
          elsif J - KB - Prefix'Length < Message'Length then
             Message (Message'First + (J - KB - Prefix'Length))
          else 0))
   with Pre => Valid_Key (Key)
               and then J in 0 .. Block_Bytes
                                  * Block_Count (Key, Prefix, Message) - 1;

   --  Block N (from 0) of the padded input, d[N].
   function Block_Of
     (Key, Prefix, Message : Byte_Array; N : I64) return Block
   is
     [for J in Block_Index =>
        Byte_At (Key, Prefix, Message, Block_Bytes * N + J)]
   with Pre => Valid_Key (Key)
               and then N in 0 .. Block_Count (Key, Prefix, Message) - 1;

   --  Section 3.3: the chaining value after the first N blocks, each
   --  compressed as a non-final block with offset counter (i + 1) * 128.
   function Fold
     (H : Words8; Key, Prefix, Message : Byte_Array; N : I64)
      return Words8
   is
     (if N = 0 then H
      else Compress (Fold (H, Key, Prefix, Message, N - 1),
                     Block_Of (Key, Prefix, Message, N - 1),
                     T_Lo => U64 (Block_Bytes * N),
                     T_Hi => 0,
                     Last => False))
   with Pre                => Valid_Key (Key)
                              and then N in 0 .. Block_Count
                                                   (Key, Prefix, Message)
                                                 - 1,
        Subprogram_Variant => (Decreases => N);

   --  Section 3.3: the final chaining value. The last block d[dd - 1] is
   --  compressed with the final flag set and offset counter ll (unkeyed)
   --  or ll + 128 (keyed).
   function Final_H
     (Key, Prefix, Message : Byte_Array; NN : Digest_Length) return Words8
   is
     (declare
         DD : constant I64 := Block_Count (Key, Prefix, Message);
         T  : constant U64 :=
           U64 (Data_Length (Prefix, Message)
                + Block_Bytes * Key_Blocks (Key));
      begin
         Compress (Fold (Initial_H (Key'Length, NN),
                         Key, Prefix, Message, DD - 1),
                   Block_Of (Key, Prefix, Message, DD - 1),
                   T_Lo => T,
                   T_Hi => 0,
                   Last => True))
   with Pre => Valid_Key (Key);

   --  Section 3.3: the digest is the first nn bytes of h, read as
   --  little-endian words.
   function Out_Byte (H : Words8; J : I64) return Byte is
     (Byte (Shift_Right (H (Chain_Index (J / 8)), Natural (8 * (J mod 8)))
            and 16#FF#))
   with Pre => J in 0 .. Max_Digest_Bytes - 1;

   --  BLAKE2b of Prefix followed by Message, keyed with Key, giving NN
   --  bytes. The result is indexed from 0.
   function Hash2
     (Prefix, Message, Key : Byte_Array; NN : Digest_Length)
      return Byte_Array
   is
     (declare
         H : constant Words8 := Final_H (Key, Prefix, Message, NN);
      begin
         [for J in 0 .. NN - 1 => Out_Byte (H, J)])
   with Pre  => Valid_Key (Key),
        Post => Hash2'Result'First = 0
                and then Hash2'Result'Length = NN;

   --  BLAKE2b of Message, keyed with Key (No_Bytes for unkeyed hashing),
   --  giving NN bytes.
   function Hash
     (Message, Key : Byte_Array; NN : Digest_Length) return Byte_Array
   is
     (Hash2 (No_Bytes, Message, Key, NN))
   with Pre  => Valid_Key (Key),
        Post => Hash'Result'First = 0 and then Hash'Result'Length = NN;

end Blake2b.Spec;
