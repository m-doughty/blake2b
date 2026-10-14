--  BLAKE2b (RFC 7693) in SPARK: a long message, hashed in pieces.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  Blake2b.Spec names a message as one Byte_Array, which holds at most
--  2**31 bytes. A client that feeds Blake2b.Hashing.Update a longer
--  message, one array at a time, needs a name for the whole of it. This
--  package gives one: a logical message of up to Max_Length bytes,
--  described by
--
--  * Contents: up to 14 sources of 2**32 bytes each, the mathematical
--    inputs the message is built from (a value only proofs construct, so
--    it is not bound by Byte_Array's size);
--  * Pieces: the message's bytes in order, each piece a run of bytes of
--    one source, placed at logical offset First. Pieces may be empty.
--
--  Byte_At gives byte P of the logical message, and zero at and past its
--  end (the RFC's zero padding). Blake2b.Streaming.Theory proves what
--  Init, Update and Final do to it; Blake2b.Streaming.Example is a
--  worked example over any number of Updates.
--
--  The domain is the one RFC 9106 (Argon2) needs: at most 2**34 + 36
--  bytes in all. A longer stream is still covered step by step by
--  Blake2b.Hashing's postconditions; this package claims nothing for it.
--
--  Static ghost code: GNATprove proves it, and no build ever compiles it.
--  Every declaration is marked static ghost, and deliberately not the
--  package itself, so that its object file still holds one symbol, the
--  package's elaboration flag: a library member with no symbols makes
--  macOS ranlib print a warning on every build of the library.

package Blake2b.Streaming
  with SPARK_Mode, Pure
is

   use type Byte;

   Max_Length : constant I64 := 2**34 + 36 with Ghost => Static;

   --  A logical offset or length.
   subtype Offset is I64 range 0 .. Max_Length with Ghost => Static;

   subtype Source_Id is Natural range 0 .. 13 with Ghost => Static;
   subtype Source_Position is I64 range 0 .. 2**32 - 1 with Ghost => Static;

   --  The sources' bytes: C (Id, P) is byte P of source Id.
   type Contents is
     array (Source_Id range <>, Source_Position range <>) of Byte
   with Ghost => Static;

   --  Count bytes of source Source from position Start, at logical
   --  offsets First .. First + Count - 1.
   type Piece is record
      Source : Source_Id;
      Start  : Source_Position;
      Count  : Offset;
      First  : Offset;
   end record
   with Ghost => Static;

   type Pieces is array (Positive range <>) of Piece
   with Ghost => Static;

   --  M cuts a logical message of Length bytes into consecutive pieces:
   --  the first starts at 0, each starts where the one before it ends,
   --  the last ends at Length, and each lies within its source.
   function Valid (M : Pieces; Length : Offset) return Boolean is
     (M'Length > 0
      and then M'Last < Positive'Last
      and then M (M'First).First = 0
      and then (for all I in M'Range =>
                  M (I).Count <= Length
                  and then M (I).First <= Length - M (I).Count
                  and then M (I).Count <= 2**32 - M (I).Start
                  and then (if I < M'Last
                            then M (I + 1).First
                                 = M (I).First + M (I).Count))
      and then M (M'Last).First + M (M'Last).Count = Length)
   with Ghost => Static;

   --  C has every source in full.
   function Has_Contents (C : Contents) return Boolean is
     (C'First (1) = Source_Id'First
      and then C'Last (1) = Source_Id'Last
      and then C'First (2) = Source_Position'First
      and then C'Last (2) = Source_Position'Last)
   with Ghost => Static;

   --  What Byte_At returns, stated without naming its search: zero at and
   --  past Length (the padding), and otherwise the source byte of every
   --  piece that holds P. Hidden from the provers; opened only by
   --  Byte_At (which proves it) and by Lemma_Absolute and Lemma_Padding
   --  (which use it).
   function Selects
     (C      : Contents;
      M      : Pieces;
      Length : Offset;
      P      : I64;
      V      : Byte) return Boolean
   is
     (if P >= Length then V = 0
      else
        (for all I in M'Range =>
           (if P >= M (I).First and then P - M (I).First < M (I).Count
            then V = C (M (I).Source, M (I).Start + P - M (I).First))))
   with Ghost => Static,
        Pre   => Has_Contents (C)
                 and then Valid (M, Length)
                 and then P in 0 .. Max_Length + 127;
   pragma Annotate
     (GNATprove, Hide_Info, "Expression_Function_Body", Selects);

   --  Pieces are in order: piece K ends no later than any later piece
   --  starts, so no later piece holds a byte of piece K.
   procedure Lemma_Order (M : Pieces; Length : Offset; K : Positive)
   with Ghost  => Static,
        Global => null,
        Pre    => Valid (M, Length) and then K in M'Range,
        Post   => (for all I in K + 1 .. M'Last =>
                     M (K).First + M (K).Count <= M (I).First);

   --  Byte P of the logical message, zero-padded: the source byte of the
   --  piece that holds P.
   function Byte_At
     (C      : Contents;
      M      : Pieces;
      Length : Offset;
      P      : I64) return Byte
   with Ghost  => Static,
        Global => null,
        Pre    => Has_Contents (C)
                  and then Valid (M, Length)
                  and then P in 0 .. Max_Length + 127,
        Post   => Selects (C, M, Length, P, Byte_At'Result);

   --  Inside piece I, Byte_At is that piece's source byte.
   procedure Lemma_Absolute
     (C      : Contents;
      M      : Pieces;
      Length : Offset;
      P      : I64;
      I      : Positive)
   with Ghost  => Static,
        Global => null,
        Pre    => Has_Contents (C)
                  and then Valid (M, Length)
                  and then I in M'Range
                  and then P >= M (I).First
                  and then P - M (I).First < M (I).Count,
        Post   => Byte_At (C, M, Length, P)
                  = C (M (I).Source, M (I).Start + P - M (I).First);

   --  From Length on, Byte_At is zero.
   procedure Lemma_Padding
     (C      : Contents;
      M      : Pieces;
      Length : Offset;
      P      : I64)
   with Ghost  => Static,
        Global => null,
        Pre    => Has_Contents (C)
                  and then Valid (M, Length)
                  and then P in Length .. Max_Length + 127,
        Post   => Byte_At (C, M, Length, P) = 0;

end Blake2b.Streaming;
