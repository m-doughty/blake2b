--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  The proofs of the model's accessor and its lemmas. Static ghost code,
--  like the specification: proved by GNATprove, never compiled.

package body Blake2b.Streaming
  with SPARK_Mode
is

   --  By induction over the pieces after K.
   procedure Lemma_Order (M : Pieces; Length : Offset; K : Positive) is
      --  Length appears only in the precondition (Valid).
      pragma Unreferenced (Length);
   begin
      for J in K + 1 .. M'Last loop
         pragma Loop_Invariant
           (for all I in K + 1 .. J =>
              M (K).First + M (K).Count <= M (I).First);
      end loop;
   end Lemma_Order;

   function Byte_At
     (C      : Contents;
      M      : Pieces;
      Length : Offset;
      P      : I64) return Byte
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", Selects);
      Result : Byte := 0;
   begin
      if P < Length then
         for I in M'Range loop
            pragma Loop_Invariant (P >= M (I).First);
            pragma Loop_Invariant
              (for all J in M'First .. I - 1 =>
                 P >= M (J).First + M (J).Count);
            if P >= M (I).First and then P - M (I).First < M (I).Count then
               --  Later pieces start at or after this one's end, so none
               --  holds P.
               Lemma_Order (M, Length, I);
               Result := C (M (I).Source, M (I).Start + P - M (I).First);
               exit;
            end if;
         end loop;
      end if;
      return Result;
   end Byte_At;

   procedure Lemma_Absolute
     (C      : Contents;
      M      : Pieces;
      Length : Offset;
      P      : I64;
      I      : Positive)
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", Selects);
   begin
      null;
   end Lemma_Absolute;

   procedure Lemma_Padding
     (C      : Contents;
      M      : Pieces;
      Length : Offset;
      P      : I64)
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", Selects);
   begin
      null;
   end Lemma_Padding;

end Blake2b.Streaming;
