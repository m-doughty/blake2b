--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Blake2b.Spec.Incremental;

--  The proof of Lemma_Consistent. Static ghost code: proved by GNATprove,
--  never compiled.

package body Blake2b.Streaming.Consistency
  with SPARK_Mode
is

   package Inc renames Blake2b.Spec.Incremental;

   --  Transitivity of array equality, in a context small enough that the
   --  provers unfold "=" on byte arrays cheaply.
   procedure Lemma_Eq_Trans (X, A, B : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => A = X and then B = X,
        Post   => A = B
   is
   begin
      null;
   end Lemma_Eq_Trans;

   --  Update (Init, Message) finishes to both hashes: to Spec.Hash by
   --  Blake2b.Spec.Incremental's lemmas, and to Logical_Hash by the
   --  theory's, since it is the context of the whole logical message.
   procedure Lemma_Consistent
     (Key     : Byte_Array;
      C       : Contents;
      M       : Pieces;
      Length  : Offset;
      Message : Byte_Array;
      NN      : Digest_Length)
   is
      Init : constant Inc.Context := Inc.Init (Key, NN);
      E    : constant Byte_Array (1 .. 0) := [others => 0];
   begin
      --  The specification's side.
      Inc.Lemma_Update (Init, Key, E, Message, Message);
      Inc.Lemma_Final (Inc.Update (Init, Message), Key, Message);
      --  The logical side.
      Lemma_Init (Key, C, M, Length, NN);
      Lemma_Update_Of (Init, Key, C, M, Length, 0, Message);
      Lemma_Final_Of (Inc.Update (Init, Message), Key, C, M, Length);
      pragma Assert (Inc.Update (Init, Message).NN = NN);
      pragma Assert
        (Inc.Final (Inc.Update (Init, Message))
         = Spec.Hash (Message, Key, NN));
      pragma Assert
        (Inc.Final (Inc.Update (Init, Message))
         = Logical_Hash (Key, C, M, Length, NN));
      Lemma_Eq_Trans (Inc.Final (Inc.Update (Init, Message)),
                      Logical_Hash (Key, C, M, Length, NN),
                      Spec.Hash (Message, Key, NN));
   end Lemma_Consistent;

end Blake2b.Streaming.Consistency;
