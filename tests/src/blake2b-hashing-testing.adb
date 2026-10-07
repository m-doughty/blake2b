--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

package body Blake2b.Hashing.Testing is

   function Is_Wiped (S : State) return Boolean is
     (S.H = [Chain_Index => 0]
      and then S.Buf = [Block_Index => 0]
      and then S.T_Lo = 0
      and then S.T_Hi = 0
      and then S.Buf_Len = 0);

   function Model_Of (S : State) return Spec.Incremental.Context is
     ((H       => S.H,
       T       => (Lo => S.T_Lo, Hi => S.T_Hi),
       Buf     => [for J in Block_Index =>
                     (if J < S.Buf_Len then S.Buf (J) else 0)],
       Buf_Len => S.Buf_Len,
       NN      => S.NN));

end Blake2b.Hashing.Testing;
