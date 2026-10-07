--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

package body Blake2b.Wipe
  with SPARK_Mode
is

   procedure Sanitize_Words8 (R : out Words8) is
   begin
      R := [others => 0];
      pragma Inspection_Point (R); --  RM H.3.2 (9)
   end Sanitize_Words8;

   procedure Sanitize_Block (R : out Block) is
   begin
      R := [others => 0];
      pragma Inspection_Point (R); --  RM H.3.2 (9)
   end Sanitize_Block;

end Blake2b.Wipe;
