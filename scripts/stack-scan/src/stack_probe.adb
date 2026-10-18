--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Ada.Text_IO;

package body Stack_Probe is

   type Volatile_Words is array (Natural range <>) of Unsigned_64
   with Volatile_Components;

   procedure Region (Snap : Boolean; Dest : Word_Array_Access) is
      --  Not initialised: in Snap mode it holds whatever the stack held.
      --  Each read and write of it is a volatile access, so none is
      --  removed or merged.
      Local : Volatile_Words (0 .. Dest'Length - 1);
      pragma Warnings
        (Off, Local, Reason => "read uninitialised on purpose: the probe");
   begin
      if Snap then
         for I in Local'Range loop
            Dest (Dest'First + I) := Local (I);
         end loop;
      else
         for I in Local'Range loop
            Local (I) := 0;
         end loop;
      end if;
   end Region;

   function Mix (Seed : Unsigned_64) return Unsigned_64 is
      Z : Unsigned_64 := Seed + 16#9E37_79B9_7F4A_7C15#;
   begin
      Z := (Z xor Shift_Right (Z, 30)) * 16#BF58_476D_1CE4_E5B9#;
      Z := (Z xor Shift_Right (Z, 27)) * 16#94D0_49BB_1331_11EB#;
      return Z xor Shift_Right (Z, 31);
   end Mix;

   function Byte_At (Snap : Word_Array; K : Natural) return Unsigned_64 is
     (Shift_Right (Snap (Snap'First + K / 8), 8 * (K mod 8)) and 16#FF#);

   function Img (N : Natural) return String is
      S : constant String := Natural'Image (N);
   begin
      return S (S'First + 1 .. S'Last);
   end Img;

   --  The depths (bytes below the top of the region) of the first hits
   --  Count found, and the index in the class of the word found there, for
   --  the report.
   Max_Depths : constant := 8;
   Depths     : array (1 .. Max_Depths) of Natural;
   Indices    : array (1 .. Max_Depths) of Natural;
   Depth_Count : Natural := 0;

   procedure Count
     (Snap      : Word_Array;
      Class     : Word_Array;
      Aligned   : out Natural;
      Unaligned : out Natural;
      Distinct  : out Natural)
   is
      Found : array (Class'Range) of Boolean := [others => False];
      Bytes : constant Natural := 8 * Snap'Length;
      W     : Unsigned_64;
   begin
      Aligned := 0;
      Unaligned := 0;
      Distinct := 0;
      Depth_Count := 0;
      if Bytes < 8 then
         return;
      end if;
      for Offset in 0 .. Bytes - 8 loop
         W := 0;
         for B in 0 .. 7 loop
            W := W or Shift_Left (Byte_At (Snap, Offset + B), 8 * B);
         end loop;
         for C in Class'Range loop
            if W = Class (C) then
               if Offset mod 8 = 0 then
                  Aligned := Aligned + 1;
               else
                  Unaligned := Unaligned + 1;
               end if;
               Found (C) := True;
               if Depth_Count < Max_Depths then
                  Depth_Count := Depth_Count + 1;
                  Depths (Depth_Count) := Bytes - Offset;
                  Indices (Depth_Count) := C;
               end if;
            end if;
         end loop;
      end loop;
      for C in Class'Range loop
         if Found (C) then
            Distinct := Distinct + 1;
         end if;
      end loop;
   end Count;

   function Touched (Snap : Word_Array) return Natural is
   begin
      for I in Snap'Range loop
         if Snap (I) /= 0 then
            for B in 0 .. 7 loop
               if (Shift_Right (Snap (I), 8 * B) and 16#FF#) /= 0 then
                  return 8 * (Snap'Last - I) + (8 - B);
               end if;
            end loop;
         end if;
      end loop;
      return 0;
   end Touched;

   procedure Put_Hits
     (Prefix : String; Snap : Word_Array; Name : String; Class : Word_Array)
   is
      Aligned, Unaligned, Distinct : Natural;
   begin
      Count (Snap, Class, Aligned, Unaligned, Distinct);
      Ada.Text_IO.Put
        (Prefix & " touched=" & Img (Touched (Snap)) & " class=" & Name
         & " aligned=" & Img (Aligned) & " unaligned=" & Img (Unaligned)
         & " distinct=" & Img (Distinct) & " depths=");
      if Depth_Count = 0 then
         Ada.Text_IO.Put ("-");
      end if;
      for D in 1 .. Depth_Count loop
         Ada.Text_IO.Put
           ((if D > 1 then "," else "") & Img (Depths (D)) & "#"
            & Img (Indices (D)));
      end loop;
      Ada.Text_IO.New_Line;
   end Put_Hits;

end Stack_Probe;
