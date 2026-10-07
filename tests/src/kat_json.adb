--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Ada.Streams;            use Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Strings.Fixed;      use Ada.Strings.Fixed;
with Ada.Strings.Unbounded;  use Ada.Strings.Unbounded;
with Ada.Text_IO;            use Ada.Text_IO;
with GNAT.SHA256;

with Test_Support;

package body Kat_Json is

   function File_Digest (Path : String) return String is
      use Ada.Streams.Stream_IO;
      F       : Ada.Streams.Stream_IO.File_Type;
      Context : GNAT.SHA256.Context := GNAT.SHA256.Initial_Context;
      Buffer  : Stream_Element_Array (1 .. 65_536);
      Last    : Stream_Element_Offset;
   begin
      Open (F, In_File, Path);
      while not End_Of_File (F) loop
         Read (F, Buffer, Last);
         GNAT.SHA256.Update (Context, Buffer (1 .. Last));
      end loop;
      Close (F);
      return GNAT.SHA256.Digest (Context);
   end File_Digest;

   --  The file is a JSON array of flat objects, one field per line:
   --      {
   --          "hash": "blake2b",
   --          "in": "00",
   --          "key": "",
   --          "out": "2fa3...e5"
   --      },
   --  Value_Of returns the string value on a line holding Name, or the
   --  empty string if the line holds some other field.
   function Value_Of (Line, Name : String) return String is
      Marker : constant String := """" & Name & """: """;
      Start  : constant Natural := Ada.Strings.Fixed.Index (Line, Marker);
   begin
      if Start = 0 then
         return "";
      end if;
      declare
         From : constant Positive := Start + Marker'Length;
         Stop : constant Natural :=
           Ada.Strings.Fixed.Index (Line (From .. Line'Last), """");
      begin
         if Stop = 0 then
            raise Constraint_Error with "unterminated value: " & Line;
         end if;
         return Line (From .. Stop - 1);
      end;
   end Value_Of;

   function Has_Field (Line, Name : String) return Boolean is
     (Ada.Strings.Fixed.Index (Line, """" & Name & """: """) /= 0);

   procedure For_Each_Blake2b (Path : String; Count : out Natural) is
      F                         : File_Type;
      Hash, Input, Key, Out_Hex : Unbounded_String;
   begin
      Count := 0;
      Open (F, In_File, Path);
      while not End_Of_File (F) loop
         declare
            Line : constant String := Get_Line (F);
         begin
            if Has_Field (Line, "hash") then
               Hash := To_Unbounded_String (Value_Of (Line, "hash"));
            elsif Has_Field (Line, "in") then
               Input := To_Unbounded_String (Value_Of (Line, "in"));
            elsif Has_Field (Line, "key") then
               Key := To_Unbounded_String (Value_Of (Line, "key"));
            elsif Has_Field (Line, "out") then
               Out_Hex := To_Unbounded_String (Value_Of (Line, "out"));
            elsif Trim (Line, Ada.Strings.Both) in "}" | "}," then
               if To_String (Hash) = "blake2b" then
                  Visit (Test_Support.From_Hex (To_String (Input)),
                         Test_Support.From_Hex (To_String (Key)),
                         Test_Support.From_Hex (To_String (Out_Hex)));
                  Count := Count + 1;
               end if;
               Hash    := Null_Unbounded_String;
               Input   := Null_Unbounded_String;
               Key     := Null_Unbounded_String;
               Out_Hex := Null_Unbounded_String;
            end if;
         end;
      end loop;
      Close (F);
   end For_Each_Blake2b;

end Kat_Json;
