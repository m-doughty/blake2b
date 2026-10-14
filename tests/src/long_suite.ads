--  Long streams: messages longer than any Byte_Array (Index'Last is
--  2**31 - 1), hashed incrementally by Blake2b.Hashing and by the two C
--  oracles' own incremental interfaces. The implementation cuts the stream at
--  its own points; the two oracles share one cut schedule. Not part of the
--  default run or of the build matrix: two streams of 20 GiB and 165 bytes
--  in all are hashed three times. Run, from the tests/ directory, in the
--  release profile:
--
--    alr -n build --release
--    ./bin/profile-profile/test_main --long
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

package Long_Suite is

   --  Two streams: 2**32 + 129 bytes, unkeyed with a 64-byte digest, then
   --  2**34 + 36 bytes with a 64-byte key and a 32-byte digest.
   procedure Run;

end Long_Suite;
