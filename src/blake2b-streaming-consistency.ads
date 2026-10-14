--  BLAKE2b (RFC 7693) in SPARK: the logical hash is the specification's.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Blake2b.Spec;
with Blake2b.Streaming.Theory;
use Blake2b.Streaming.Theory;

--  Blake2b.Streaming.Theory defines the digest of a logical message
--  directly (Logical_Hash), not through Blake2b.Spec. This ties the two
--  together: wherever one Byte_Array holds the message, Logical_Hash is
--  Spec.Hash, the transcription of RFC 7693 that the tests validate.
--
--  Static ghost code: GNATprove proves it, and no build ever compiles it.
--  Every declaration is marked static ghost, and deliberately not the
--  package itself, so that its object file still holds one symbol, the
--  package's elaboration flag: a library member with no symbols makes
--  macOS ranlib print a warning on every build of the library.

package Blake2b.Streaming.Consistency
  with SPARK_Mode, Pure
is

   procedure Lemma_Consistent
     (Key     : Byte_Array;
      C       : Contents;
      M       : Pieces;
      Length  : Offset;
      Message : Byte_Array;
      NN      : Digest_Length)
   with Ghost  => Static,
        Global => null,
        Pre    => OK (Key, C, M, Length)
                  and then Message'Length = Length
                  and then Realizes (C, M, Length, 0, Message),
        Post   => Logical_Hash (Key, C, M, Length, NN)
                  = Spec.Hash (Message, Key, NN);

end Blake2b.Streaming.Consistency;
