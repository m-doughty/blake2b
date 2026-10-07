#!/usr/bin/env python3
"""Third oracle: BLAKE2b test vectors from CPython's hashlib.

From Python 3.14, hashlib.blake2b is HACL*'s formally verified
implementation (CPython gh-99108), independent of both C oracles vendored
in tests/ref. This writes vectors in the layout of the BLAKE2 team's
blake2-kat.json, but over every key length (0..64) and digest length
(1..64) rather than only 64-byte keys and digests, for

    tests/bin/profile-profile/test_main --vectors <file>

Usage: scripts/cpython-vectors.py <output.json> [count]
"""

import hashlib
import json
import random
import sys

if sys.version_info < (3, 14):
    sys.exit("needs Python 3.14 or later (hashlib.blake2b from HACL*)")

if len(sys.argv) < 2:
    sys.exit(__doc__)

out_path = sys.argv[1]
count = int(sys.argv[2]) if len(sys.argv) > 2 else 20_000

rng = random.Random(0xB1A2E)  # fixed seed: the same file every run
entries = []
for _ in range(count):
    length = rng.randrange(0, 2_049)
    key_length = rng.randrange(0, 65)
    digest_length = rng.randrange(1, 65)
    message = rng.randbytes(length)
    key = rng.randbytes(key_length)
    digest = hashlib.blake2b(message, key=key, digest_size=digest_length)
    entries.append({
        "hash": "blake2b",
        "in": message.hex(),
        "key": key.hex(),
        "out": digest.hexdigest(),
    })

with open(out_path, "w", newline="\n") as f:
    json.dump(entries, f, indent=4)
    f.write("\n")

print(f"wrote {count} vectors to {out_path} (Python {sys.version.split()[0]})")
