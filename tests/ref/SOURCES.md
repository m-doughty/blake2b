# Vendored third-party files

Test-only oracles and data, kept byte-for-byte as published (see
`.gitattributes`: never line-ending converted). None of it is linked into
the library.

## BLAKE2 reference implementation and known answers

Repository: <https://github.com/BLAKE2/BLAKE2>, commit
`ed1974ea83433eba7b2d95c5dcd9ac33cb847913`. Licence: CC0 1.0, OpenSSL or
Apache 2.0 at the user's choice; `BLAKE2-COPYING` is the CC0 text.

| File | Upstream path | SHA-256 |
|---|---|---|
| `blake2b-ref.c` | `ref/blake2b-ref.c` | `e2bf9872a8f0a51711b765936d420a7f8c34797db4d938948c24f2ddbc1dc588` |
| `blake2.h` | `ref/blake2.h` | `389bc87a83cdd9e25569a294d01a3347970d117237a66eee9df8edd6058736a4` |
| `blake2-impl.h` | `ref/blake2-impl.h` | `bc0ead7f3259a415325fa40ddebb1876f903d5062d888fc5994e8b2d9e616ec4` |
| `BLAKE2-COPYING` | `COPYING` | `a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499` |
| `../data/blake2-kat.json` | `testvectors/blake2-kat.json` | `5031ac14800798ae15cee79c04d65e326a575f2c968c7e2846a79bd07a1c0e61` |

The known-answer file's digest is also pinned in `tests/src/kat_json.ads`;
the suite refuses to run against any other.

## Monocypher

Release 4.0.3, <https://github.com/LoupVaillant/Monocypher/releases/tag/4.0.3>
(tarball `monocypher-4.0.3.tar.gz`, SHA-256
`8cc9bc341a66249016db9bd70e9142d8d0aef9945973744b1ac05dbc55d8ee66`,
matching the digest GitHub publishes for the release asset). Licence: CC0
1.0 or BSD-2-Clause at the user's choice (`MONOCYPHER-LICENCE.md`).

| File | Path in the tarball | SHA-256 |
|---|---|---|
| `monocypher.c` | `src/monocypher.c` | `57eb914fc88136119bd41655cccb8c250048bf54d470540625186f8ab16f64be` |
| `monocypher.h` | `src/monocypher.h` | `c494da712122da7ff679fdcf318a5317e84972b6c950fe9d896212947797facd` |
| `MONOCYPHER-LICENCE.md` | `LICENCE.md` | `5f8360e4c06ddcc584bdb4b210c6af824c4bb301e6a9a521869b6d90795ca4b3` |
