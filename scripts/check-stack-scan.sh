#!/usr/bin/env bash
# What the hardened subprograms of Blake2b.Hashing leave on the stack after
# they return, and after an exception escapes them. The hardened bodies
# (Digest_Of, behind both Hash procedures, and Init, Update and Final)
# carry GCC's strub ("internal": the stack the body used is zeroed on
# return), zero_call_used_regs ("all") and flatten, and the compression
# function is Inline_Always, so its message words and working vector live
# in the scrubbed body. A normal return is gated: ANY canary a hardened
# build leaves fails. What GCC does on an exceptional exit is not
# documented as a guarantee and the crate claims nothing for it, so the
# exception results are measured and reported, never gated.
#
# What is measured. The script copies the crate's sources (src/, the
# Alire manifest and blake2b.gpr) and the driver (scripts/stack-scan/,
# whose manifest pins the crate two directories up) into scratch trees
# under obj/stack-scan/ (git ignores obj/), with the repository's layout,
# and builds each through Alire in the release profile (alr build
# --release), as the crate's other scripts do. Nothing in src/ is touched.
# The builds:
#   shipped   the sources unmodified;
#   spill     at the start of each hardened body, a copy of the secrets it
#             receives into a local array of volatile components declared
#             with the body's own locals (so the compiler must store it in
#             the body's frame, cannot discard it, and keeps the slot for
#             the whole body): Digest_Of the key and the first 128 bytes of
#             the message, Init the key, Update and Final the state's
#             buffer and chaining value (and Update the first 128 bytes of
#             its data). In the control build only, the same copy in Clear
#             (see below). No raise;
#   injected  two statements, each `if <trigger> then raise Program_Error;
#             end if;` at an anchor that must match exactly once (or the
#             script stops): in Blake2b.Core.Compress after round 6 of 12,
#             firing on the final block when the byte counter is 2,048
#             (so inside Final or Digest_Of, into which Compress is
#             inlined), and in Update after the compression of the
#             topped-up buffer, firing when the counter reaches 2,048. The
#             triggers are data, so one build serves a run that raises and
#             a run that returns normally.
# Each build has a hardened variant (as written) and a control: the same
# copy with the strub and zero_call_used_regs pragmas removed (flatten and
# Inline_Always kept, so the code is laid out as the hardened build's).
# The shipped sources have a second control that also removes flatten; it
# is reported, not judged.
#
# The driver (scripts/stack-scan/src/stack_scan.adb) keeps every input,
# output and state on the heap, so no frame of its own holds a canary.
# The canaries are 64-bit SplitMix64 values: the key's words (K), the
# message's words as BLAKE2b loads them, little-endian (M), and the
# chaining value after every compression (H, from an independent
# transcription of RFC 7693 whose final value the driver checks against
# the library's digest). From one helper frame the driver makes the calls
# that set up the state, zeroes the region of stack below that frame,
# makes the measured call, then copies the same region with volatile reads
# and counts every occurrence of every canary, at 8-byte-aligned offsets
# and at the others (byte-wise); the digest itself is in the caller's
# heap buffer, so only what lies below the caller's frame is counted. The
# call is made below an unused spacer of SPACER_KIB (8) KiB, so that the
# run-time's handler for an injected exception runs inside the spacer and
# does not overwrite what the call and the propagation left. The region is
# the spacer plus PROBE_KIB KiB (default 16); the deepest byte written
# must lie inside it with 256 bytes to spare, or the runs are repeated
# with the region doubled, up to 256 KiB. Each scenario runs as REPEATS
# (default 5) separate processes; a "hits" figure is the most of any
# repeat. Every run starts with a baseline (no call; it must find
# nothing). After Final and Clear the driver also counts canaries in the
# state object itself, which those calls must have wiped.
#
# On Linux x86-64 (SysV), a leaf function may use the 128-byte red zone
# below its stack pointer without moving it. The scanned region is the
# local array of the probe procedure, which starts just below the helper
# frame and extends PROBE_KIB + SPACER_KIB KiB down, far below any
# measured frame, so a leaf's red zone lies inside the region (the 256
# bytes of spare required below the deepest byte written cover it). Only
# the probe's own return address and saved registers, at the top of the
# region in the driver's own frames above the spacer, are not scanned.
#
# The scenarios (step-key-length; k: a 64-byte key, u: none):
#   hash1   Hash (Message, Key, Digest): u-1000 k-1000 k-0 k-128 u-128 u-129
#   hash2   Hash (Prefix, Message, Key, Digest), an 8-byte prefix:
#           u-1000 k-1000 k-136
#   init    Init (S, 64, Key): k-0
#   update  Update after Init: k-0 k-128 k-129 k-1000 u-128 u-129 u-1000
#   final   Final after Init and Update: the same lengths (128: the last
#           block is a full block of message; 129: one byte of it)
#   clear   Clear on a state abandoned before Final: k-129 u-1000
# and, in the injected builds: hash1-u, hash1-k, hash2-k (the exception in
# Compress, in Digest_Of), final-u, final-k (in Compress, in Final),
# update-u, update-k (in Update after a compression); each also with a
# normal run on 1,000 bytes.
#
# Verdicts, per scenario:
#   normal return (gated)  the hardened shipped build and the hardened
#                          spill build must leave no canary, and Final and
#                          Clear none in the state (exit 3 otherwise).
#                          Each needs a control that can see a leak: the
#                          shipped control's hits where it leaves some
#                          (the real inlined layout), and in every
#                          scenario the spill control, which must show at
#                          least SPILL_MIN (4) distinct canary words. A
#                          spill control below that is BLIND (exit 1).
#                          Init, Clear and Update calls that compress
#                          nothing leave nothing even in the shipped
#                          control (they copy bytes, or read nothing), so
#                          the spill is their evidence. Clear is not
#                          hardened (it reads no secret, it only writes
#                          zeros): its spill is in the control build only,
#                          to show that the scan sees Clear's frame;
#   normal, injected       the normal run of the injected builds: gated
#                          as the shipped build (the hardened build must
#                          leave nothing), the control reported;
#   exception              reported only. If the control leaves no canary
#                          after the exception, that scenario's exception
#                          result is UNMEASURED (a notice; the exit status
#                          is unchanged).
#
# Output: per scenario, each build's counts (per class: aligned/unaligned/
# distinct words, then class@depth#word for the first hits; depths are in
# bytes below the helper frame), then one "summary:" line with the verdict.
#
# Exit status:
#   0  every gated result passed, and every control saw canaries;
#   1  a harness error (a build, an anchor, a run, a digest that disagrees
#      with the reference), or a spill control that is blind;
#   3  a hardened build left a canary after a normal return (or in the
#      state after Final or Clear).
#
# Mutations (MUTATE, applied to every hardened tree; for
# scripts/test-check-stack-scan.sh, which shows that the gate fails):
#   none               the sources as they are (default);
#   nostrub-update     Update's strub pragma removed;
#   noflatten-update   Update's flatten pragma removed;
#   noinline-compress  Compress's Inline_Always and every flatten pragma
#                      removed (the compression function back in a frame
#                      of its own, outside every scrubbed body).
#
# Usage: bash scripts/check-stack-scan.sh
#        ALR=/path/to/alr PROBE_KIB=16 REPEATS=5 SPILL_MIN=4 EXCEPTIONS=1 \
#          MUTATE=none bash scripts/check-stack-scan.sh
# (EXCEPTIONS=0 skips the injected builds.) It runs alr itself, not inside
# `alr exec`.

set -euo pipefail

ALR=${ALR:-alr}
PROBE_KIB=${PROBE_KIB:-16}
SPACER_KIB=8
REPEATS=${REPEATS:-5}
SPILL_MIN=${SPILL_MIN:-4}
EXCEPTIONS=${EXCEPTIONS:-1}
MUTATE=${MUTATE:-none}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
WORK="$ROOT/obj/stack-scan"
DRIVER="$ROOT/scripts/stack-scan"

say () { echo "check-stack-scan: $*"; }
# To standard error: it may run inside a command substitution.
harness_error () {
  say "HARNESS ERROR: $*" >&2
  exit 1
}

case $PROBE_KIB in
  ''|*[!0-9]*|0) harness_error "PROBE_KIB must be a positive number of KiB" ;;
esac
case $REPEATS in
  ''|*[!0-9]*|0) harness_error "REPEATS must be a positive number" ;;
esac
case $SPILL_MIN in
  ''|*[!0-9]*|0) harness_error "SPILL_MIN must be a positive number" ;;
esac
case $EXCEPTIONS in
  0|1) ;;
  *) harness_error "EXCEPTIONS must be 0 or 1" ;;
esac
case $MUTATE in
  none|nostrub-update|noflatten-update|noinline-compress) ;;
  *) harness_error "unknown MUTATE $MUTATE (none, nostrub-update," \
       "noflatten-update or noinline-compress)" ;;
esac
[ "$#" -eq 0 ] || harness_error "no arguments (see the header for the knobs)"

NORMAL_SCENARIOS="hash1-u-1000 hash1-k-1000 hash1-k-0 hash1-k-128
  hash1-u-128 hash1-u-129 hash2-u-1000 hash2-k-1000 hash2-k-136 init-k-0
  update-k-0 update-k-128 update-k-129 update-k-1000 update-u-128
  update-u-129 update-u-1000 final-k-0 final-k-128 final-k-129
  final-k-1000 final-u-128 final-u-129 final-u-1000 clear-k-129
  clear-u-1000"
RAISE_SCENARIOS="hash1-u-1000 hash1-k-1000 hash2-k-1000 final-u-1000
  final-k-1000 update-u-1000 update-k-1000"

# The anchors, and what replaces each. In each, \n stands for a line
# break; the sources are copied with LF line endings.
HASHING=src/blake2b-hashing.adb
CORE_BODY=src/blake2b-core.adb
CORE_SPEC=src/blake2b-core.ads
HASHING_SPEC=src/blake2b-hashing.ads
SPILL_BYTES='      type Spill_Bytes is array (I64 range 0 .. 255) of Byte\n      with Volatile_Components;\n      Spill : Spill_Bytes;\n'
SPILL_WORDS='      type Spill_Words is array (Chain_Index) of U64\n      with Volatile_Components;\n      Spill_H : Spill_Words;\n'
COPY_STATE='      for J in Block_Index loop\n         Spill (J) := S.Buf (J);\n      end loop;\n      for J in Chain_Index loop\n         Spill_H (J) := S.H (J);\n      end loop;\n'
COPY_KEY='      for J in I64 range 0 .. Key'"'"'Length - 1 loop\n         Spill (J) := Key (Key'"'"'First + J);\n      end loop;\n'
# Spill: Digest_Of.
ANCHOR_SD="      H   : Words8 := Core.Initial_H (Key'Length, NN);\n      Buf : Block;\n   begin\n"
INSERT_SD="      H   : Words8 := Core.Initial_H (Key'Length, NN);\n      Buf : Block;\n$SPILL_BYTES   begin\n$COPY_KEY      for J in 0 .. I64'Min (Message'Length, 128) - 1 loop\n         Spill (128 + J) := Message (Message'First + J);\n      end loop;\n"
# Spill: Init.
ANCHOR_SI="      Key    : Byte_Array) is\n   begin\n      S.H := Core.Initial_H (Key'Length, Length);\n"
INSERT_SI="      Key    : Byte_Array) is\n$SPILL_BYTES   begin\n$COPY_KEY      S.H := Core.Initial_H (Key'Length, Length);\n"
# Spill: Update.
ANCHOR_SU="      Left         : I64 := Data'Length;\n   begin\n"
INSERT_SU="      Left         : I64 := Data'Length;\n$SPILL_BYTES$SPILL_WORDS   begin\n$COPY_STATE      for J in 0 .. I64'Min (Data'Length, 128) - 1 loop\n         Spill (128 + J) := Data (Data'First + J);\n      end loop;\n"
# Spill: Final.
ANCHOR_SF="      C0 : constant Inc.Context := Model (S) with Ghost => Static;\n   begin\n"
INSERT_SF="      C0 : constant Inc.Context := Model (S) with Ghost => Static;\n$SPILL_BYTES$SPILL_WORDS   begin\n$COPY_STATE"
# Spill: Clear (control builds only).
ANCHOR_SC="   procedure Clear (S : in out State) is\n   begin\n"
INSERT_SC="   procedure Clear (S : in out State) is\n$SPILL_BYTES$SPILL_WORDS   begin\n$COPY_STATE"
# Injected: in Compress after round 6, on the final block at counter 2048.
ANCHOR_RC='      Round (V, M, 5);\n      Lemma_Same (V, Spec.Rounds (Init, M, 6));\n'
INSERT_RC='      Round (V, M, 5);\n      Lemma_Same (V, Spec.Rounds (Init, M, 6));\n      if Last and then T_Lo = 2048 then\n         raise Program_Error;\n      end if;\n'
# Injected: in Update after the topped-up buffer's compression.
ANCHOR_RU='         Core.Compress (S.H, S.Buf, S.T_Lo, S.T_Hi, Last => False);\n         Blocks := 1;\n'
INSERT_RU='         Core.Compress (S.H, S.Buf, S.T_Lo, S.T_Hi, Last => False);\n         Blocks := 1;\n         if S.T_Lo = 2048 then\n            raise Program_Error;\n         end if;\n'
# Mutations.
ANCHOR_MS='   pragma Machine_Attribute (Update, "strub", "internal");\n'
ANCHOR_MF='   pragma Machine_Attribute (Update, "flatten");\n'
ANCHOR_MI='   with Inline_Always,\n        Global => null,\n        Post   => H = Spec.Compress'
INSERT_MI='   with Global => null,\n        Post   => H = Spec.Compress'

# Replaces the one occurrence of $2 in file $1 with $3, literally (awk's
# index, no pattern; the file is read as one record, as it holds no \001);
# stops the script if $2 does not occur exactly once. (Bash's own string
# operations would do it, but bash 3.2 takes minutes over a source file.)
patch_once () {
  local file=$1 count
  count=$(SEARCH=$2 REPLACE=$3 OUT="$file.patched" awk '
    BEGIN { RS = "\001"; s = ENVIRON["SEARCH"]; r = ENVIRON["REPLACE"] }
    { text = text $0; records++ }
    END {
      if (records > 1 || s == "") { print -1; exit }
      rest = text; out = ""; n = 0
      while ((i = index(rest, s)) > 0) {
        n++
        out = out substr(rest, 1, i - 1) r
        rest = substr(rest, i + length(s))
      }
      printf "%s%s", out, rest > ENVIRON["OUT"]
      print n
    }' "$file") || harness_error "could not read ${file#"$WORK"/}"
  if [ "$count" -ne 1 ]; then
    rm -f "$file.patched"
    harness_error "anchor found $count times (want exactly 1) in" \
      "${file#"$WORK"/}: $2"
  fi
  mv "$file.patched" "$file"
}

# patch_once with \n escapes expanded in the anchor and the replacement.
patch () {
  patch_once "$1" "$(printf '%b' "$2")" "$(printf '%b' "$3")"
}

# Copies the Ada sources of directory $1 to $2 with LF line endings (a
# Windows checkout may have CRLF; the compiler reads both alike).
copy_sources () {
  local from=$1 to=$2 file
  mkdir -p "$to"
  for file in "$from"/*.ads "$from"/*.adb; do
    [ -f "$file" ] || continue
    tr -d '\r' < "$file" > "$to/${file##*/}"
  done
}

# Removes, from the sources in directory $1, every Machine_Attribute
# pragma naming one of the attributes in the regular expression $2, and
# checks that some were removed and none is left. Prints the number.
strip_attributes () {
  local dir=$1 names=$2 file before after removed=0
  for file in "$dir"/*.ads "$dir"/*.adb; do
    before=$(grep -cE "^ *pragma Machine_Attribute \\(.*\"($names)\"" "$file" || true)
    [ "$before" -gt 0 ] || continue
    grep -vE "^ *pragma Machine_Attribute \\(.*\"($names)\"" "$file" \
      > "$file.tmp"
    mv "$file.tmp" "$file"
    # Any mention left outside a comment (a pragma split across lines).
    after=$(grep -E "\"($names)\"" "$file" | grep -cvE '^ *--' || true)
    [ "$after" -eq 0 ] \
      || harness_error "could not remove every $names pragma from ${file#"$WORK"/}"
    removed=$((removed + before))
  done
  [ "$removed" -gt 0 ] \
    || harness_error "no $names pragma found in ${dir#"$WORK"/}"
  echo "$removed"
}

compiler=$("$ALR" -n exec -- gcc --version | head -n 1 | tr -d '\r')
platform="$(uname -s) $(uname -m)"
say "platform: $platform; compiler: $compiler"
say "measured: normal returns of the shipped sources and of a copy with a" \
    "spill of the secrets in each hardened body, and copies with injected" \
    "raises; see the script's header. Stack region scanned:" \
    "$((PROBE_KIB + SPACER_KIB)) KiB below the helper frame ($SPACER_KIB" \
    "KiB of spacer, then $PROBE_KIB KiB below the measured call; doubled" \
    "when the call needs more); depths are counted from the helper frame"
say "hits are given per class as aligned/unaligned/distinct words, then" \
    "class@depth#word for the first ones"
if [ "$MUTATE" != none ]; then
  say "MUTATE=$MUTATE: every hardened build is mutated (see the header)"
fi

# The sources as shipped, then one tree per build.
rm -rf "$WORK"
SOURCES="$WORK/sources"
mkdir -p "$SOURCES/scripts/stack-scan"
copy_sources "$ROOT/src" "$SOURCES/src"
tr -d '\r' < "$ROOT/alire.toml" > "$SOURCES/alire.toml"
tr -d '\r' < "$ROOT/blake2b.gpr" > "$SOURCES/blake2b.gpr"
copy_sources "$DRIVER/src" "$SOURCES/scripts/stack-scan/src"
tr -d '\r' < "$DRIVER/alire.toml" > "$SOURCES/scripts/stack-scan/alire.toml"
tr -d '\r' < "$DRIVER/stack_scan.gpr" \
  > "$SOURCES/scripts/stack-scan/stack_scan.gpr"

# Creates tree $1 (a name) from the sources: variant $2 (hardened,
# control or control-noflatten), build kind $3 (shipped, spill or
# injected).
prepare () {
  local name=$1 variant=$2 kind=$3 tree="$WORK/$1" names n
  mkdir -p "$tree"
  cp -R "$SOURCES/." "$tree/"
  case $variant in
    hardened) ;;
    control|control-noflatten)
      names='strub|zero_call_used_regs'
      [ "$variant" = control ] || names="$names|flatten"
      n=$(strip_attributes "$tree/src" "$names")
      say "$name: $n Machine_Attribute pragmas ($names) removed"
      ;;
    *) harness_error "unknown variant $variant" ;;
  esac
  case $kind in
    shipped) ;;
    spill)
      patch "$tree/$HASHING" "$ANCHOR_SD" "$INSERT_SD"
      patch "$tree/$HASHING" "$ANCHOR_SI" "$INSERT_SI"
      patch "$tree/$HASHING" "$ANCHOR_SU" "$INSERT_SU"
      patch "$tree/$HASHING" "$ANCHOR_SF" "$INSERT_SF"
      if [ "$variant" != hardened ]; then
        patch "$tree/$HASHING" "$ANCHOR_SC" "$INSERT_SC"
      fi
      ;;
    injected)
      patch "$tree/$CORE_BODY" "$ANCHOR_RC" "$INSERT_RC"
      patch "$tree/$HASHING" "$ANCHOR_RU" "$INSERT_RU"
      ;;
    *) harness_error "unknown build kind $kind" ;;
  esac
  if [ "$variant" = hardened ]; then
    case $MUTATE in
      none) ;;
      nostrub-update) patch "$tree/$HASHING_SPEC" "$ANCHOR_MS" '' ;;
      noflatten-update) patch "$tree/$HASHING_SPEC" "$ANCHOR_MF" '' ;;
      noinline-compress)
        patch "$tree/$CORE_SPEC" "$ANCHOR_MI" "$INSERT_MI"
        n=$(strip_attributes "$tree/src" flatten)
        [ "$n" -eq 4 ] \
          || harness_error "$name: $n flatten pragmas removed (want 4)"
        ;;
    esac
  fi
  (cd "$tree/scripts/stack-scan" && "$ALR" -n build --release) \
    > "$WORK/$name.build.log" 2>&1 || {
      tail -n 40 "$WORK/$name.build.log"
      harness_error "build failed (${WORK#"$ROOT"/}/$name.build.log)"
    }
}

# Summarises run $2 of results file $1 (every repeat): prints
# "<least> <most> <totals per repeat> <distinct>|<detail>", where the
# total is every hit of every class, the distinct figure the number of
# distinct canary words found (all classes), and the detail, for the
# repeat with the most hits, each class's hits at aligned and at other
# offsets and its distinct words, and where the first hits lie.
summarise () {
  awk -v run="$2" '
    $1 == "hits" {
      delete f
      for (i = 2; i <= NF; i++) { split($i, kv, "="); f[kv[1]] = kv[2] }
      if (f["run"] != run) next
      r = f["repeat"] + 0
      if (r > last) last = r
      n = f["aligned"] + f["unaligned"]
      total[r] += n
      distinct[r] += f["distinct"]
      text[r] = text[r] sprintf(" %s=%d/%d/%d", f["class"], f["aligned"],
                                f["unaligned"], f["distinct"])
      if (n > 0) depths[r] = depths[r] sprintf(" %s@%s", f["class"], f["depths"])
    }
    END {
      lo = -1; hi = -1; best = 1; list = ""
      for (r = 1; r <= last; r++) {
        if (lo < 0 || total[r] < lo) lo = total[r]
        if (total[r] > hi || (total[r] == hi && distinct[r] > distinct[best])) {
          hi = total[r]; best = r
        }
        list = list (r > 1 ? "," : "") total[r] + 0
      }
      printf "%d %d %s %d|%s%s\n", lo, hi, list, distinct[best] + 0,
             substr(text[best], 2),
             (depths[best] == "" ? "" : ";" depths[best])
    }' "$1"
}

# The most stack any repeat of run $2 in file $1 wrote (the touched=
# field: bytes of the region from its top down to the deepest nonzero
# byte).
touched () {
  awk -v run="$2" '
    $1 == "hits" {
      delete f
      for (i = 2; i <= NF; i++) { split($i, kv, "="); f[kv[1]] = kv[2] }
      if (f["run"] == run && f["touched"] + 0 > m) m = f["touched"] + 0
    }
    END { print m + 0 }' "$1"
}

# The canaries found in the state object after run $2 of file $1, in all
# repeats ("state" lines).
state_hits () {
  awk -v run="$2" '
    $1 == "state" {
      delete f
      for (i = 2; i <= NF; i++) { split($i, kv, "="); f[kv[1]] = kv[2] }
      if (f["run"] == run) n += f["aligned"] + f["unaligned"]
    }
    END { print n + 0 }' "$1"
}

# Checks the bookkeeping of results file $1 (label $2), from a run in
# mode $3 (raise or normal): the baseline finds nothing, the raise run
# raised (and exists only in mode raise), the normal run did not raise,
# and every call wrote some stack.
check_runs () {
  local file=$1 label=$2 mode=$3
  awk -v label="$label" -v mode="$mode" '
    $1 == "hits" {
      delete f
      for (i = 2; i <= NF; i++) { split($i, kv, "="); f[kv[1]] = kv[2] }
      seen[f["run"]] = 1
      if (f["run"] == "baseline" && f["aligned"] + f["unaligned"] > 0) {
        print label ": the baseline (no call) found canaries"; bad = 1 }
      if (f["run"] == "raise" && f["raised"] != "yes") {
        print label ": the injected exception was not raised"; bad = 1 }
      if (f["run"] == "normal" && f["raised"] != "no") {
        print label ": the normal run raised"; bad = 1 }
      if (f["run"] != "baseline" && f["touched"] + 0 == 0) {
        print label ": the call wrote nothing in the region"; bad = 1 }
    }
    END {
      if (!seen["baseline"] || !seen["normal"] \
          || (mode == "raise") != ("raise" in seen)) {
        print label ": runs missing from the output, or unexpected"; bad = 1 }
      exit bad
    }' "$file" | sort -u
  return "${PIPESTATUS[0]}"
}

# Runs the driver of tree $1 on scenario $2 in mode $3 (normal or raise),
# REPEATS times, into file $4; each "hits" and "state" line is tagged
# repeat=<n>. The region must hold all the stack the call wrote, with 256
# bytes to spare; if it does not, every repeat is run again with the
# region doubled, up to 256 KiB. Then checks the bookkeeping.
probe () {
  local tree=$1 scenario=$2 mode=$3 out=$4 kib=$((PROBE_KIB + SPACER_KIB))
  local program="$WORK/$1/scripts/stack-scan/bin/stack_scan" step key length
  local deepest repeat
  IFS=- read -r step key length <<< "$scenario"
  while :; do
    : > "$out"
    for repeat in $(seq 1 "$REPEATS"); do
      "$program" "$kib" "$SPACER_KIB" "$step" "$key" "$length" "$mode" \
        > "$out.one" 2>&1 \
        || { tr -d '\r' < "$out.one"
             harness_error "the driver failed ($tree $scenario $mode)"; }
      tr -d '\r' < "$out.one" \
        | sed -e "s/^hits /hits repeat=$repeat /" \
              -e "s/^state /state repeat=$repeat /" >> "$out"
    done
    rm -f "$out.one"
    deepest=$(touched "$out" normal)
    if [ "$mode" = raise ]; then
      deepest=$(( $(touched "$out" raise) > deepest \
                  ? $(touched "$out" raise) : deepest ))
    fi
    if [ $((deepest + 256)) -le $((kib * 1024)) ]; then
      break
    fi
    if [ "$kib" -ge 256 ]; then
      harness_error "the call wrote $deepest bytes of stack, more than a" \
        "$kib KiB region can scan ($tree $scenario $mode)"
    fi
    say "  ($tree $scenario wrote $deepest bytes of a $kib KiB region;" \
        "repeating with $((kib * 2)) KiB)"
    kib=$((kib * 2))
  done
  check_runs "$out" "$tree $scenario" "$mode" \
    || harness_error "bad run ($tree $scenario; see ${out#"$ROOT"/})"
}

# Prints one build's counts for run $4 of file $3 (label $2), and records
# the most hits of any repeat as result $1 (see most), and the distinct
# words of that repeat (see most_distinct).
show () {
  local key=$1 label=$2 file=$3 run=$4 result hits per_repeat distinct
  result=$(summarise "$file" "$run")
  read -r _ hits per_repeat distinct <<< "${result%%|*}"
  echo "  $label: hits per repeat $per_repeat (most: ${result#*|});" \
       "stack written up to $(touched "$file" "$run") bytes"
  printf -v "MOST_${key//[^A-Za-z0-9]/_}" '%s' "$hits"
  printf -v "MOSTD_${key//[^A-Za-z0-9]/_}" '%s' "$distinct"
}

# The result recorded as $1 by show (bash 3 has no associative arrays).
most () {
  local name="MOST_${1//[^A-Za-z0-9]/_}"
  [ -n "${!name:-}" ] || harness_error "no result recorded for $1"
  echo "${!name}"
}

most_distinct () {
  local name="MOSTD_${1//[^A-Za-z0-9]/_}"
  [ -n "${!name:-}" ] || harness_error "no distinct count recorded for $1"
  echo "${!name}"
}

scenario_name () {
  local step key length what keyed
  IFS=- read -r step key length <<< "$1"
  case $step in
    hash1) what="Hash (Message, Key, Digest)" ;;
    hash2) what="Hash (Prefix, Message, Key, Digest), 8-byte prefix" ;;
    init) what="Init" ;;
    update) what="Update after Init" ;;
    final) what="Final after Init and Update" ;;
    clear) what="Clear after Init and Update" ;;
  esac
  if [ "$key" = k ]; then keyed="64-byte key"; else keyed="no key"; fi
  echo "$1: $what, $keyed, $length-byte message"
}

# The verdicts, collected over the whole scan.
blind=""          # spill controls that saw too little (exit 1)
failed=""         # gated normal-return results that failed (exit 3)
unmeasured=""     # exception results whose control saw nothing (notice)
exception_hits="" # hardened hits after an exception (reported only)
real_layout=""    # scenarios whose shipped control saw canaries
spill_only=""     # scenarios whose evidence is the spill control alone

start=$(date +%s)
TREES="hardened-shipped:hardened:shipped control-shipped:control:shipped
  control-noflatten-shipped:control-noflatten:shipped
  hardened-spill:hardened:spill control-spill:control:spill"
if [ "$EXCEPTIONS" = 1 ]; then
  TREES="$TREES hardened-injected:hardened:injected
    control-injected:control:injected"
fi
for spec in $TREES; do
  IFS=: read -r name variant kind <<< "$spec"
  prepare "$name" "$variant" "$kind"
done
say "built: $(( $(date +%s) - start )) s"

for scenario in $NORMAL_SCENARIOS; do
  for tree in hardened-shipped control-shipped control-noflatten-shipped \
              hardened-spill control-spill; do
    probe "$tree" "$scenario" normal "$WORK/$tree-$scenario.out"
  done
  say "$(scenario_name "$scenario"):"
  for tree in control-shipped control-noflatten-shipped hardened-shipped \
              control-spill hardened-spill; do
    show "$tree/$scenario" "$tree" "$WORK/$tree-$scenario.out" normal
  done
  hs=$(most "hardened-shipped/$scenario")
  cs=$(most "control-shipped/$scenario")
  ns=$(most "control-noflatten-shipped/$scenario")
  h_spill=$(most "hardened-spill/$scenario")
  c_spill=$(most "control-spill/$scenario")
  c_spill_d=$(most_distinct "control-spill/$scenario")
  state=0
  case $scenario in
    final-*|clear-*)
      state=$(( $(state_hits "$WORK/hardened-shipped-$scenario.out" normal)
                + $(state_hits "$WORK/hardened-spill-$scenario.out" normal) ))
      ;;
  esac
  verdict=""
  if [ "$hs" -gt 0 ] || [ "$h_spill" -gt 0 ] || [ "$state" -gt 0 ]; then
    failed="$failed $scenario"
    verdict="FAIL: the hardened build left canaries after a normal return"
    [ "$state" -eq 0 ] || verdict="$verdict ($state in the state object)"
  fi
  if [ "$c_spill_d" -lt "$SPILL_MIN" ]; then
    blind="$blind $scenario"
    verdict="${verdict:+$verdict; }BLIND: the spill control showed $c_spill_d distinct canary words (want at least $SPILL_MIN), so the scan is not shown to see this call's frame"
  elif [ -z "$verdict" ]; then
    if [ "$cs" -gt 0 ]; then
      real_layout="$real_layout $scenario"
      verdict="pass: none left; the shipped control (the real inlined layout) left $cs, the spill control $c_spill_d distinct words"
    else
      spill_only="$spill_only $scenario"
      verdict="pass: none left; the shipped control left none (the call leaves nothing to find unscrubbed), the spill control $c_spill_d distinct words"
    fi
    case $scenario in
      clear-*) verdict="$verdict (Clear is not hardened: it reads no secret; its spill is in the control only)" ;;
    esac
  fi
  echo "  summary: $scenario normal: control $cs (no flatten $ns)," \
       "hardened $hs; spill: control $c_spill, hardened $h_spill: $verdict"
done

if [ "$EXCEPTIONS" = 1 ]; then
  for scenario in $RAISE_SCENARIOS; do
    for tree in hardened-injected control-injected; do
      probe "$tree" "$scenario" raise "$WORK/$tree-$scenario-raise.out"
    done
    IFS=- read -r step key _ <<< "$scenario"
    case $step in
      hash1|hash2) where="in Compress, inside Digest_Of" ;;
      final) where="in Compress, inside Final" ;;
      update) where="in Update, after a compression" ;;
    esac
    say "$step-$key with an injected raise $where (and a normal run on" \
        "1000 bytes):"
    for tree in control-injected hardened-injected; do
      out="$WORK/$tree-$scenario-raise.out"
      show "$tree/$scenario/raise" "$tree: exception" "$out" raise
      show "$tree/$scenario/normal" "$tree: normal" "$out" normal
    done
    c=$(most "control-injected/$scenario/raise")
    h=$(most "hardened-injected/$scenario/raise")
    if [ "$c" -eq 0 ]; then
      unmeasured="$unmeasured $step-$key"
      verdict="UNMEASURED: the control left no canary after the exception, so the hardened count is not a measurement (reported only)"
    else
      [ "$h" -eq 0 ] || exception_hits="$exception_hits $step-$key=$h"
      verdict="measured; reported only (nothing is claimed for an exception)"
    fi
    echo "  summary: $step-$key exception: control $c, hardened $h: $verdict"
    c=$(most "control-injected/$scenario/normal")
    h=$(most "hardened-injected/$scenario/normal")
    if [ "$h" -gt 0 ]; then
      failed="$failed $scenario/injected"
      verdict="FAIL: the hardened build left canaries after a normal return"
    else
      verdict="pass: none left (control $c)"
    fi
    echo "  summary: $scenario normal (injected build): control $c," \
         "hardened $h: $verdict"
  done
fi
say "time: $(( $(date +%s) - start )) s"

say "controls: the shipped control (the real inlined layout) saw canaries" \
    "in:${real_layout:- none}"
if [ -n "$spill_only" ]; then
  say "the spill control is the only evidence (the shipped control left" \
      "none) in:$spill_only"
fi
if [ -n "$exception_hits" ]; then
  say "after an exception (reported only), hardened hits in:$exception_hits"
fi
if [ -n "$unmeasured" ]; then
  say "NOTICE: exception results unmeasured on this platform (the control" \
      "left no canary after the exception) in:$unmeasured"
fi
if [ -n "$blind" ]; then
  say "BLIND: a spill control saw fewer than $SPILL_MIN distinct canary" \
      "words in:$blind; the normal-return results there are not a" \
      "measurement${failed:+ (failed besides:$failed)}"
  exit 1
fi
if [ -n "$failed" ]; then
  say "FAILED: a hardened build left canaries after a normal return in:$failed"
  exit 3
fi
say "passed: no hardened build left a canary after a normal return"
exit 0
