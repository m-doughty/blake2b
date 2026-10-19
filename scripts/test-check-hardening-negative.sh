#!/usr/bin/env bash
# Negative controls for scripts/check-hardening.sh: each removes one piece
# of the hardening from a scratch copy of the crate, builds it in the
# release profile (check-hardening.sh builds it), and requires the gate
# to fail with the message that names the cause:
#
#   compress-out-of-line  Compress loses Inline_Always: blake2b-core.o
#                         defines it, and blake2b-hashing.o calls it
#   update-no-flatten     Update loses flatten (at -O3 its code does not
#                         change, so the source check is what catches it)
#   final-no-strub        Final loses strub: no clone of Final
#   init-no-zero-regs     Init loses zero_call_used_regs: registers not
#                         cleared on return from Init
#   update-flatten-capitalised
#                         Update's "flatten" becomes "Flatten", which GCC
#                         ignores with a warning: the source check
#                         compares the attribute names exactly
#   final-strub-upper-case
#                         Final's "strub" becomes "STRUB", likewise
#   counter-no-inline-always
#                         Add_Counter loses Inline_Always: the counter's
#                         object defines it
#   counter-no-inline     Add_Counter is No_Inline: defined out of line and
#                         called from blake2b-hashing.o
#   initial-h-out-of-line Initial_H loses Inline_Always: blake2b-core.o
#                         defines it, and blake2b-hashing.o calls it
#   libc-flags-default    blake2b.gpr's -fno-tree-loop-distribute-patterns
#                         and -finline-stringops for blake2b-hashing.adb
#                         become GCC's defaults (-ftree-loop-distribute-
#                         patterns, -fno-inline-stringops), as if removed:
#                         GCC turns the copy and zeroing loops back into
#                         calls to memcpy, memmove or memset. If the
#                         mutated blake2b-hashing.o references none of
#                         them (nm), the control is ineffective on this
#                         target: that fails the run too, with a message
#                         of its own, not as a call the gate missed
#
# Then the unmutated copy must pass. A mutation that does not apply (its
# source text was not found) fails the run, as does one the gate does not
# catch, or a gate that stops on an error (exit 2) instead of a failed
# check.
#
# The scratch copy (the sources, the project files and the gate) lives
# in obj/hardening-negative.XXXXXX and is removed on exit; nothing outside
# it is written.
#
# Usage: scripts/test-check-hardening-negative.sh
#        ALR=/path/to/alr NM=/path/to/nm OBJDUMP=/path/to/objdump \
#          scripts/test-check-hardening-negative.sh
# (The variables are passed on to check-hardening.sh.)

set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p obj
scratch=$(mktemp -d "$PWD/obj/hardening-negative.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
crate=$scratch/crate
mkdir "$crate" "$crate/scripts" "$scratch/pristine"
cp -R src alire.toml blake2b.gpr "$crate/"
cp scripts/check-hardening.sh scripts/zeroed-at-return.awk "$crate/scripts/"
cp src/blake2b-core.ads src/blake2b-hashing.ads \
   src/blake2b-hashing-counter_arithmetic.ads blake2b.gpr "$scratch/pristine/"

# Rewrites one file of the scratch copy ($1, relative to the crate: a
# source or the project file) with the Perl expression $2 (run over the
# whole file); fails if the file does not change.
mutate () {
  local file=$crate/$1
  perl -0 -pe "$2" "$file" > "$scratch/mutated"
  if cmp -s "$file" "$scratch/mutated"; then
    echo "FAILED: mutation did not apply to $1 (source changed?)"
    exit 1
  fi
  cp "$scratch/mutated" "$file"
}

# Restores the mutated files.
restore () {
  cp "$scratch/pristine/blake2b-core.ads" "$scratch/pristine/blake2b-hashing.ads" \
     "$scratch/pristine/blake2b-hashing-counter_arithmetic.ads" "$crate/src/"
  cp "$scratch/pristine/blake2b.gpr" "$crate/"
}

# Runs the scratch copy's gate into log $1, from a clean build: a source
# restored within the second it was mutated keeps its time stamp, and an
# incremental build would not see the change. Prints the exit status.
run_gate () {
  local status=0
  rm -rf "$crate/obj" "$crate/lib"
  bash "$crate/scripts/check-hardening.sh" > "$1" 2>&1 || status=$?
  echo "$status"
}

pass=0
bad=0
# Runs the scratch copy's gate for mutation $1; requires it to fail its
# checks (exit 1) with, for each further argument, a line matching that
# extended regular expression.
expect_caught () {
  local name=$1
  shift
  judge "$name" "$(run_gate "$scratch/$name.log")" "$@"
}

# Judges the gate's run for mutation $1, which ended with exit status $2
# and wrote its log to $scratch/$1.log, as expect_caught describes; then
# restores the mutated files.
judge () {
  local name=$1 status=$2 message missed=""
  shift 2
  for message in "$@"; do
    if ! grep -qE -- "$message" "$scratch/$name.log"; then
      missed="$missed [$message]"
    fi
  done
  if [ "$status" -eq 1 ] && [ -z "$missed" ]; then
    echo "caught: $name"
    for message in "$@"; do
      grep -E -- "$message" "$scratch/$name.log" | head -n 1 | sed 's/^/  /'
    done
    pass=$((pass + 1))
  else
    echo "NOT CAUGHT: $name (gate exit status $status, expected 1;" \
         "no line matching:${missed:- (all matched)}). Its output:"
    sed 's/^/  /' "$scratch/$name.log"
    bad=$((bad + 1))
  fi
  restore
}

mutate src/blake2b-core.ads \
  's/(procedure Compress\s*\(.*?\bwith\s+)Inline_Always\s*,\s*/$1/s'
expect_caught compress-out-of-line \
  '^NOT inlined: blake2b-core\.o defines blake2b__core__compress ' \
  '^NOT inlined: blake2b-hashing\.o calls _?blake2b__core__compress '

mutate src/blake2b-hashing.ads \
  's/^[ \t]*pragma Machine_Attribute \(Update, "flatten"\);[ \t]*\r?\n//m'
expect_caught update-no-flatten \
  '^MISSING in the source: pragma Machine_Attribute \(update, "flatten"\);$'

# strub and zero_call_used_regs are caught in the object; the source
# check names them too.
mutate src/blake2b-hashing.ads \
  's/^[ \t]*pragma Machine_Attribute \(Final, "strub", "internal"\);[ \t]*\r?\n//m'
expect_caught final-no-strub '^MISSING strub clone: final$' \
  '^MISSING in the source: pragma Machine_Attribute \(final, "strub", "internal"\);$'

mutate src/blake2b-hashing.ads \
  's/^[ \t]*pragma Machine_Attribute \(Init, "zero_call_used_regs", "all"\);[ \t]*\r?\n//m'
expect_caught init-no-zero-regs '^NOT cleared on return from init: ' \
  '^MISSING in the source: pragma Machine_Attribute \(init, "zero_call_used_regs", "all"\);$'

# The attribute names are case-sensitive: GCC ignores a misspelt one with
# only a warning, and the source check compares them exactly.
mutate src/blake2b-hashing.ads \
  's/(pragma Machine_Attribute \(Update, )"flatten"\);/$1"Flatten");/'
expect_caught update-flatten-capitalised \
  '^MISSING in the source: pragma Machine_Attribute \(update, "flatten"\);$'

mutate src/blake2b-hashing.ads \
  's/(pragma Machine_Attribute \(Final, )"strub"/$1"STRUB"/'
expect_caught final-strub-upper-case \
  '^MISSING in the source: pragma Machine_Attribute \(final, "strub", "internal"\);$'

mutate src/blake2b-hashing-counter_arithmetic.ads \
  's/(procedure Add_Counter\s*\(.*?\bwith\s+)Inline_Always\s*,\s*/$1/s'
expect_caught counter-no-inline-always \
  '^NOT inlined: blake2b-hashing-counter_arithmetic\.o defines '

mutate src/blake2b-hashing-counter_arithmetic.ads \
  's/(procedure Add_Counter\s*\(.*?\bwith\s+)Inline_Always\b/$1No_Inline/s'
expect_caught counter-no-inline \
  '^NOT inlined: blake2b-hashing-counter_arithmetic\.o defines ' \
  '^NOT allowed: blake2b-hashing\.o references .*add_counter'

# Initial_H's Inline_Always, wherever it stands among the aspects (or
# alone, with its "with").
mutate src/blake2b-core.ads \
  's{(function\s+Initial_H\s*\([^)]*\)\s*return\s+[\w.]+)(\s+with\s+)([^;]*)(;)}{my ($d, $w, $a, $e) = ($1, $2, $3, $4); if ($a =~ /^\s*Inline_Always\s*$/) { "$d$e" } else { $a =~ s/\bInline_Always\s*,\s*// or $a =~ s/\s*,\s*Inline_Always\b//; "$d$w$a$e" }}se'
expect_caught initial-h-out-of-line \
  '^NOT inlined: blake2b-core\.o defines blake2b__core__initial_h ' \
  '^NOT inlined: blake2b-hashing\.o calls Blake2b\.Core\.Initial_H out of line '

# Each flag back to GCC's default, wherever blake2b.gpr sets it; mutate
# requires each to be found. The control is required, but it shows the
# gate at work only if the mutated object does call the C library: a
# target where GCC keeps the loops as loops even without the two flags
# fails here with its own message, not as a gate that missed a call. The
# object is read with nm (undefined references, strong or weak, in any
# spelling the gate knows) after the gate has built it.
mutate blake2b.gpr \
  's/"-fno-tree-loop-distribute-patterns"/"-ftree-loop-distribute-patterns"/g'
mutate blake2b.gpr 's/"-finline-stringops"/"-fno-inline-stringops"/g'
status=$(run_gate "$scratch/libc-flags-default.log")
mutated_o=$crate/obj/release-profile-profile/blake2b-hashing.o
if [ -f "$mutated_o" ] && libc_syms=$("${NM:-nm}" "$mutated_o" 2>&1); then
  libc_refs=$(awk '
    { sub(/\r$/, "") }
    (NF >= 2 && $(NF - 1) == "U") || (NF == 2 && $1 ~ /^[wv]$/) {
      s = tolower($NF)
      if (s ~ /^(_*imp_)?_*(memcpy|memmove|memset)(_chk)?(@.*)?$/) printf " %s", $NF
    }' <<< "$libc_syms")
  if [ -z "$libc_refs" ]; then
    echo "FAILED: libc-flags-default: the control is ineffective on this" \
         "target: without the two flags blake2b-hashing.o still references" \
         "no C library routine (memcpy, memmove or memset, in any" \
         "spelling), so it cannot show that the gate catches one"
    bad=$((bad + 1))
    restore
  else
    echo "libc-flags-default: blake2b-hashing.o references the C library" \
         "without the two flags:$libc_refs"
    judge libc-flags-default "$status" \
      '^NOT allowed: blake2b-hashing\.o calls the C library \(outside the scrubbed frame\): mem(cpy|move|set)'
  fi
else
  # No object to read (the build failed): the judgement reports the
  # gate's exit status and its log.
  judge libc-flags-default "$status" \
    '^NOT allowed: blake2b-hashing\.o calls the C library \(outside the scrubbed frame\): mem(cpy|move|set)'
fi

status=$(run_gate "$scratch/pristine.log")
if [ "$status" -eq 0 ] && grep -q '^hardening: present$' "$scratch/pristine.log"; then
  echo "unmutated copy passes"
  pass=$((pass + 1))
else
  echo "FAILED: the unmutated copy does not pass (exit status $status):"
  sed 's/^/  /' "$scratch/pristine.log"
  bad=$((bad + 1))
fi

echo "hardening negative controls: $pass passed, $bad failed"
[ "$bad" -eq 0 ]
