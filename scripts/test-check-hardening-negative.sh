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
   src/blake2b-hashing-counter_arithmetic.ads "$scratch/pristine/"

# Rewrites one source file of the scratch copy with the Perl expression
# $2 (run over the whole file); fails if the file does not change.
mutate () {
  local file=$crate/src/$1
  perl -0 -pe "$2" "$file" > "$scratch/mutated"
  if cmp -s "$file" "$scratch/mutated"; then
    echo "FAILED: mutation did not apply to src/$1 (source changed?)"
    exit 1
  fi
  cp "$scratch/mutated" "$file"
}

# Restores the mutated sources.
restore () {
  cp "$scratch/pristine/blake2b-core.ads" "$scratch/pristine/blake2b-hashing.ads" \
     "$scratch/pristine/blake2b-hashing-counter_arithmetic.ads" "$crate/src/"
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
  local name=$1 status message missed=""
  shift
  status=$(run_gate "$scratch/$name.log")
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

mutate blake2b-core.ads \
  's/(procedure Compress\s*\(.*?\bwith\s+)Inline_Always\s*,\s*/$1/s'
expect_caught compress-out-of-line \
  '^NOT inlined: blake2b-core\.o defines blake2b__core__compress ' \
  '^NOT inlined: blake2b-hashing\.o calls _?blake2b__core__compress '

mutate blake2b-hashing.ads \
  's/^[ \t]*pragma Machine_Attribute \(Update, "flatten"\);[ \t]*\r?\n//m'
expect_caught update-no-flatten \
  '^MISSING in the source: pragma Machine_Attribute \(update, "flatten"\);$'

# strub and zero_call_used_regs are caught in the object; the source
# check names them too.
mutate blake2b-hashing.ads \
  's/^[ \t]*pragma Machine_Attribute \(Final, "strub", "internal"\);[ \t]*\r?\n//m'
expect_caught final-no-strub '^MISSING strub clone: final$' \
  '^MISSING in the source: pragma Machine_Attribute \(final, "strub", "internal"\);$'

mutate blake2b-hashing.ads \
  's/^[ \t]*pragma Machine_Attribute \(Init, "zero_call_used_regs", "all"\);[ \t]*\r?\n//m'
expect_caught init-no-zero-regs '^NOT cleared on return from init: ' \
  '^MISSING in the source: pragma Machine_Attribute \(init, "zero_call_used_regs", "all"\);$'

# The attribute names are case-sensitive: GCC ignores a misspelt one with
# only a warning, and the source check compares them exactly.
mutate blake2b-hashing.ads \
  's/(pragma Machine_Attribute \(Update, )"flatten"\);/$1"Flatten");/'
expect_caught update-flatten-capitalised \
  '^MISSING in the source: pragma Machine_Attribute \(update, "flatten"\);$'

mutate blake2b-hashing.ads \
  's/(pragma Machine_Attribute \(Final, )"strub"/$1"STRUB"/'
expect_caught final-strub-upper-case \
  '^MISSING in the source: pragma Machine_Attribute \(final, "strub", "internal"\);$'

mutate blake2b-hashing-counter_arithmetic.ads \
  's/(procedure Add_Counter\s*\(.*?\bwith\s+)Inline_Always\s*,\s*/$1/s'
expect_caught counter-no-inline-always \
  '^NOT inlined: blake2b-hashing-counter_arithmetic\.o defines '

mutate blake2b-hashing-counter_arithmetic.ads \
  's/(procedure Add_Counter\s*\(.*?\bwith\s+)Inline_Always\b/$1No_Inline/s'
expect_caught counter-no-inline \
  '^NOT inlined: blake2b-hashing-counter_arithmetic\.o defines ' \
  '^NOT allowed: blake2b-hashing\.o references .*add_counter'

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
