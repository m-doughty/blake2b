#!/usr/bin/env bash
# Mutation suite: shows that the proof and the tests each catch the
# mistakes they are supposed to catch.
#
# First the unmutated crate (the baseline) must build, prove and pass its
# tests under the same settings, or the run stops: otherwise a broken
# toolchain or a missing prover would look like a caught mutant. Then each
# mutant changes one line of a TEMPORARY COPY of the crate (under
# .mutants/, never the sources):
#   * GNATprove re-runs on the mutated unit (P);
#   * the full test suite is rebuilt and re-run (T).
# Each layer's outcome is one of:
#   * yes: its log shows unproved checks, or failed tests (or an exception
#     out of the mutated code);
#   * no: it passed;
#   * ERROR: it failed in some other way, which fails the run.
# Every log is kept in .mutants/logs/.
#
# Every mutant lists the layers that must catch it. Three are caught by
# the proof alone on purpose:
#   * carry, plus-carry: a missing carry into the counter's high word
#     (in the code, or in the model it is proved against) only matters
#     after 2**64 bytes, which no test can reach;
#   * model-stale: the proof model must not see the leftover bytes past
#     the buffered ones; the tests execute their own copy of the model.
#
# Usage: scripts/mutants.sh            (from anywhere in the crate)
#        ALR=/path/to/alr scripts/mutants.sh
#        PROVE_JOBS=4 scripts/mutants.sh
#                     (GNATprove processes; default 0 = one per core.
#                     Fewer use less memory.)
#        ONLY=model-stale,carry scripts/mutants.sh
#                     (run only the named mutants)
#        MUTANT_TIMEOUT=300 scripts/mutants.sh
#                     (seconds per prover attempt, mutant proofs only)
#
# Why the timeout: a mutant makes some goals false, and on a false goal a
# prover can run on without ever exhausting its step budget (cvc5 has
# spun for an hour; alt-ergo has grown to 27 GB). The library's own
# proof stays steps-only, so its result is the same on every machine.
# The baseline is proved under the same timeout, which shows the timeout
# doesn't fail any goal that should prove; so a mutant's unproved check is
# down to the mutant. It bounds time, not memory: watch memory, and lower
# PROVE_JOBS on small machines.

set -euo pipefail

ALR=${ALR:-alr}
PROVE_JOBS=${PROVE_JOBS:-0}
MUTANT_TIMEOUT=${MUTANT_TIMEOUT:-300}
ONLY=${ONLY:-}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK="$ROOT/.mutants"

# name | file | exact text | replacement | unit to prove | must catch
MUTANTS=(
  "core-rotation|src/blake2b-core.adb|VB := Rotate_Right (VB xor VC, 63);|VB := Rotate_Right (VB xor VC, 62);|blake2b-core.adb|PT"
  "core-sigma|src/blake2b-core.ads|[14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],|[14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 3, 5],|blake2b-core.adb|PT"
  "core-iv|src/blake2b-core.ads|[16#6A09_E667_F3BC_C908#|[16#6A09_E667_F3BC_C909#|blake2b-core.adb|PT"
  "param-block|src/blake2b-core.adb|xor Shift_Left (U64 (KK), 8)|xor Shift_Left (U64 (KK), 16)|blake2b-core.adb|PT"
  "final-flag|src/blake2b-core.adb|(if Last then not IV (6) else IV (6)),|IV (6),|blake2b-core.adb|PT"
  "keyed-counter|src/blake2b-hashing.adb|T_Lo => U64 (L + Block_Bytes * KB),|T_Lo => U64 (L),|blake2b-hashing.adb|PT"
  "truncation|src/blake2b-core.adb|(Byte (Shift_Right (H (Chain_Index (J / 8)),|(Byte (Shift_Right (H (Chain_Index (7 - J / 8)),|blake2b-core.adb|PT"
  "lazy-final|src/blake2b-hashing.adb|while Left > Block_Bytes loop|while Left >= Block_Bytes loop|blake2b-hashing.adb|PT"
  "spec-rotation|src/blake2b-spec.ads|VB2 : constant U64 := Rotate_Right (VB1 xor VC2, 63);|VB2 : constant U64 := Rotate_Right (VB1 xor VC2, 62);|blake2b-core.adb|PT"
  "carry|src/blake2b-hashing.adb|Hi := Hi + 1;|Hi := Hi;|blake2b-hashing.adb|P"
  "update-content|src/blake2b-hashing.adb|Data (Pos .. Pos + Left - 1);|[others => 0];|blake2b-hashing.adb|PT"
  "stream-model|src/blake2b-spec-incremental.ads|T       => (Lo => U64 (Block_Bytes * (DD - 1)), Hi => 0),|T       => (Lo => U64 (Block_Bytes * DD), Hi => 0),|blake2b-spec-incremental.adb|PT"
  "plus-carry|src/blake2b-spec-incremental.ads|(Lo => Lo, Hi => (if Lo < N then T.Hi + 1 else T.Hi)));|(Lo => Lo, Hi => T.Hi));|blake2b-hashing.adb|P"
  "model-stale|src/blake2b-hashing.ads|(if J < S.Buf_Len then S.Buf (J) else 0)],|S.Buf (J)],|blake2b-hashing.adb|P"
)

copy_crate () {
  local dest=$1
  rm -rf "$dest"
  mkdir -p "$dest/tests"
  cp -r "$ROOT/src" "$ROOT/alire.toml" "$ROOT/blake2b_spark.gpr" "$dest/"
  cp -r "$ROOT/tests/src" "$ROOT/tests/ref" "$ROOT/tests/data" \
        "$ROOT/tests/alire.toml" "$ROOT/tests/blake2b_spark_tests.gpr" \
        "$dest/tests/"
}

# Replaces the one occurrence of $3 in file $2 with $4, literally.
mutate () {
  local file=$1 search=$2 replace=$3
  local content count
  content=$(cat "$file"; printf x); content=${content%x}
  count=$(grep -cF -- "$search" "$file" || true)
  if [ "$count" -ne 1 ]; then
    echo "  mutation site found $count times (want exactly 1): $search"
    return 1
  fi
  printf '%s' "${content/"$search"/"$replace"}" > "$file"
}

# Each step's full output is kept in $LOGS, one file per mutant and step,
# and survives the run (only the scratch copies are deleted).
LOGS="$WORK/logs"

build () {        # $1 = crate copy, $2 = log
  (cd "$1/tests" && "$ALR" -n build) > "$2" 2>&1
}

prove () {        # $1 = crate copy, $2 = unit, $3 = log
  (cd "$1/tests" && "$ALR" -n exec -- gnatprove \
     -P ../blake2b_spark.gpr -j"$PROVE_JOBS" -u "$2" \
     --timeout="$MUTANT_TIMEOUT") > "$3" 2>&1
}

run_tests () {    # $1 = crate copy, $2 = log
  (cd "$1/tests" && ./bin/profile-profile/test_main) > "$2" 2>&1
}

# What a failed step means. A non-zero exit alone proves nothing: a
# missing prover, a broken toolchain or a crash also fail. A step counts
# as having CAUGHT the mutant only when its log shows the kind of failure
# that step exists to report; any other failure is an ERROR.
#   proof: GNATprove's check messages ("medium: ... might fail") and its
#          "unproved check messages considered as errors" summary;
#   tests: the harness's own count ("passed: N  failed: M", M > 0), or an
#          exception raised out of the mutated code.
proof_outcome () {   # $1 = exit status, $2 = log
  if [ "$1" -eq 0 ]; then
    echo no
  elif grep -qE '^ *(low|medium|high): ' "$2" \
       && grep -q 'unproved check messages considered as errors' "$2"; then
    echo yes
  else
    echo ERROR
  fi
}

test_outcome () {    # $1 = exit status, $2 = log
  if [ "$1" -eq 0 ]; then
    echo no
  elif grep -qE '^passed: [0-9]+ +failed: [1-9]' "$2" \
       || grep -qE '^raised [A-Z_.]+' "$2"; then
    echo yes
  else
    echo ERROR
  fi
}

# The selected mutants, and the units their proofs need.
selected=()
nselected=0
units=""
for entry in "${MUTANTS[@]}"; do
  IFS='|' read -r name file search replace unit expect <<< "$entry"
  if [ -n "$ONLY" ]; then
    case ",$ONLY," in
      *",$name,"*) ;;
      *) continue ;;
    esac
  fi
  selected+=("$entry")
  nselected=$((nselected + 1))
  case " $units " in
    *" $unit "*) ;;
    *) units="$units $unit" ;;
  esac
done
if [ "$nselected" -eq 0 ]; then
  echo "mutants: no mutant matched ONLY=$ONLY"
  exit 1
fi

rm -rf "$WORK"
mkdir -p "$LOGS"

# Baseline: the unmutated crate must build, prove and pass its tests
# under exactly the settings the mutants get (same jobs, same timeout).
# Otherwise a failure below could be the toolchain, a prover or the
# timeout, not the mutant, and the run stops here. Proving the baseline
# under the same timeout also shows the timeout cannot, on its own, fail
# a goal that should prove.
echo "=================================================================="
echo "baseline: unmutated crate (units:$units)"
base="$WORK/baseline"
copy_crate "$base"
if ! build "$base" "$LOGS/baseline.build.log"; then
  echo "  baseline does not build: see $LOGS/baseline.build.log"
  exit 2
fi
for unit in $units; do
  if ! prove "$base" "$unit" "$LOGS/baseline.prove.$unit.log"; then
    echo "  baseline proof of $unit failed: see $LOGS/baseline.prove.$unit.log"
    echo "  (a toolchain or prover problem, or MUTANT_TIMEOUT too low)"
    exit 2
  fi
done
if ! run_tests "$base" "$LOGS/baseline.tests.log"; then
  echo "  baseline tests failed: see $LOGS/baseline.tests.log"
  exit 2
fi
rm -rf "$base"
echo "  baseline: builds, proves and passes"

results=()
broken=0
errors=0
for entry in "${selected[@]}"; do
  IFS='|' read -r name file search replace unit expect <<< "$entry"
  echo "=================================================================="
  echo "mutant: $name ($file)"
  dir="$WORK/$name"
  copy_crate "$dir"
  mutate "$dir/$file" "$search" "$replace"

  caught_p=-
  caught_t=-
  if ! build "$dir" "$LOGS/$name.build.log"; then
    # A mutant that doesn't compile tests nothing: an error in the suite,
    # not a catch.
    echo "  does not build: see $LOGS/$name.build.log"
    caught_p=ERROR
    caught_t=ERROR
  else
    status=0
    prove "$dir" "$unit" "$LOGS/$name.prove.log" || status=$?
    caught_p=$(proof_outcome "$status" "$LOGS/$name.prove.log")
    status=0
    run_tests "$dir" "$LOGS/$name.tests.log" || status=$?
    caught_t=$(test_outcome "$status" "$LOGS/$name.tests.log")
  fi

  verdict=ok
  if [ "$caught_p" = ERROR ] || [ "$caught_t" = ERROR ]; then
    verdict=ERROR
    errors=$((errors + 1))
  else
    case "$expect" in
      *P*) [ "$caught_p" = yes ] || verdict=MISSED ;;
    esac
    case "$expect" in
      *T*) [ "$caught_t" = yes ] || verdict=MISSED ;;
    esac
    [ "$verdict" = ok ] || broken=$((broken + 1))
  fi
  line=$(printf '%-15s proof:%-5s tests:%-5s must:%-3s %s' \
         "$name" "$caught_p" "$caught_t" "$expect" "$verdict")
  echo "  $line"
  results+=("$line")
  rm -rf "$dir"
done

echo
echo "mutation summary (logs in $LOGS)"
printf '  %s\n' "${results[@]}"
if [ "$errors" -gt 0 ]; then
  echo "mutants: $errors mutant(s) could not be judged (ERROR): see the logs"
  exit 1
elif [ "$broken" -eq 0 ]; then
  echo "mutants: every mutant caught by every layer it must be"
else
  echo "mutants: $broken mutant(s) MISSED"
  exit 1
fi
