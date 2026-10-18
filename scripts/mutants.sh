#!/usr/bin/env bash
# Mutation suite: shows that the proof and the tests each catch the
# mistakes they are supposed to catch.
#
# First the unmutated crate (the baseline) must build, prove and pass its
# tests under the same settings (prove only, when only theory mutants are
# selected), or the run stops: otherwise a broken toolchain or a missing
# prover would look like a caught mutant. Then each
# mutant changes one place in a TEMPORARY COPY of the crate (under
# .mutants/, never the sources):
#   * GNATprove re-runs on the mutated unit (P), under the guard below;
#   * the full test suite is rebuilt and re-run (T).
# Each layer's outcome is one of:
#   * yes: its log shows unproved checks, or failed tests (or an exception
#     out of the mutated code); theory and counter mutants are held to
#     more (below);
#   * no: it passed;
#   * TAINTED (proof only): the guard killed the proof, or (theory and
#     counter mutants) every unproved check failed only through a prover
#     timeout, memory exhaustion or crash. Not a catch, and it fails the
#     run;
#   * ERROR: it failed in some other way, which fails the run.
# Every log is kept in .mutants/logs/, with each proof's results
# (<name>.spark) and its guard record (<name>.guard).
#
# Every mutant lists the layers that must catch it. One is caught by the
# proof alone on purpose:
#   * model-stale: the proof model must not see the leftover bytes past
#     the buffered ones; the tests execute their own copy of the model.
#
# Counter mutants (carry, plus-carry) are proved in the counter's own
# unit, Blake2b.Hashing.Counter_Arithmetic (Add_Counter and its contract):
# carry mutates its body, plus-carry the model's Plus, which Add_Counter's
# postcondition states. The counter lives in its own unit for this: the
# unit has the default step budget (20000 in blake2b.gpr), while
# blake2b-hashing.adb has 200000, and under that budget Alt-Ergo runs on
# for hours on the false carry goal. The suite judges their proof as
# strictly as the theory's (below), in the counter unit's own spec or
# body. Unlike the theory, the counter unit is compiled code, so the
# suite still builds the mutant and runs the tests, which must catch both
# too: a missing carry only matters after 2**64 bytes, which no test
# reaches through the public interface, but the test of the counter calls
# Add_Counter and the model's Plus directly. A mutant that doesn't build
# is an ERROR.
#
# Theory mutants (theory-*, example-*, witness-*) are proof-only: they
# mutate the streaming theory (Blake2b.Streaming and its children Theory,
# Consistency and Example), static ghost code that no build compiles, so
# no test can see them. For them the suite neither builds nor runs the
# tests (tests: n/a), and judges the proof strictly, from GNATprove's
# results file (scripts/spark-proof.py judge):
#   * caught only when an unproved check lies in the proved unit's own
#     spec or body (the unit named in the mutant's entry: for
#     witness-domain-shrink, which mutates Blake2b.Streaming, that is
#     Example), the guard did not fire, and at least one VC of such a
#     check was attempted and failed within the step budget for every
#     prover (Step limit exceeded, Unknown or Invalid). Only a failed
#     proof counts (severity low, medium or high on a VC_ rule): a proof
#     warning, such as an unreachable branch, does not; nor do unproved
#     checks elsewhere;
#   * TAINTED when the only unproved checks there failed through a
#     timeout, memory exhaustion or prover crash: a steps-only proof
#     might have proved them.
# They are:
#   * semantic: theory-fold-counter (the fold's counter one block ahead),
#     theory-final-counter (the key block missing from the final
#     counter), theory-realizes-shift (Realizes one byte off),
#     theory-key-padding (the key block padded with ones),
#     theory-last-flag (the final flag false), theory-buffer-boundary
#     (the buffered block reads one byte past the prefix);
#   * ablations, each removing one lemma call the proof needs:
#     theory-no-same-block, theory-no-counter, theory-no-same-context,
#     theory-no-padding (the padding fact inside Lemma_Pad_Byte);
#   * the worked example: example-no-piece (Lemma_Piece removed),
#     example-fits-2pow32 (Fits loosened to 2**32-byte pieces),
#     example-no-absorbed (the Absorbed loop invariant dropped);
#   * the witness, which shows Run_Loop's premises hold at the full
#     length: witness-overlong (one byte too many), witness-oversize-piece
#     (pieces of 2**32 bytes, which no Byte_Array holds),
#     witness-domain-shrink (Max_Length one byte shorter).
# Known non-mutants, not in the list:
#   * removing the Lemma_Room call in Example.Run_Loop is not caught: the
#     provers see Max_Input's private completion through proof visibility
#     and discharge Update's size precondition without the lemma;
#   * removing the per-byte Lemma_Pad_Byte call in Lemma_Logical_Final
#     made the provers exhaust time or memory, not steps, when tried
#     (killed at 15 minutes, near 4 GB): a tainted run, never a
#     catch. theory-no-padding removes the padding fact inside
#     Lemma_Pad_Byte instead, in a small proof context.
#
# The step margin. Whenever a theory mutant is selected, the baseline also
# proves all four theory units, and whenever a counter mutant is selected,
# the counter unit, once with every prover and once with each prover
# alone, and every check must cost at most STEP_MARGIN steps (5000, half
# the theory's 10000-step budget in blake2b.gpr and a quarter of the
# counter unit's 20000; not configurable), or the baseline fails. A
# check's cost is the largest, over its VCs, of the
# fewest steps any prover needed for the VC: the cheapest prover's steps
# (scripts/spark-proof.py margin). Not the steps of the prover GNATprove
# credits when it races them all: that is whichever finishes first, which
# depends on timing (one check has cost 1167 steps with cvc5 and been
# credited to z3 at 8168), while each prover's steps are the same on
# every run. So any check a mutant fails proved in the baseline with at
# least half its budget to spare, and the failure is down to the mutant,
# not to a proof near its limit. Each catch also prints the baseline's
# cost of the same check (matched by where it is checked and its rule)
# where the mutant left its line in place.
#
# The guard. Every mutant proof runs under a guard that polls the proof's
# process tree (ps, on macOS and Linux) every MUTANT_POLL seconds and kills
# the whole tree when one process, or the tree in total, exceeds
# MUTANT_RSS_KB of resident memory, or the proof exceeds MUTANT_WALL
# seconds. A killed proof is TAINTED, never a catch. The guard records the
# wall time and the largest RSS it saw (single process and tree), which a
# spike shorter than the poll interval can exceed. MUTANT_WALL=0 turns the
# time limit off. The tree total counts every GNATprove process: with
# PROVE_JOBS=0 on a machine with many cores it can pass the default limit
# by itself, so lower PROVE_JOBS (2 is enough for the theory) or raise
# MUTANT_RSS_KB. The baseline proofs are not guarded: they must succeed,
# and MUTANT_TIMEOUT bounds them.
#
# CI: the crate's CI (.github/workflows/ci.yml) does not run this script.
# It runs locally on macOS and in the Linux images, by hand.
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
#        MUTANT_RSS_KB=4194304 MUTANT_WALL=3600 MUTANT_POLL=2
#                     (the guard: KB per process or tree, seconds per
#                     proof, seconds between polls)
#
# Why the timeout: a mutant makes some goals false, and on a false goal a
# prover can run on without ever exhausting its step budget (cvc5 has
# spun for an hour; alt-ergo has grown to 27 GB). The library's own
# proof stays steps-only, so its result is the same on every machine.
# The baseline is proved under the same timeout, which shows the timeout
# doesn't fail any goal that should prove; so a mutant's unproved check is
# down to the mutant. It bounds each prover attempt's time; the guard
# bounds memory and the proof's total time.

set -euo pipefail

ALR=${ALR:-alr}
PROVE_JOBS=${PROVE_JOBS:-0}
MUTANT_TIMEOUT=${MUTANT_TIMEOUT:-300}
MUTANT_RSS_KB=${MUTANT_RSS_KB:-4194304}
MUTANT_WALL=${MUTANT_WALL:-3600}
MUTANT_POLL=${MUTANT_POLL:-2}
STEP_MARGIN=5000
ONLY=${ONLY:-}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK="$ROOT/.mutants"
SPARK_PROOF="$ROOT/scripts/spark-proof.py"
PYTHON=${PYTHON:-python3}
# The provers blake2b.gpr's Proof_Switches race (--prover=...).
PROVERS="z3 cvc5 altergo"

# The streaming theory: static ghost code, proved and never compiled.
THEORY_UNITS="blake2b-streaming.adb blake2b-streaming-theory.adb"
THEORY_UNITS="$THEORY_UNITS blake2b-streaming-consistency.adb"
THEORY_UNITS="$THEORY_UNITS blake2b-streaming-example.adb"

# The 128-bit counter (Add_Counter), in its own unit under the default
# step budget: compiled and tested, its mutants judged strictly.
COUNTER_UNITS="blake2b-hashing-counter_arithmetic.adb"

# name | file | exact text | replacement | unit to prove | must catch
# In the text and its replacement, \n stands for a line break.
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
  "carry|src/blake2b-hashing-counter_arithmetic.adb|Hi := Hi + 1;|Hi := Hi;|blake2b-hashing-counter_arithmetic.adb|PT"
  "update-content|src/blake2b-hashing.adb|Data (Pos .. Pos + Left - 1);|[others => 0];|blake2b-hashing.adb|PT"
  "stream-model|src/blake2b-spec-incremental.ads|T       => (Lo => U64 (Block_Bytes * (DD - 1)), Hi => 0),|T       => (Lo => U64 (Block_Bytes * DD), Hi => 0),|blake2b-spec-incremental.adb|PT"
  "plus-carry|src/blake2b-spec-incremental.ads|(Lo => Lo, Hi => (if Lo < N then T.Hi + 1 else T.Hi)));|(Lo => Lo, Hi => T.Hi));|blake2b-hashing-counter_arithmetic.adb|PT"
  "model-stale|src/blake2b-hashing.ads|(if J < S.Buf_Len then S.Buf (J) else 0)],|S.Buf (J)],|blake2b-hashing.adb|P"
  # The streaming theory (proof-only; see the header).
  "theory-fold-counter|src/blake2b-streaming-theory.ads|T_Lo => U64 (Block_Bytes * N),|T_Lo => U64 (Block_Bytes * (N + 1)),|blake2b-streaming-theory.adb|P"
  "theory-final-counter|src/blake2b-streaming-theory.ads|T_Lo => U64 (KB (Key) + Length),|T_Lo => U64 (Length),|blake2b-streaming-theory.adb|P"
  "theory-realizes-shift|src/blake2b-streaming-theory.ads|Data (Data'First + I) = Byte_At (C, M, Length, L + I)))|Data (Data'First + I) = Byte_At (C, M, Length, L + I + 1)))|blake2b-streaming-theory.adb|P"
  "theory-key-padding|src/blake2b-streaming-theory.ads|(if J < Key'Length then Key (Key'First + J) else 0)|(if J < Key'Length then Key (Key'First + J) else 1)|blake2b-streaming-theory.adb|P"
  "theory-last-flag|src/blake2b-streaming-theory.ads|Last => True);|Last => False);|blake2b-streaming-theory.adb|P"
  "theory-buffer-boundary|src/blake2b-streaming-theory.ads|(if Block_Bytes * BB (Key, L) + J < KB (Key) + L|(if Block_Bytes * BB (Key, L) + J <= KB (Key) + L|blake2b-streaming-theory.adb|P"
  "theory-no-same-block|src/blake2b-streaming-theory.adb|Lemma_Same_Block\n        (Spec.Block_Of (No_Bytes, Tail, Data, K - 1),\n         Logical_Block (Key, C, M, Length, BB (Key, L) + K - 1));|null;|blake2b-streaming-theory.adb|P"
  "theory-no-counter|src/blake2b-streaming-theory.adb|Lemma_Counter (BB (Key, L), K);|null;|blake2b-streaming-theory.adb|P"
  "theory-no-same-context|src/blake2b-streaming-theory.adb|Lemma_Same_Context (Ctx, Logical_After (Key, C, M, Length, L, Ctx.NN));|null;|blake2b-streaming-theory.adb|P"
  "theory-no-padding|src/blake2b-streaming-theory.adb|Lemma_Padding (C, M, Length, P - KB (Key));|null;|blake2b-streaming-theory.adb|P"
  "example-no-piece|src/blake2b-streaming-example.adb|Lemma_Piece (C, M, Length, I);|null;|blake2b-streaming-example.adb|P"
  "example-fits-2pow32|src/blake2b-streaming-example.ads|(for all I in M'Range => M (I).Count <= 2**31)|(for all I in M'Range => M (I).Count <= 2**32)|blake2b-streaming-example.adb|P"
  "example-no-absorbed|src/blake2b-streaming-example.adb|         pragma Loop_Invariant (Absorbed (S) = Big.Length (KB (Key) + P));\n||blake2b-streaming-example.adb|P"
  "witness-overlong|src/blake2b-streaming-example.adb|Count  => (if I <= 8 then 2**31 elsif I = 9 then 36 else 0),|Count  => (if I <= 8 then 2**31 elsif I = 9 then 37 else 0),|blake2b-streaming-example.adb|P"
  "witness-oversize-piece|src/blake2b-streaming-example.adb|Count  => (if I <= 8 then 2**31 elsif I = 9 then 36 else 0),\n          First  => (if I <= 9 then 2**31 * I64 (I - 1) else Max_Length))]);|Count  => (if I <= 4 then 2**32 elsif I = 5 then 36 else 0),\n          First  => (if I <= 5 then 2**32 * I64 (I - 1) else Max_Length))]);|blake2b-streaming-example.adb|P"
  "witness-domain-shrink|src/blake2b-streaming.ads|Max_Length : constant I64 := 2**34 + 36|Max_Length : constant I64 := 2**34 + 35|blake2b-streaming-example.adb|P"
)

is_theory () {    # $1 = unit to prove
  case " $THEORY_UNITS " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

is_counter () {   # $1 = unit to prove
  case " $COUNTER_UNITS " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

copy_crate () {
  local dest=$1
  rm -rf "$dest"
  mkdir -p "$dest/tests"
  cp -r "$ROOT/src" "$ROOT/alire.toml" "$ROOT/blake2b.gpr" "$dest/"
  cp -r "$ROOT/tests/src" "$ROOT/tests/ref" "$ROOT/tests/data" \
        "$ROOT/tests/alire.toml" "$ROOT/tests/blake2b_tests.gpr" \
        "$dest/tests/"
}

# How many times $2 occurs in file $1, literally (across lines).
occurrences () {
  local content stripped
  content=$(cat "$1"; printf x); content=${content%x}
  stripped=${content//"$2"/}
  echo $(( (${#content} - ${#stripped}) / ${#2} ))
}

# Replaces the one occurrence of $2 in file $1 with $3, literally.
mutate () {
  local file=$1 search=$2 replace=$3
  local content count
  content=$(cat "$file"; printf x); content=${content%x}
  count=$(occurrences "$file" "$search")
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

# Only what GNATprove needs without a build: Alire's generated
# configuration (config/blake2b_config.gpr, which blake2b.gpr imports).
configure () {    # $1 = crate copy, $2 = log
  (cd "$1/tests" && "$ALR" -n build --stop-after=generation) > "$2" 2>&1
}

prove () {        # $1 = crate copy, $2 = unit, $3 = log
  (cd "$1/tests" && "$ALR" -n exec -- gnatprove \
     -P ../blake2b.gpr -j"$PROVE_JOBS" -u "$2" \
     --timeout="$MUTANT_TIMEOUT") > "$3" 2>&1
}

# Proves unit $2 of crate copy $1 with prover $3 alone, from cold, into
# log $4. Some checks need another prover, so the exit status means
# nothing; the results file is what is read.
prove_alone () {
  rm -rf "$1"/obj/*/gnatprove
  (cd "$1/tests" && "$ALR" -n exec -- gnatprove \
     -P ../blake2b.gpr -j"$PROVE_JOBS" -u "$2" --prover="$3" \
     --timeout="$MUTANT_TIMEOUT") > "$4" 2>&1 || true
}

run_tests () {    # $1 = crate copy, $2 = log
  (cd "$1/tests" && ./bin/profile-profile/test_main) > "$2" 2>&1
}

# The results file GNATprove wrote for unit $2 in crate copy $1 (empty if
# there is none).
spark_file () {
  local stem=${2%.adb}
  { find "$1/obj" -path "*/gnatprove/$stem.spark" 2>/dev/null || true; } \
    | head -n 1
}

# The process tree under pid $1 (itself included), from one ps snapshot.
# ps -A -o pid=,ppid=,rss= means the same on macOS and Linux (RSS in KB).
tree_snapshot () {
  ps -A -o pid=,ppid=,rss= 2>/dev/null | awk -v root="$1" '
    { parent[$1] = $2; rss[$1] = $3 }
    END {
      keep[root] = 1
      do {
        grown = 0
        for (p in parent)
          if (!(p in keep) && (parent[p] in keep)) { keep[p] = 1; grown = 1 }
      } while (grown)
      for (p in keep) if (p in rss) print p, rss[p]
    }'
}

# Stops the whole tree under pid $1 (so nothing in it can fork again),
# then kills every process in it.
kill_tree () {
  local all="" pids round
  for round in 1 2 3 4 5 6 7 8; do
    pids=$(tree_snapshot "$1" | awk '{ print $1 }')
    [ -n "$pids" ] || break
    all="$all $pids"
    # shellcheck disable=SC2086
    kill -STOP $pids 2>/dev/null || true
  done
  if [ -n "$all" ]; then
    # shellcheck disable=SC2086
    kill -KILL $all 2>/dev/null || true
  fi
}

# Proves unit $2 of crate copy $1 into log $3 under the guard, and writes
# the guard's record to $4. Sets PROVE_STATUS (GNATprove's exit status),
# GUARD_FIRED (empty, or why the guard killed the proof), GUARD_WALL_S,
# GUARD_PEAK_ONE_KB and GUARD_PEAK_TREE_KB.
guarded_prove () {
  local crate=$1 unit=$2 log=$3 record=$4
  local pid start now one tree
  GUARD_FIRED=""
  GUARD_PEAK_ONE_KB=0
  GUARD_PEAK_TREE_KB=0
  start=$(date +%s)
  prove "$crate" "$unit" "$log" &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    read -r one tree < <(tree_snapshot "$pid" \
      | awk '{ t += $2; if ($2 > m) m = $2 } END { print m + 0, t + 0 }') \
      || { one=0; tree=0; }
    [ "$one" -le "$GUARD_PEAK_ONE_KB" ] || GUARD_PEAK_ONE_KB=$one
    [ "$tree" -le "$GUARD_PEAK_TREE_KB" ] || GUARD_PEAK_TREE_KB=$tree
    now=$(date +%s)
    if [ "$one" -gt "$MUTANT_RSS_KB" ]; then
      GUARD_FIRED="memory: one process at $one KB (limit $MUTANT_RSS_KB)"
    elif [ "$tree" -gt "$MUTANT_RSS_KB" ]; then
      GUARD_FIRED="memory: process tree at $tree KB (limit $MUTANT_RSS_KB)"
    elif [ "$MUTANT_WALL" -gt 0 ] && [ $((now - start)) -gt "$MUTANT_WALL" ]
    then
      GUARD_FIRED="wall: $((now - start)) s (limit $MUTANT_WALL)"
    fi
    if [ -n "$GUARD_FIRED" ]; then
      {
        echo "guard fired: $GUARD_FIRED"
        echo "killed:"
        ps -o pid=,rss=,etime=,comm= \
           -p "$(tree_snapshot "$pid" | awk '{ print $1 }' | paste -sd, -)" \
           2>/dev/null || true
      } >> "$record"
      kill_tree "$pid"
      break
    fi
    sleep "$MUTANT_POLL"
  done
  PROVE_STATUS=0
  # (stderr: the shell's own "Killed" notice for a killed proof.)
  wait "$pid" 2>/dev/null || PROVE_STATUS=$?
  GUARD_WALL_S=$(( $(date +%s) - start ))
  echo "exit=$PROVE_STATUS wall=${GUARD_WALL_S}s" \
       "guard=${GUARD_FIRED:-none}" \
       "peak_rss_one_kb=$GUARD_PEAK_ONE_KB" \
       "peak_rss_tree_kb=$GUARD_PEAK_TREE_KB" >> "$record"
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

# A theory or counter mutant's proof, judged strictly (see the header)
# from its results file. $1 = exit status, $2 = log, $3 = unit, $4 =
# results file (may be empty), $5 = its judgement's log.
strict_outcome () {
  local reference=() status=0
  if [ "$1" -eq 0 ]; then
    echo no
    return
  fi
  if [ -z "$4" ]; then
    echo "no results file" > "$5"
    echo ERROR
    return
  fi
  if [ -f "$LOGS/baseline.costs.json" ]; then
    reference=("$LOGS/baseline.costs.json")
  fi
  "$PYTHON" -I "$SPARK_PROOF" judge "$3" "$4" \
    ${reference[@]+"${reference[@]}"} > "$5" 2>&1 || status=$?
  case "$status" in
    0) echo yes ;;
    3) echo TAINTED ;;
    4)
      # Unproved checks only outside the unit: not a catch. Anything
      # else (a compile error, a crash) is an error.
      if [ "$(proof_outcome "$1" "$2")" = yes ]; then echo no; else echo ERROR; fi
      ;;
    *) echo ERROR ;;
  esac
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

# The selected mutants, the units their proofs need, whether any of them
# needs the build and the tests (every mutant but the theory's), and the
# units whose step margin the baseline measures (the theory's when a
# theory mutant is selected, the counter's when a counter mutant is).
selected=()
nselected=0
units=""
need_tests=0
need_theory=0
need_counter=0
margin_units=""
add_unit () {
  case " $units " in
    *" $1 "*) ;;
    *) units="$units $1" ;;
  esac
}
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
  add_unit "$unit"
  if is_theory "$unit"; then
    need_theory=1
  else
    need_tests=1
  fi
  if is_counter "$unit"; then
    need_counter=1
  fi
done
if [ "$nselected" -eq 0 ]; then
  echo "mutants: no mutant matched ONLY=$ONLY"
  exit 1
fi
if [ "$need_theory" -eq 1 ]; then
  margin_units="$margin_units $THEORY_UNITS"
fi
if [ "$need_counter" -eq 1 ]; then
  margin_units="$margin_units $COUNTER_UNITS"
fi
# The step margin needs each measured unit's baseline results.
for unit in $margin_units; do add_unit "$unit"; done

# Every selected mutation site must occur exactly once in the sources,
# before any time goes into the baseline.
sites_ok=1
for entry in "${selected[@]}"; do
  IFS='|' read -r name file search replace unit expect <<< "$entry"
  search=${search//\\n/$'\n'}
  count=$(occurrences "$ROOT/$file" "$search")
  if [ "$count" -ne 1 ]; then
    echo "mutant $name: site found $count times in $file (want exactly 1)"
    sites_ok=0
  fi
done
[ "$sites_ok" -eq 1 ] || exit 2

rm -rf "$WORK"
mkdir -p "$LOGS"

# Baseline: the unmutated crate must build, prove and pass its tests
# under exactly the settings the mutants get (same jobs, same timeout).
# Otherwise a failure below could be the toolchain, a prover or the
# timeout, not the mutant, and the run stops here. Proving the baseline
# under the same timeout also shows the timeout cannot, on its own, fail
# a goal that should prove. (Theory mutants alone need neither the build
# nor the tests.)
echo "=================================================================="
echo "baseline: unmutated crate (units:$units)"
base="$WORK/baseline"
copy_crate "$base"
if [ "$need_tests" -eq 1 ]; then
  if ! build "$base" "$LOGS/baseline.build.log"; then
    echo "  baseline does not build: see $LOGS/baseline.build.log"
    exit 2
  fi
elif ! configure "$base" "$LOGS/baseline.configure.log"; then
  echo "  baseline cannot be configured: see $LOGS/baseline.configure.log"
  exit 2
fi
for unit in $units; do
  if ! prove "$base" "$unit" "$LOGS/baseline.prove.$unit.log"; then
    echo "  baseline proof of $unit failed: see $LOGS/baseline.prove.$unit.log"
    echo "  (a toolchain or prover problem, or MUTANT_TIMEOUT too low)"
    exit 2
  fi
  spark=$(spark_file "$base" "$unit")
  if [ -n "$spark" ]; then
    cp "$spark" "$LOGS/baseline.${unit%.adb}.spark"
  fi
done
if [ -n "$margin_units" ]; then
  for unit in $margin_units; do
    for prover in $PROVERS; do
      prove_alone "$base" "$unit" "$prover" \
        "$LOGS/baseline.prove.$unit.$prover.log"
      spark=$(spark_file "$base" "$unit")
      if [ -n "$spark" ]; then
        cp "$spark" "$LOGS/baseline.${unit%.adb}.$prover.spark"
      fi
    done
  done
  # One call for every measured unit: it writes baseline.costs.json whole.
  # shellcheck disable=SC2086
  if ! "$PYTHON" -I "$SPARK_PROOF" margin "$STEP_MARGIN" \
       "$LOGS/baseline.costs.json" "$LOGS" "${PROVERS// /,}" \
       $margin_units > "$LOGS/baseline.margin.log" 2>&1; then
    sed 's/^/  /' "$LOGS/baseline.margin.log"
    echo "  baseline fails the step margin: a measured unit's check costs"
    echo "  more than $STEP_MARGIN steps, or its results are unreadable"
    echo "  (see $LOGS/baseline.margin.log)"
    exit 2
  fi
  sed 's/^/  /' "$LOGS/baseline.margin.log"
fi
if [ "$need_tests" -eq 1 ] && ! run_tests "$base" "$LOGS/baseline.tests.log"
then
  echo "  baseline tests failed: see $LOGS/baseline.tests.log"
  exit 2
fi
rm -rf "$base"
if [ "$need_tests" -eq 1 ]; then
  echo "  baseline: builds, proves and passes"
else
  echo "  baseline: proves (theory mutants only: no build, no tests)"
fi

results=()
broken=0
errors=0
tainted=0
for entry in "${selected[@]}"; do
  IFS='|' read -r name file search replace unit expect <<< "$entry"
  echo "=================================================================="
  echo "mutant: $name ($file)"
  dir="$WORK/$name"
  copy_crate "$dir"
  # An entry's \n stands for a line break (decoded here, not in a
  # command substitution, which would drop a trailing one).
  search=${search//\\n/$'\n'}
  replace=${replace//\\n/$'\n'}
  mutate "$dir/$file" "$search" "$replace"

  caught_p=-
  caught_t=-
  GUARD_WALL_S=0
  GUARD_PEAK_TREE_KB=0
  if is_theory "$unit" \
     && ! configure "$dir" "$LOGS/$name.configure.log"; then
    echo "  cannot be configured: see $LOGS/$name.configure.log"
    caught_p=ERROR
    caught_t=n/a
  elif is_theory "$unit"; then
    # Ghost code no build compiles: the proof alone.
    caught_t=n/a
    guarded_prove "$dir" "$unit" "$LOGS/$name.prove.log" "$LOGS/$name.guard"
    spark=$(spark_file "$dir" "$unit")
    if [ -n "$spark" ]; then
      cp "$spark" "$LOGS/$name.spark"
      spark="$LOGS/$name.spark"
    fi
    if [ -n "$GUARD_FIRED" ]; then
      caught_p=TAINTED
      echo "  guard fired: $GUARD_FIRED"
    else
      caught_p=$(strict_outcome "$PROVE_STATUS" "$LOGS/$name.prove.log" \
                   "$unit" "$spark" "$LOGS/$name.judge.log")
      [ ! -f "$LOGS/$name.judge.log" ] \
        || sed 's/^/  /' "$LOGS/$name.judge.log"
    fi
  elif ! build "$dir" "$LOGS/$name.build.log"; then
    # A mutant that doesn't compile tests nothing: an error in the suite,
    # not a catch.
    echo "  does not build: see $LOGS/$name.build.log"
    caught_p=ERROR
    caught_t=ERROR
  else
    guarded_prove "$dir" "$unit" "$LOGS/$name.prove.log" "$LOGS/$name.guard"
    spark=$(spark_file "$dir" "$unit")
    if [ -n "$spark" ]; then
      cp "$spark" "$LOGS/$name.spark"
      spark="$LOGS/$name.spark"
    fi
    if [ -n "$GUARD_FIRED" ]; then
      caught_p=TAINTED
      echo "  guard fired: $GUARD_FIRED"
    elif is_counter "$unit"; then
      # Caught by the proof alone (must: P): judged as strictly as the
      # theory (see the header). The tests still run, below.
      caught_p=$(strict_outcome "$PROVE_STATUS" "$LOGS/$name.prove.log" \
                   "$unit" "$spark" "$LOGS/$name.judge.log")
      [ ! -f "$LOGS/$name.judge.log" ] \
        || sed 's/^/  /' "$LOGS/$name.judge.log"
    else
      caught_p=$(proof_outcome "$PROVE_STATUS" "$LOGS/$name.prove.log")
    fi
    status=0
    run_tests "$dir" "$LOGS/$name.tests.log" || status=$?
    caught_t=$(test_outcome "$status" "$LOGS/$name.tests.log")
  fi

  verdict=ok
  if [ "$caught_p" = ERROR ] || [ "$caught_t" = ERROR ]; then
    verdict=ERROR
    errors=$((errors + 1))
  elif [ "$caught_p" = TAINTED ]; then
    verdict=TAINTED
    tainted=$((tainted + 1))
  else
    case "$expect" in
      *P*) [ "$caught_p" = yes ] || verdict=MISSED ;;
    esac
    case "$expect" in
      *T*) [ "$caught_t" = yes ] || verdict=MISSED ;;
    esac
    [ "$verdict" = ok ] || broken=$((broken + 1))
  fi
  line=$(printf '%-24s proof:%-7s tests:%-5s must:%-3s %-7s wall:%5ss rss:%8sKB' \
         "$name" "$caught_p" "$caught_t" "$expect" "$verdict" \
         "$GUARD_WALL_S" "$GUARD_PEAK_TREE_KB")
  echo "  $line"
  results+=("$line")
  rm -rf "$dir"
done

echo
echo "mutation summary (logs in $LOGS; wall and rss: the guarded proof,"
echo "rss the largest process-tree total the guard saw)"
printf '  %s\n' "${results[@]}"
status=0
if [ "$errors" -gt 0 ]; then
  echo "mutants: $errors mutant(s) could not be judged (ERROR): see the logs"
  status=1
fi
if [ "$tainted" -gt 0 ]; then
  echo "mutants: $tainted mutant(s) TAINTED (killed by the guard, or failed"
  echo "         only through timeouts, memory or crashes): not catches"
  status=1
fi
if [ "$broken" -gt 0 ]; then
  echo "mutants: $broken mutant(s) MISSED"
  status=1
fi
if [ "$status" -eq 0 ]; then
  echo "mutants: every mutant caught by every layer it must be"
fi
exit "$status"
