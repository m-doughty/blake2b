#!/usr/bin/env bash
# The speed of the working tree against an earlier commit, from bench_main
# (tests/src/bench_main.adb): reported, never gated.
#
# What is measured. The script builds bench_main twice, each in a scratch
# tree under obj/bench-compare/ (git ignores obj/), exactly as tests/
# builds it (alr -n build in the tree's tests/ directory, which builds the
# crate in that tree through its path pin):
#   base     the commit BASE_REF, extracted with git archive (the working
#            tree, the index and the branches are not touched);
#   current  the working tree as it is, uncommitted changes included: every
#            tracked file that exists, and every untracked file git does not
#            ignore.
# Which bench_main each side runs is BENCH_SOURCE:
#   current  (default) both run the working tree's tests/src/bench_main.adb,
#            copied into the base tree before its build, so that only the
#            library differs, and every line is compared; the script stops
#            if that program does not build against the base tree;
#   base     each side runs its own bench_main (a line the base's lacks is
#            then named, not compared).
# It then runs the two programs alternately, PAIRS (default 5) pairs, base
# first in odd pairs and current first in even ones, so that a drift of the
# machine's speed during the run falls on both alike. Each run prints
# bench_main's table (each figure there is already the median of its own
# seven timings).
#
# The lines compared, where both programs print them (Ada's MB/s only; the
# reference C column is not compared):
#   unkeyed one-shot  64 B, 1 KiB, 64 KiB, 1 MiB
#   keyed one-shot    64 B, 1 KiB (a 64-byte key)
#   incremental       1 MiB in 4 KiB updates, and in 100-byte updates
# A line only one of the programs prints (one added since BASE_REF, say) is
# named, not compared.
#
# Output, one line per compared line: each side's median over the pairs in
# MB/s, its spread (least - most, and that range as a percentage of the
# median), and the ratio current/base of the medians (above 1: the working
# tree is faster). A line where either spread exceeds 10% of its median is
# marked "inconclusive"; otherwise one whose ratio is below 0.95 is marked
# "more than 5% slower". Neither changes the exit status.
#
# Exit status: 0 if both builds and every run succeeded (whatever the
# speeds); 1 if a build or a run failed (with BENCH_SOURCE=current, the
# working tree's bench_main not building against the base tree is named as
# such), BASE_REF is not a commit, or a run printed none of the lines
# above.
#
# Usage: bash scripts/bench-compare.sh BASE_REF
#        ALR=/path/to/alr PAIRS=5 BENCH_SOURCE=current \
#          bash scripts/bench-compare.sh BASE_REF
# (A shallow clone may lack BASE_REF: fetch it, or the whole history,
# first.)

set -euo pipefail

ALR=${ALR:-alr}
PAIRS=${PAIRS:-5}
BENCH_SOURCE=${BENCH_SOURCE:-current}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
WORK="$ROOT/obj/bench-compare"

say () { echo "bench-compare: $*"; }
fail () {
  say "ERROR: $*" >&2
  exit 1
}

[ "$#" -eq 1 ] || fail "usage: bash scripts/bench-compare.sh BASE_REF"
BASE_REF=$1
case $PAIRS in
  ''|*[!0-9]*|0) fail "PAIRS must be a positive number" ;;
esac
case $BENCH_SOURCE in
  current)
    bench_text="both sides run the working tree's bench_main, so only the"
    bench_text="$bench_text library differs"
    ;;
  base) bench_text="each side runs its own bench_main" ;;
  *) fail "BENCH_SOURCE must be current or base" ;;
esac
base_commit=$(git rev-parse --verify --quiet "$BASE_REF^{commit}") \
  || fail "$BASE_REF is not a commit in this repository (in a shallow" \
          "clone, fetch it first)"

compiler=$("$ALR" -n exec -- gcc --version | head -n 1 | tr -d '\r')
say "platform: $(uname -s) $(uname -m); compiler: $compiler"
say "base: $BASE_REF ($base_commit); current: the working tree"
say "BENCH_SOURCE=$BENCH_SOURCE: $bench_text"
say "$PAIRS pairs of runs, alternating which side runs first; figures are" \
    "Ada MB/s (10**6 bytes per second)"

rm -rf "$WORK"
mkdir -p "$WORK/base" "$WORK/current"

# The base: the commit's tracked files.
git archive "$base_commit" | tar -x -C "$WORK/base" \
  || fail "could not extract $BASE_REF"

# The current tree: tracked files that exist, and untracked ones not
# ignored, as they are on disk.
git ls-files -co --exclude-standard > "$WORK/current.files"
while IFS= read -r file; do
  [ -f "$file" ] || continue
  mkdir -p "$WORK/current/$(dirname "$file")"
  cp "$file" "$WORK/current/$file"
done < "$WORK/current.files"

# BENCH_SOURCE=current: the base tree runs the working tree's bench_main.
if [ "$BENCH_SOURCE" = current ]; then
  cp tests/src/bench_main.adb "$WORK/base/tests/src/bench_main.adb" \
    || fail "could not copy tests/src/bench_main.adb into the base tree"
fi

for side in base current; do
  log="$WORK/$side.build.log"
  (cd "$WORK/$side/tests" && "$ALR" -n build) > "$log" 2>&1 || {
    tail -n 40 "$log"
    if [ "$side" = base ] && [ "$BENCH_SOURCE" = current ] \
       && grep -q 'bench_main\.adb:[0-9]' "$log"; then
      fail "the working tree's bench_main does not build against" \
           "$BASE_REF's tree (${log#"$ROOT"/}); BENCH_SOURCE=base runs" \
           "each side's own"
    fi
    fail "the $side build failed (${log#"$ROOT"/})"
  }
done

# Reads bench_main's output on standard input; prints "<label>|<MB/s>" for
# each line compared.
extract () {
  tr -d '\r' | awk '
    function size(n) {
      if (n == 64) return "64 B"
      if (n == 1024) return "1 KiB"
      if (n == 65536) return "64 KiB"
      if (n == 1048576) return "1 MiB"
      return n " B"
    }
    /^BLAKE2b-512, unkeyed, one-shot/ { section = "unkeyed one-shot"; next }
    /^BLAKE2b-512, keyed/ { section = "keyed one-shot"; next }
    /^BLAKE2b-512/ { section = ""; next }
    section != "" && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ {
      print section " " size($1 + 0) "|" $2
    }
    /^incremental, 1 MiB in .* updates: *[0-9]+ MB\/s$/ {
      label = $0
      sub(/^incremental, 1 MiB in /, "", label)
      sub(/ updates:.*/, "", label)
      print "incremental, " label " updates|" $(NF - 1)
    }'
}

# Runs side $1's bench_main once (pair $2), appending "<side>|<label>|<MB/s>"
# lines to the results.
run () {
  local side=$1 pair=$2 out="$WORK/$1-$2.out" lines
  "$WORK/$side/tests/bin/profile-profile/bench_main" > "$out" 2>&1 || {
    tr -d '\r' < "$out"
    fail "the $side bench_main failed (pair $pair)"
  }
  lines=$(extract < "$out")
  [ -n "$lines" ] || {
    tr -d '\r' < "$out"
    fail "the $side bench_main printed no line this script reads (pair $pair)"
  }
  awk -v p="$side|" '{ print p $0 }' <<< "$lines" >> "$WORK/results"
}

: > "$WORK/results"
start=$(date +%s)
for pair in $(seq 1 "$PAIRS"); do
  if [ $((pair % 2)) -eq 1 ]; then
    run base "$pair"
    run current "$pair"
  else
    run current "$pair"
    run base "$pair"
  fi
done
say "time: $(( $(date +%s) - start )) s"

awk -F'|' '
  {
    key = $1 SUBSEP $2
    n[key]++
    v[key, n[key]] = $3 + 0
    if (!(($1, $2) in side)) { side[$1, $2] = 1; order[$1, ++count[$1]] = $2 }
  }
  function sorted(key,    i, j, x) {
    for (i = 1; i <= n[key]; i++) s[i] = v[key, i]
    for (i = 2; i <= n[key]; i++) {
      x = s[i]
      for (j = i - 1; j >= 1 && s[j] > x; j--) s[j + 1] = s[j]
      s[j + 1] = x
    }
  }
  function median(key,    m) {
    sorted(key)
    m = n[key]
    lo = s[1]; hi = s[m]
    return (m % 2) ? s[(m + 1) / 2] : (s[m / 2] + s[m / 2 + 1]) / 2
  }
  END {
    # In the order the current side prints, then any line only the base
    # prints.
    for (i = 1; i <= count["current"]; i++)
      all[++labels] = order["current", i]
    for (i = 1; i <= count["base"]; i++)
      if (!(("current", order["base", i]) in side))
        all[++labels] = order["base", i]
    for (i = 1; i <= labels; i++) {
      label = all[i]
      if (!(("base", label) in side) || !(("current", label) in side)) {
        missing = missing (missing == "" ? "" : ", ") label \
          " (only in " ((("base", label) in side) ? "base" : "current") ")"
        continue
      }
      mb = median("base" SUBSEP label); blo = lo; bhi = hi
      mc = median("current" SUBSEP label); clo = lo; chi = hi
      bs = (mb > 0) ? 100 * (bhi - blo) / mb : 0
      cs = (mc > 0) ? 100 * (chi - clo) / mc : 0
      ratio = (mb > 0) ? mc / mb : 0
      note = ""
      if (bs > 10 || cs > 10) note = "; inconclusive (a spread over 10%)"
      else if (ratio < 0.95) note = "; more than 5% slower"
      printf "  %s: base %g (%g-%g, %.1f%%), current %g (%g-%g, %.1f%%)," \
             " current/base %.3f%s\n", label, mb, blo, bhi, bs, mc, clo, chi,
             cs, ratio, note
    }
    if (missing != "")
      print "bench-compare: not compared (printed by one side only): " missing
    else
      print "bench-compare: every line is printed by both sides"
  }' "$WORK/results"

say "reported, not gated: speed never changes the exit status"
exit 0
