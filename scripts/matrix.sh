#!/usr/bin/env bash
# Builds and runs the whole test suite in every cell of the build matrix:
#
#   optimisation  -O0 / -O2 / -O3
#   checks        off  (-gnatp: the release setting, justified by the proof)
#                 lang (every language check: overflow, range, index, ...)
#
# plus one cell with contracts enabled (-gnata), where every precondition,
# postcondition, loop invariant and assertion -- including folds of the
# executable specification -- runs. That cell is quadratic in input
# length, so it runs the small configuration, and it also checks that
# misuse is rejected.
#
# Every cell must pass. A miscompilation at one optimisation level, or a
# gap between what the proof covers and what the checks enforce, shows up
# as a failing cell.
#
# Usage: scripts/matrix.sh            (from anywhere in the crate)
#        ALR=/path/to/alr scripts/matrix.sh

set -euo pipefail

ALR=${ALR:-alr}
cd "$(dirname "$0")/../tests"

cells=(
  "O0 off" "O0 lang"
  "O2 off" "O2 lang"
  "O3 off" "O3 lang"
  "O0 contracts"
)

failed=()
for cell in "${cells[@]}"; do
  read -r opt checks <<< "$cell"
  echo "=================================================================="
  echo "cell: -$opt, checks=$checks"
  echo "=================================================================="
  "$ALR" -n build -- \
    "-XBLAKE2B_OPT=$opt" "-XBLAKE2B_CHECKS=$checks"

  set --
  if [ "$checks" = contracts ]; then
    set -- --small --contracts
  fi
  if "./bin/$opt-$checks/test_main" "$@"; then
    echo "cell -$opt/$checks: PASS"
  else
    echo "cell -$opt/$checks: FAIL"
    failed+=("-$opt/$checks")
  fi
done

echo
if [ "${#failed[@]}" -eq 0 ]; then
  echo "matrix: all ${#cells[@]} cells passed"
else
  echo "matrix: FAILED cells: ${failed[*]}"
  exit 1
fi
