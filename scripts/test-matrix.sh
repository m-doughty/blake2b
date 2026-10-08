#!/usr/bin/env bash
# Exercise the real matrix with mock builds and tests, including Bash 3.2's
# nounset handling of an empty argument list.
#
# Usage: scripts/test-matrix.sh
#        TEST_BASH=/path/to/bash scripts/test-matrix.sh

set -euo pipefail
cd "$(dirname "$0")/.."
TEST_BASH=${TEST_BASH:-/bin/bash}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/scripts" "$tmp/tests" "$tmp/mocks"
cp scripts/matrix.sh "$tmp/scripts/"

cat > "$tmp/mocks/alr" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "$#" -eq 5 ]
[ "$1" = -n ]
[ "$2" = build ]
[ "$3" = -- ]
printf '%s\n' "$*" >> "$MOCK_DIR/builds"
opt=${4#-XBLAKE2B_OPT=}
checks=${5#-XBLAKE2B_CHECKS=}
cell=$opt-$checks
if [ "$cell" = "${MOCK_BUILD_FAIL:-}" ]; then exit 23; fi
mkdir -p "bin/$cell"
cp "$MOCK_TEST_MAIN" "bin/$cell/test_main"
EOF

cat > "$tmp/mocks/test_main" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cell=$(basename "$(dirname "$0")")
printf '%s|%s|%s\n' "$cell" "$#" "$*" >> "$MOCK_DIR/tests"
if [ "$cell" = "${MOCK_TEST_FAIL:-}" ]; then exit 17; fi
EOF
chmod +x "$tmp/mocks/alr" "$tmp/mocks/test_main"

cat > "$tmp/cells" <<'EOF'
O0 off
O0 lang
O2 off
O2 lang
O3 off
O3 lang
O0 contracts
EOF

while read -r opt checks; do
  printf '%s\n' "-n build -- -XBLAKE2B_OPT=$opt -XBLAKE2B_CHECKS=$checks" \
    >> "$tmp/expected-builds"
  if [ "$checks" = contracts ]; then
    printf '%s\n' "$opt-$checks|2|--small --contracts"
  else
    printf '%s\n' "$opt-$checks|0|"
  fi >> "$tmp/expected-tests"
done < "$tmp/cells"

pass=0
for mode in pass test-failure build-failure; do
  export MOCK_DIR="$tmp/$mode" MOCK_TEST_MAIN="$tmp/mocks/test_main"
  export MOCK_BUILD_FAIL= MOCK_TEST_FAIL=
  mkdir -p "$MOCK_DIR"
  case "$mode" in
    test-failure) MOCK_TEST_FAIL=O2-lang ;;
    build-failure) MOCK_BUILD_FAIL=O2-off ;;
  esac
  status=0
  ALR="$tmp/mocks/alr" "$TEST_BASH" "$tmp/scripts/matrix.sh" \
    > "$MOCK_DIR/output" 2>&1 || status=$?
  case "$mode" in
    pass)
      if [ "$status" -ne 0 ]; then cat "$MOCK_DIR/output"; exit 1; fi
      grep -q '^matrix: all 7 cells passed$' "$MOCK_DIR/output"
      [ "$(grep -c '^cell .*: PASS$' "$MOCK_DIR/output")" -eq 7 ] ;;
    test-failure)
      [ "$status" -eq 1 ]
      grep -q '^cell -O2/lang: FAIL$' "$MOCK_DIR/output"
      grep -q '^matrix: FAILED cells: -O2/lang$' "$MOCK_DIR/output"
      [ "$(grep -c '^cell .*: PASS$' "$MOCK_DIR/output")" -eq 6 ]
      [ "$(grep -c '^cell .*: FAIL$' "$MOCK_DIR/output")" -eq 1 ] ;;
    build-failure)
      [ "$status" -eq 23 ]
      head -n 3 "$tmp/expected-builds" > "$MOCK_DIR/expected-builds"
      head -n 2 "$tmp/expected-tests" > "$MOCK_DIR/expected-tests"
      diff -u "$MOCK_DIR/expected-builds" "$MOCK_DIR/builds"
      diff -u "$MOCK_DIR/expected-tests" "$MOCK_DIR/tests"
      [ "$(grep -c '^cell .*: PASS$' "$MOCK_DIR/output")" -eq 2 ]
      if grep -q '^matrix:' "$MOCK_DIR/output"; then
        echo 'FAILED: matrix continued after a build failure'
        exit 1
      fi ;;
  esac
  if [ "$mode" != build-failure ]; then
    diff -u "$tmp/expected-builds" "$MOCK_DIR/builds"
    diff -u "$tmp/expected-tests" "$MOCK_DIR/tests"
  fi
  pass=$((pass + 1))
done

echo "matrix: $pass passed, 0 failed"
