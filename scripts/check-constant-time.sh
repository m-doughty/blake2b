#!/usr/bin/env bash
# Linux x86-64 Memcheck gate. Both builds run without Valgrind suppressions;
# the hardened report permits only scrub instructions verified in disassembly.
# All source copies, binaries and evidence stay under obj/constant-time/.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ALR=${ALR:-alr}
VALGRIND=${VALGRIND:-valgrind}
PYTHON=${PYTHON:-python3}
OBJDUMP=${OBJDUMP:-objdump}

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
  echo "constant-time gate requires Linux x86-64" >&2
  exit 1
fi
for tool in "$ALR" "$VALGRIND" "$PYTHON" "$OBJDUMP"; do
  command -v "$tool" >/dev/null || {
    echo "required tool unavailable: $tool" >&2
    exit 1
  }
done

WORK="$ROOT/obj/constant-time"
mkdir -p "$WORK"
# Prevent concurrent invocations from replacing each other's evidence.
if ! mkdir "$WORK/.running" 2>/dev/null; then
  echo "constant-time gate already running (lock: $WORK/.running)" >&2
  exit 1
fi
trap 'rmdir "$WORK/.running"' EXIT

copy_crate () {
  local dest=$1
  # dest is a fixed path under this gate's artifact directory.
  rm -rf "$dest"
  mkdir -p "$dest/tests/ct"
  cp -r "$ROOT/src" "$ROOT/alire.toml" "$ROOT/blake2b.gpr" "$dest/"
  cp -r "$ROOT/tests/src" "$ROOT/tests/ref" "$ROOT/tests/data" \
        "$ROOT/tests/alire.toml" "$ROOT/tests/blake2b_tests.gpr" \
        "$dest/tests/"
  cp "$ROOT/tests/ct/ct.gpr" "$ROOT/tests/ct/ct_main.adb" \
     "$ROOT/tests/ct/ct_shim.c" "$dest/tests/ct/"
}

failed=0
for mode in plain hardened; do
  dest="$WORK/$mode"
  copy_crate "$dest"
  logs="$dest/logs"
  mkdir -p "$logs"
  echo "constant-time: building $mode (logs: $logs)"
  if ! (cd "$dest/tests" && "$ALR" -n build) > "$logs/dependencies.log" 2>&1; then
    cat "$logs/dependencies.log" >&2
    exit 1
  fi
  extra=()
  if [ "$mode" = plain ]; then
    extra=(-cargs:Ada -fstrub=disable)
  fi
  # -f rebuilds the imported library too. Plain and hardened outputs never
  # share a directory, and neither can replace a production-build object.
  if ! (cd "$dest/tests" && "$ALR" -n exec -- gprbuild -P ct/ct.gpr \
      -XBLAKE2B_OPT=O3 -XBLAKE2B_CHECKS=off -f \
      "${extra[@]}") > "$logs/build.log" 2>&1; then
    cat "$logs/build.log" >&2
    exit 1
  fi
  binary="$dest/tests/ct/bin/ct_main"
  "$OBJDUMP" -d --no-show-raw-insn "$binary" > "$logs/disassembly.txt"

  for control in clean negative; do
    args=()
    checker_args=()
    if [ "$control" = negative ]; then
      args=(--negative-control)
      checker_args=(--expect-secret-branch)
    fi
    xml="$logs/$control.xml"
    echo "constant-time: $mode $control"
    status=0
    "$VALGRIND" --command-line-only=yes --default-suppressions=no --demangle=no \
      --xml=yes --xml-file="$xml" --error-exitcode=99 \
      --track-origins=yes --error-limit=no "$binary" "${args[@]}" \
      > "$logs/$control.log" 2>&1 || status=$?
    printf '%s\n' "$status" > "$logs/$control.exit-status"
    if [ "$status" -ne 0 ] && [ "$status" -ne 99 ]; then
      echo "Valgrind/harness failed with unexpected exit status $status" >&2
      failed=1
      continue
    fi
    # Memcheck's exit must agree with its XML in both directions. Invalid/
    # truncated XML and unknown error kinds are also rejected by checker.
    if ! "$PYTHON" -c \
      'import sys, xml.etree.ElementTree as E; errors = bool(E.parse(sys.argv[1]).getroot().findall("error")); sys.exit(errors != (sys.argv[2] == "99"))' \
      "$xml" "$status"; then
      echo "Valgrind exit status disagrees with XML, or XML is invalid" >&2
      failed=1
      continue
    fi
    if ! "$PYTHON" "$ROOT/scripts/ct-valgrind.py" --xml "$xml" \
        --disassembly "$logs/disassembly.txt" --binary "$binary" \
        --mode "$mode" "${checker_args[@]}" \
        > "$logs/$control.check.log" 2>&1; then
      failed=1
    fi
    cat "$logs/$control.check.log"
  done
done
if [ "$failed" -ne 0 ]; then
  echo "constant-time gate FAILED (evidence: $WORK)" >&2
  exit 1
fi
echo "constant-time gate passed: both builds and both negative controls"
