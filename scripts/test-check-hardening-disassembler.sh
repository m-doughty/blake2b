#!/usr/bin/env bash
# Exercise the real hardening gate with GNU/LLVM disassembler fixtures.
# GNU AArch64 --show-all-symbols exposes ELF mapping symbols inside a
# function, whereas LLVM needs the option to expose Mach-O function aliases.
# The register requirements remain strict in both formats.

set -euo pipefail
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/scripts" "$tmp/mocks"
cp scripts/check-hardening.sh scripts/zeroed-at-return.awk "$tmp/scripts/"

cat > "$tmp/mocks/alr" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = -n ]; then shift; fi
case "$1" in
  build) exit 0 ;;
  exec)
    shift
    [ "$1" = -- ] && shift
    if [ "$1" = gcc ]; then
      if [ "${2:-}" = --version ]; then echo 'gcc mock hardening probe'; fi
      exit 0
    fi
    exec "$@" ;;
esac
exit 2
EOF

cat > "$tmp/mocks/nm" <<'EOF'
#!/usr/bin/env bash
for entry in digest_of init update final; do
  echo "0000000000000000 t blake2b__hashing__${entry}.strub.0"
done
echo '                 U blake2b__wipe__sanitize_words8'
echo '                 U blake2b__wipe__sanitize_block'
EOF

cat > "$tmp/mocks/objdump" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$MOCK_LOG"
case "$1" in
  --version)
    case "$MOCK_MODE" in
      llvm*) echo 'LLVM mock objdump' ;;
      *) echo 'GNU objdump mock 2.42' ;;
    esac
    exit 0 ;;
  --help)
    if [ "$MOCK_MODE" != llvm-unsupported ]; then echo '--show-all-symbols'; fi
    exit 0 ;;
esac
all=0
for arg in "$@"; do
  if [ "$arg" = --show-all-symbols ]; then all=1; fi
done
if [ "$MOCK_MODE" = llvm-unsupported ] && [ "$all" -eq 1 ]; then exit 2; fi
object=${!#}
emit () {
  local fn=$1
  if [ "$MOCK_MODE" = llvm ] && [ "$all" -eq 0 ]; then
    printf '0000000000000000 <ltmp0>:\n'
  elif [ "$MOCK_MODE" = llvm ]; then
    printf '0000000000000000 <ltmp0>:\n0000000000000000 <_%s>:\n' "$fn"
  else
    printf '0000000000000000 <%s>:\n' "$fn"
  fi
  if [ "$MOCK_MODE" = gnu-probe-failure ] && [ "$fn" = blake2b_hardening_probe ]; then
    printf '   0:\tret\n'
    return
  fi
  printf '   0:\tmov\tx0, #0x0\n'
  if [[ "$MOCK_MODE" = gnu* ]] && [ "$all" -eq 1 ]; then
    printf '\n0000000000000004 <$d>:\n'
  fi
  if [ "$MOCK_MODE" != gnu-missing-register ] || [ "$fn" != blake2b__hashing__final ]; then
    printf '   4:\tmovi\tv0.2d, #0x0\n'
  fi
  printf '   8:\tret\n'
}
if [[ "$object" = */probe.o ]]; then
  emit blake2b_hardening_probe
else
  for entry in init update final digest_of.strub.0; do
    emit "blake2b__hashing__$entry"
  done
fi
EOF
chmod +x "$tmp/mocks/alr" "$tmp/mocks/nm" "$tmp/mocks/objdump"

pass=0
for mode in gnu llvm llvm-unsupported gnu-missing-register gnu-probe-failure; do
  export MOCK_MODE=$mode MOCK_LOG="$tmp/$mode.commands"
  status=0
  ALR="$tmp/mocks/alr" NM="$tmp/mocks/nm" OBJDUMP="$tmp/mocks/objdump" \
    bash "$tmp/scripts/check-hardening.sh" > "$tmp/$mode.log" 2>&1 || status=$?
  case "$mode" in
    gnu|llvm|llvm-unsupported)
      if [ "$status" -ne 0 ]; then cat "$tmp/$mode.log"; exit 1; fi
      grep -q 'hardening: present' "$tmp/$mode.log" ;;
    gnu-missing-register)
      [ "$status" -ne 0 ]
      grep -q 'NOT cleared on return from final: v0' "$tmp/$mode.log" ;;
    gnu-probe-failure)
      [ "$status" -ne 0 ]
      grep -q 'could not measure the registers' "$tmp/$mode.log"
      grep -q 'gcc mock hardening probe' "$tmp/$mode.log"
      grep -q 'GNU objdump mock 2.42' "$tmp/$mode.log"
      grep -q '<blake2b_hardening_probe>:' "$tmp/$mode.log" ;;
  esac
  if [ "$mode" = llvm ]; then
    [ "$(grep -c -- '--show-all-symbols' "$MOCK_LOG")" -eq 2 ]
  elif grep -q -- '--show-all-symbols' "$MOCK_LOG"; then
    echo "FAILED: unexpected --show-all-symbols for $mode"
    exit 1
  fi
  pass=$((pass + 1))
done

echo "hardening disassembler: $pass passed, 0 failed"
