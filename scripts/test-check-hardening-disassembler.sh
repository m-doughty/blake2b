#!/usr/bin/env bash
# Exercise the real hardening gate with GNU/LLVM disassembler fixtures.
# GNU AArch64 --show-all-symbols exposes ELF mapping symbols inside a
# function, whereas LLVM needs the option to expose Mach-O function aliases.
# The register requirements remain strict in both formats. The mocks also
# show that the gate reads Mach-O's underscored symbol names, and fails by
# name on a helper or a compression function left out of line, on an
# uncleared return in a cold part (of a wrapper, or of Digest_Of's clone,
# whose returns are checked too), on a cold part that jumps back into its
# function, on a wrapper that tail-jumps to a helper (seen only in the
# relocation record after the jump), on a jump whose record names its own
# function (its real target is past the clearing), on an indirect jump in
# a clone or in a cold part with no return, on a call through a register
# or memory in a clone (AArch64 blr) or a cold part (x86-64, through a GOT
# slot whose record names a symbol), on a clone's jump into its
# wrapper's cold section, on a cold part or a clone that runs off its end,
# on a reference outside the allowed classes, and on a probe compiler that
# is not GCC. A jump from a function into its own cold part or its own
# cold section passes, as do a function that ends in a call (to a routine
# that does not return) and nop padding after the last instruction.
# The C library fails by the routine's name in every spelling a toolchain
# gives it (memcpy, Mach-O's _memcpy, __memcpy_chk, memmove@plt,
# memset@GLIBC_2.2.5, __imp_memcpy, __imp__memset), and as an undefined
# weak reference (nm's w and v; a weak definition, W or V, is no
# reference), as does a call to
# Initial_H, or a definition of it in blake2b-core.o; a reference to the
# constant table IV passes. The wipe
# routines pass as the frameless leaves GCC compiles today, and fail by
# name, with the instruction, on an AArch64 frame record, an x86-64 push
# and stack adjustment, a call (direct, or through a register), a tail
# jump, or a routine missing from blake2b-wipe.o; a call to any other
# routine of Blake2b.Wipe, one not checked frameless, fails by name.

set -euo pipefail
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/scripts" "$tmp/mocks" "$tmp/src" \
  "$tmp/obj/release-profile-profile"
cp scripts/check-hardening.sh scripts/zeroed-at-return.awk "$tmp/scripts/"
# The gate reads the entry points' attributes from these two sources.
cp src/blake2b-hashing.ads src/blake2b-hashing.adb "$tmp/src/"
: > "$tmp/obj/release-profile-profile/blake2b-hashing.o"
: > "$tmp/obj/release-profile-profile/blake2b-core.o"
: > "$tmp/obj/release-profile-profile/blake2b-hashing-counter_arithmetic.o"
: > "$tmp/obj/release-profile-profile/blake2b-wipe.o"

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
      case "${2:-}" in
        --version) echo 'gcc mock hardening probe' ;;
        -v)
          if [ "$MOCK_MODE" = gnu-not-gcc ]; then
            echo 'Apple clang version 17.0.0 (mock)' >&2
          else
            echo 'gcc version 16.1.0 (mock)' >&2
          fi ;;
      esac
      exit 0
    fi
    exec "$@" ;;
esac
exit 2
EOF

cat > "$tmp/mocks/nm" <<'EOF'
#!/usr/bin/env bash
# Mach-O names carry a leading underscore.
p=''
case "$MOCK_MODE" in llvm*) p=_ ;; esac
case "$1" in
  */blake2b-hashing.o)
    for entry in init update final; do
      echo "0000000000000000 T ${p}blake2b__hashing__${entry}"
    done
    for entry in digest_of init update final; do
      echo "0000000000000000 t ${p}blake2b__hashing__${entry}.strub.0"
    done
    for fn in hash hash__2 clear is_empty valid stateIP statePartial_DIC; do
      echo "0000000000000000 T ${p}blake2b__hashing__${fn}"
    done
    echo "0000000000000000 t ${p}blake2b__hashing__statePartial_DIC.constprop.0"
    echo "0000000000000000 t ltmp0"
    echo "0000000000000000 t .text\$blake2b__hashing__init"
    echo "0000000000000000 D ${p}blake2b__hashing_E"
    case "$MOCK_MODE" in
      gnu-stray-helper)
        echo "0000000000000000 t ${p}blake2b__hashing__add_counter"
        echo "0000000000000000 t ${p}blake2b__hashing__update.part.0" ;;
      gnu-core-compress)
        echo "                 U ${p}blake2b__core__compress" ;;
      gnu-core-helper)
        echo "                 U ${p}blake2b__core__load_words" ;;
      gnu-clone-cold-dirty)
        echo "0000000000000000 t ${p}blake2b__hashing__digest_of.strub.0.cold" ;;
      gnu-cold*)
        echo "0000000000000000 t ${p}blake2b__hashing__final.cold"
        echo "0000000000000000 t ${p}blake2b__hashing__update.strub.0.cold" ;;
      # Not in the default output: a reference outside the allowed
      # classes fails the gate (it was listed, not checked, before).
      gnu-other-reference)
        echo "                 U ${p}abort_mock" ;;
      # Initial_H called out of line (it is Inline_Always).
      gnu-core-initial-h)
        echo "                 U ${p}blake2b__core__initial_h" ;;
      # The C library, in each spelling a toolchain gives it.
      gnu-libc-memcpy)
        echo "                 U memcpy" ;;
      gnu-libc-underscore)
        echo "                 U _memcpy" ;;
      gnu-libc-chk)
        echo "                 U __memcpy_chk" ;;
      gnu-libc-plt)
        echo "                 U memmove@plt" ;;
      gnu-libc-version)
        echo "                 U memset@GLIBC_2.2.5" ;;
      gnu-libc-imp)
        echo "                 U __imp_memcpy" ;;
      gnu-libc-imp-underscore)
        echo "                 U __imp__memset" ;;
      # Mach-O: the underscore every symbol carries, on a plain name and
      # on a fortified one.
      llvm-libc)
        echo "                 U ${p}memcpy"
        echo "                 U ${p}__memmove_chk" ;;
      # Undefined weak references (w, v: no address) are references; a
      # weak definition (V: an address) is not.
      gnu-libc-weak)
        echo "                 w memcpy"
        echo "                 v memset"
        echo "0000000000000000 V blake2b__hashing__weak_object" ;;
      # A function defined weak (W) is out of line like a strong one.
      gnu-weak-helper)
        echo "0000000000000000 W ${p}blake2b__hashing__fill_block" ;;
      # A wipe routine that is not one of the two checked frameless.
      gnu-wipe-other)
        echo "                 U ${p}blake2b__wipe__sanitize_bytes" ;;
    esac
    # IV is read in place by the inlined Initial_H (allowed: public data).
    echo "                 U ${p}blake2b__core__iv"
    echo "                 U ${p}blake2b__wipe__sanitize_words8"
    echo "                 U ${p}blake2b__wipe__sanitize_block"
    echo "                 U ${p}_Unwind_Resume" ;;
  */blake2b-core.o)
    for fn in load64 out_byte TscheduleBIP; do
      echo "0000000000000000 T ${p}blake2b__core__${fn}"
    done
    if [ "$MOCK_MODE" = gnu-core-compress ]; then
      echo "0000000000000000 T ${p}blake2b__core__compress"
    fi
    # Initial_H (Inline_Always) left out of line, as it is called.
    if [ "$MOCK_MODE" = gnu-core-initial-h ]; then
      echo "0000000000000000 T ${p}blake2b__core__initial_h"
    fi ;;
  */blake2b-hashing-counter_arithmetic.o)
    echo "0000000000000000 D ${p}blake2b__hashing__counter_arithmetic_E"
    echo "0000000000000000 t ltmp0"
    # Add_Counter left out of line, and a clone of it.
    if [ "$MOCK_MODE" = gnu-counter-out-of-line ]; then
      echo "0000000000000000 T ${p}blake2b__hashing__counter_arithmetic__add_counter"
      echo "0000000000000000 t ${p}blake2b__hashing__counter_arithmetic__add_counter.constprop.0"
    fi ;;
  *)  # every release object, for the big-integer check
    echo "0000000000000000 T ${p}blake2b__hashing__init" ;;
esac
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
# LLVM's headers (Mach-O: the underscore, the section-start alias).
llvm=0
case "$MOCK_MODE" in llvm|llvm-libc) llvm=1 ;; esac
header () {
  if [ "$llvm" -eq 1 ] && [ "$all" -eq 0 ]; then
    printf '0000000000000000 <ltmp0>:\n'
  elif [ "$llvm" -eq 1 ]; then
    printf '0000000000000000 <ltmp0>:\n0000000000000000 <_%s>:\n' "$1"
  else
    printf '0000000000000000 <%s>:\n' "$1"
  fi
}
# A wipe routine: by default the frameless leaf GCC compiles today (stores
# of a zeroed register through the argument, a return).
emit_wipe () {
  local fn=$1
  header "$fn"
  case "$MOCK_MODE:$fn" in
    # AArch64: a frame record pushed and popped around the stores.
    gnu-wipe-frame-aarch64:blake2b__wipe__sanitize_words8)
      printf '   0:\tstp\tx29, x30, [sp, #-16]!\n'
      printf '   4:\tmov\tx29, sp\n'
      printf '   8:\tmovi\tv31.4s, #0x0\n'
      printf '   c:\tstp\tq31, q31, [x0]\n'
      printf '  10:\tldp\tx29, x30, [sp], #16\n'
      printf '  14:\tret\n' ;;
    # x86-64: a pushed frame pointer and a stack adjustment.
    gnu-wipe-frame-x86:blake2b__wipe__sanitize_block)
      printf '   0:\tpush   %%rbp\n'
      printf '   1:\tsub    $0x18,%%rsp\n'
      printf '   5:\tpxor   %%xmm0,%%xmm0\n'
      printf '   9:\tmovups %%xmm0,(%%rdi)\n'
      printf '   c:\tadd    $0x18,%%rsp\n'
      printf '  10:\tpop    %%rbp\n'
      printf '  11:\tret\n' ;;
    # A call out (to memset, through its relocation record).
    gnu-wipe-call:blake2b__wipe__sanitize_block)
      printf '   0:\tmov\tx2, #0x80\n'
      printf '   4:\tmov\tw1, #0x0\n'
      printf '   8:\tbl\t8 <blake2b__wipe__sanitize_block+0x8>\n'
      printf '\t\t\t8: R_AARCH64_CALL26\tmemset\n'
      printf '   c:\tret\n' ;;
    # A call through a register (its target not known).
    gnu-wipe-indirect-call:blake2b__wipe__sanitize_block)
      printf '   0:\tmovi\tv31.4s, #0x0\n'
      printf '   4:\tblr\tx8\n'
      printf '   8:\tstp\tq31, q31, [x0]\n'
      printf '   c:\tret\n' ;;
    # A tail jump to memset, seen only in the record.
    gnu-wipe-tail-jump:blake2b__wipe__sanitize_words8)
      printf '   0:\tmov\tx2, #0x40\n'
      printf '   4:\tmov\tw1, #0x0\n'
      printf '   8:\tb\t8 <blake2b__wipe__sanitize_words8+0x8>\n'
      printf '\t\t\t8: R_AARCH64_JUMP26\tmemset\n' ;;
    *)
      printf '   0:\tmovi\tv31.4s, #0x0\n'
      printf '   4:\tstp\tq31, q31, [x0]\n'
      printf '   8:\tstp\tq31, q31, [x0, #32]\n'
      printf '   c:\tret\n' ;;
  esac
}
emit () {
  local fn=$1
  header "$fn"
  if [ "$MOCK_MODE" = gnu-probe-failure ] && [ "$fn" = blake2b_hardening_probe ]; then
    printf '   0:\tret\n'
    return
  fi
  if [ "$MOCK_MODE" = gnu-cold-dirty ] && [ "$fn" = blake2b__hashing__final.cold ]; then
    printf '   0:\tmov\tx0, #0x0\n   4:\tret\n'
    return
  fi
  # A cold part that jumps back into its function, past the clearing.
  if [ "$MOCK_MODE" = gnu-cold-rejoin ] && [ "$fn" = blake2b__hashing__final.cold ]; then
    printf '   0:\tmov\tx0, #0x0\n   4:\tb\t8 <blake2b__hashing__final+0x8>\n'
    return
  fi
  # A cold part that leaves by an indirect jump (no return, no symbol).
  if [ "$MOCK_MODE" = gnu-cold-indirect ] && [ "$fn" = blake2b__hashing__final.cold ]; then
    printf '   0:\tmov\tx0, #0x0\n   4:\tbr\tx1\n'
    return
  fi
  # A clone that consists of an indirect jump.
  if [ "$MOCK_MODE" = gnu-clone-indirect ] && [ "$fn" = blake2b__hashing__update.strub.0 ]; then
    printf '   0:\tbr\tx1\n'
    return
  fi
  # A clone that calls through a register (AArch64), then returns.
  if [ "$MOCK_MODE" = gnu-clone-indirect-call ] && [ "$fn" = blake2b__hashing__update.strub.0 ]; then
    printf '   0:\tblr\tx8\n'
    printf '   4:\tmov\tx0, #0x0\n   8:\tmovi\tv0.2d, #0x0\n   c:\tret\n'
    return
  fi
  # An x86-64 cold part that calls through a GOT slot (memory-indirect: the
  # record names the slot's symbol, not the target), as GCC would with
  # -fno-plt, then traps.
  if [ "$MOCK_MODE" = gnu-cold-indirect-call ] && [ "$fn" = blake2b__hashing__final.cold ]; then
    printf '   0:\tcall   *0x0(%%rip)        # 6 <blake2b__hashing__final.cold+0x6>\n'
    printf '\t\t\t2: R_X86_64_GOTPCRELX\t__gnat_rcheck-0x4\n'
    printf '   6:\tud2\n'
    return
  fi
  # A returning cold part of Digest_Of's clone, whose returns are checked
  # (its wrapper is inlined into Hash), that does not clear the registers.
  if [ "$fn" = blake2b__hashing__digest_of.strub.0.cold ]; then
    printf '   0:\tmov\tx0, #0x2a\n   4:\tret\n'
    return
  fi
  # A jump whose record names the function itself: the placeholder targets
  # the function's start, but the real target (the addend) is the return,
  # past the clearing.
  if [ "$MOCK_MODE" = gnu-self-reloc ] && [ "$fn" = blake2b__hashing__final ]; then
    printf '   0:\tcbz\tx1, 0 <blake2b__hashing__final>\n'
    printf '\t\t\t0: R_AARCH64_CONDBR19\tblake2b__hashing__final+0xc\n'
    printf '   4:\tmov\tx0, #0x0\n   8:\tmovi\tv0.2d, #0x0\n   c:\tret\n'
    return
  fi
  # A cold part that runs off its end into whatever follows it.
  if [ "$MOCK_MODE" = gnu-cold-falls-through ] && [ "$fn" = blake2b__hashing__final.cold ]; then
    printf '   0:\tmov\tx0, #0x2a\n'
    return
  fi
  if [ "$fn" = blake2b__hashing__update.strub.0.cold ]; then
    printf '   0:\tbl\t0 <__gnat_rcheck>\n'
    return
  fi
  # Set when a conditional branch follows the return: a call to a routine
  # that does not return then ends the function, as in GCC's code.
  local raise=0
  printf '   0:\tmov\tx0, #0x0\n'
  if [[ "$MOCK_MODE" = gnu* ]] && [ "$all" -eq 1 ]; then
    printf '\n0000000000000004 <$d>:\n'
  fi
  if [ "$MOCK_MODE" != gnu-missing-register ] || [ "$fn" != blake2b__hashing__final ]; then
    printf '   4:\tmovi\tv0.2d, #0x0\n'
  fi
  printf '   8:\tret\n'
  # A jump into the function's own cold part (allowed).
  if [[ "$MOCK_MODE" = gnu-cold* ]] && [ "$fn" = blake2b__hashing__final ]; then
    case "$MOCK_MODE" in
      # An object file: the cold section is reached through its section
      # symbol (the record), not through the cold part's own name.
      gnu-cold-section)
        printf '   c:\tcbz\tx1, c <blake2b__hashing__final+0xc>\n'
        printf '\t\t\tc: R_AARCH64_CONDBR19\t.text.unlikely.blake2b__hashing__final+0x4\n' ;;
      # The same jump into the hot section of the function (not allowed).
      gnu-cold-hot-section)
        printf '   c:\tcbz\tx1, c <blake2b__hashing__final+0xc>\n'
        printf '\t\t\tc: R_AARCH64_CONDBR19\t.text.blake2b__hashing__final+0x4\n' ;;
      *) printf '   c:\tcbz\tx1, 0 <blake2b__hashing__final.cold>\n' ;;
    esac
    raise=1
  fi
  # A clone's jumps, in an object file, into its own cold section
  # (allowed) and into its wrapper's (not allowed: only the function's own
  # section is its cold part).
  if [ "$MOCK_MODE" = gnu-clone-cold-section ] && [ "$fn" = blake2b__hashing__final.strub.0 ]; then
    printf '   c:\tcbz\tx1, c <blake2b__hashing__final.strub.0+0xc>\n'
    printf '\t\t\tc: R_AARCH64_CONDBR19\t.text.unlikely.blake2b__hashing__final.strub.0+0x4\n'
    printf '  10:\tcbz\tx2, 10 <blake2b__hashing__final.strub.0+0x10>\n'
    printf '\t\t\t10: R_AARCH64_CONDBR19\t.text.unlikely.blake2b__hashing__final+0x4\n'
    raise=1
  fi
  # A jump from Digest_Of's clone into its own cold part (allowed).
  if [ "$MOCK_MODE" = gnu-clone-cold-dirty ] && [ "$fn" = blake2b__hashing__digest_of.strub.0 ]; then
    printf '   c:\tcbz\tx1, 0 <blake2b__hashing__digest_of.strub.0.cold>\n'
    raise=1
  fi
  # A tail jump to a helper, in an object file: the placeholder targets
  # the jump itself; the relocation record names the helper.
  if [ "$MOCK_MODE" = gnu-tail-jump ] && [ "$fn" = blake2b__hashing__update ]; then
    printf '   c:\tb\tc <blake2b__hashing__update+0xc>\n'
    printf '\t\t\tc: R_AARCH64_JUMP26\tblake2b__hashing__helper\n'
  fi
  # A clone whose last instruction is a conditional branch: it runs off
  # its end when the branch is not taken.
  if [ "$MOCK_MODE" = gnu-cold-falls-through ] && [ "$fn" = blake2b__hashing__update.strub.0 ]; then
    printf '   c:\tb.ne\t0 <blake2b__hashing__update.strub.0>\n'
  fi
  if [ "$raise" -eq 1 ]; then
    printf '  20:\tbl\t0 <__gnat_rcheck>\n'
  fi
  # Alignment padding, after the last instruction (allowed).
  printf '  24:\tnop\n  28:\tnop\n'
}
if [[ "$object" = */probe.o ]]; then
  emit blake2b_hardening_probe
elif [[ "$object" = */blake2b-wipe.o ]]; then
  emit_wipe blake2b__wipe__sanitize_words8
  # Sanitize_Block missing from the object.
  if [ "$MOCK_MODE" != gnu-wipe-missing ]; then
    emit_wipe blake2b__wipe__sanitize_block
  fi
else
  for entry in init update final init.strub.0 update.strub.0 final.strub.0 \
               digest_of.strub.0; do
    emit "blake2b__hashing__$entry"
  done
  case "$MOCK_MODE" in
    gnu-clone-cold-dirty)
      emit blake2b__hashing__digest_of.strub.0.cold ;;
    gnu-cold*)
      emit blake2b__hashing__final.cold
      emit blake2b__hashing__update.strub.0.cold ;;
  esac
fi
EOF
chmod +x "$tmp/mocks/alr" "$tmp/mocks/nm" "$tmp/mocks/objdump"

pass=0
for mode in gnu llvm llvm-unsupported gnu-missing-register gnu-probe-failure \
            gnu-not-gcc gnu-stray-helper gnu-core-compress gnu-core-helper \
            gnu-cold gnu-cold-section gnu-cold-hot-section gnu-cold-dirty \
            gnu-cold-rejoin gnu-tail-jump gnu-clone-cold-dirty \
            gnu-self-reloc gnu-cold-indirect gnu-clone-indirect \
            gnu-clone-cold-section gnu-cold-falls-through \
            gnu-other-reference gnu-counter-out-of-line gnu-core-initial-h \
            gnu-libc-memcpy gnu-libc-underscore gnu-libc-chk gnu-libc-plt \
            gnu-libc-version gnu-libc-imp gnu-libc-imp-underscore llvm-libc \
            gnu-wipe-frame-aarch64 gnu-wipe-frame-x86 gnu-wipe-call \
            gnu-wipe-tail-jump gnu-wipe-missing gnu-wipe-other \
            gnu-libc-weak gnu-clone-indirect-call gnu-cold-indirect-call \
            gnu-wipe-indirect-call gnu-weak-helper; do
  export MOCK_MODE=$mode MOCK_LOG="$tmp/$mode.commands"
  status=0
  ALR="$tmp/mocks/alr" NM="$tmp/mocks/nm" OBJDUMP="$tmp/mocks/objdump" \
    bash "$tmp/scripts/check-hardening.sh" > "$tmp/$mode.log" 2>&1 || status=$?
  ok=1
  case "$mode" in
    gnu|llvm|llvm-unsupported)
      [ "$status" -eq 0 ] || ok=0
      grep -q '^hardening: present$' "$tmp/$mode.log" || ok=0
      grep -q '^references to Blake2b.Core constant tables (IV, Sigma): blake2b__core__iv$' \
        "$tmp/$mode.log" || ok=0
      grep -q '^wipe routines are frameless leaves: sanitize_words8 sanitize_block$' \
        "$tmp/$mode.log" || ok=0
      ! grep -q 'C library' "$tmp/$mode.log" || ok=0
      grep -q '^jumps out of .* (allowed): none$' "$tmp/$mode.log" || ok=0
      grep -q '^no call through a register or memory in ' "$tmp/$mode.log" || ok=0 ;;
    # Initial_H is Inline_Always: a call to it fails by name.
    gnu-core-initial-h)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^NOT inlined: blake2b-hashing.o calls Blake2b.Core.Initial_H out of line .*: blake2b__core__initial_h$' \
        "$tmp/$mode.log" || ok=0
      grep -q '^NOT inlined: blake2b-core.o defines blake2b__core__initial_h (Initial_H is Inline_Always; .*: blake2b__core__initial_h$' \
        "$tmp/$mode.log" || ok=0
      ! grep -q 'outside the expected set' "$tmp/$mode.log" || ok=0 ;;
    # The C library, in each spelling: each fails by the routine's name
    # (and the spelling, when it differs), never as an unclassified
    # reference.
    gnu-libc-*|llvm-libc)
      case "$mode" in
        gnu-libc-memcpy) want=('memcpy') ;;
        gnu-libc-underscore) want=('memcpy (as _memcpy)') ;;
        gnu-libc-chk) want=('memcpy (as __memcpy_chk)') ;;
        gnu-libc-plt) want=('memmove (as memmove@plt)') ;;
        gnu-libc-version) want=('memset (as memset@GLIBC_2.2.5)') ;;
        gnu-libc-imp) want=('memcpy (as __imp_memcpy)') ;;
        gnu-libc-imp-underscore) want=('memset (as __imp__memset)') ;;
        llvm-libc) want=('memcpy' 'memmove (as __memmove_chk)') ;;
        gnu-libc-weak) want=('memcpy' 'memset') ;;
      esac
      [ "$status" -eq 1 ] || ok=0
      for routine in "${want[@]}"; do
        grep -qxF "NOT allowed: blake2b-hashing.o calls the C library (outside the scrubbed frame): $routine" \
          "$tmp/$mode.log" || ok=0
      done
      [ "$(grep -c 'C library' "$tmp/$mode.log")" -eq "${#want[@]}" ] || ok=0
      ! grep -q 'outside the classes above' "$tmp/$mode.log" || ok=0 ;;
    # The wipe routines must be frameless leaves: each failure names the
    # routine and the instruction; the other routine still passes.
    gnu-wipe-frame-aarch64)
      [ "$status" -eq 1 ] || ok=0
      grep -qxF 'NOT a frameless leaf: sanitize_words8 uses the stack: stp x29, x30, [sp, #-16]!' \
        "$tmp/$mode.log" || ok=0
      grep -qxF 'NOT a frameless leaf: sanitize_words8 uses the stack: mov x29, sp' \
        "$tmp/$mode.log" || ok=0
      grep -qxF 'NOT a frameless leaf: sanitize_words8 uses the stack: ldp x29, x30, [sp], #16' \
        "$tmp/$mode.log" || ok=0
      ! grep -q 'frameless.*sanitize_block' "$tmp/$mode.log" || ok=0 ;;
    gnu-wipe-frame-x86)
      [ "$status" -eq 1 ] || ok=0
      grep -qxF 'NOT a frameless leaf: sanitize_block uses the stack: push %rbp' \
        "$tmp/$mode.log" || ok=0
      grep -qxF 'NOT a frameless leaf: sanitize_block uses the stack: sub $0x18,%rsp' \
        "$tmp/$mode.log" || ok=0
      grep -qxF 'NOT a frameless leaf: sanitize_block uses the stack: add $0x18,%rsp' \
        "$tmp/$mode.log" || ok=0
      grep -qxF 'NOT a frameless leaf: sanitize_block uses the stack: pop %rbp' \
        "$tmp/$mode.log" || ok=0
      ! grep -q 'frameless.*sanitize_words8' "$tmp/$mode.log" || ok=0 ;;
    gnu-wipe-call)
      [ "$status" -eq 1 ] || ok=0
      grep -qxF 'NOT a frameless leaf: sanitize_block calls: bl 8 <blake2b__wipe__sanitize_block+0x8> (record: memset)' \
        "$tmp/$mode.log" || ok=0
      [ "$(grep -c '^NOT a frameless leaf' "$tmp/$mode.log")" -eq 1 ] || ok=0 ;;
    gnu-wipe-tail-jump)
      [ "$status" -eq 1 ] || ok=0
      grep -qxF 'NOT a frameless leaf: sanitize_words8 jumps out (only a return is allowed): memset' \
        "$tmp/$mode.log" || ok=0
      [ "$(grep -c '^NOT a frameless leaf' "$tmp/$mode.log")" -eq 1 ] || ok=0 ;;
    # Only the two wipe routines checked frameless may be called; another
    # fails by name, and the two still pass as frameless leaves.
    gnu-wipe-other)
      [ "$status" -eq 1 ] || ok=0
      grep -qxF 'NOT allowed: blake2b-hashing.o calls a wipe routine that is not checked frameless (the checked ones: sanitize_words8 sanitize_block): blake2b__wipe__sanitize_bytes' \
        "$tmp/$mode.log" || ok=0
      grep -qxF 'references to the wipe routines and Blake2b.No_Bytes: blake2b__wipe__sanitize_block blake2b__wipe__sanitize_words8' \
        "$tmp/$mode.log" || ok=0
      grep -q '^wipe routines are frameless leaves: sanitize_words8 sanitize_block$' \
        "$tmp/$mode.log" || ok=0
      ! grep -q 'outside the classes above' "$tmp/$mode.log" || ok=0 ;;
    # A call through a register or memory fails by the function's name: in
    # a clone (AArch64 blr), in a cold part (x86-64, through a GOT slot
    # whose record names a symbol), and in a wipe routine.
    gnu-clone-indirect-call)
      [ "$status" -eq 1 ] || ok=0
      grep -qxF 'CALLS INDIRECTLY from blake2b__hashing__update.strub.0 (through a register or memory: its target is not known, so it is not checked)' \
        "$tmp/$mode.log" || ok=0
      [ "$(grep -c '^CALLS INDIRECTLY' "$tmp/$mode.log")" -eq 1 ] || ok=0
      ! grep -q '^no call through a register' "$tmp/$mode.log" || ok=0
      ! grep -q '^JUMPS OUT' "$tmp/$mode.log" || ok=0 ;;
    gnu-cold-indirect-call)
      [ "$status" -eq 1 ] || ok=0
      grep -qxF 'CALLS INDIRECTLY from blake2b__hashing__final.cold (through a register or memory: its target is not known, so it is not checked)' \
        "$tmp/$mode.log" || ok=0
      [ "$(grep -c '^CALLS INDIRECTLY' "$tmp/$mode.log")" -eq 1 ] || ok=0
      ! grep -q '^JUMPS OUT\|^FALLS THROUGH' "$tmp/$mode.log" || ok=0 ;;
    gnu-wipe-indirect-call)
      [ "$status" -eq 1 ] || ok=0
      grep -qxF 'NOT a frameless leaf: sanitize_block calls: blr x8' \
        "$tmp/$mode.log" || ok=0
      grep -qxF 'NOT a frameless leaf: sanitize_block calls through a register or memory (its target is not known)' \
        "$tmp/$mode.log" || ok=0
      [ "$(grep -c '^NOT a frameless leaf' "$tmp/$mode.log")" -eq 2 ] || ok=0 ;;
    gnu-wipe-missing)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^MISSING: blake2b__wipe__sanitize_block is not in the disassembly of blake2b-wipe.o ' \
        "$tmp/$mode.log" || ok=0
      ! grep -q '^wipe routines are frameless' "$tmp/$mode.log" || ok=0 ;;
    gnu-missing-register)
      [ "$status" -eq 1 ] || ok=0
      grep -q 'NOT cleared on return from final: v0' "$tmp/$mode.log" || ok=0 ;;
    gnu-probe-failure)
      [ "$status" -eq 2 ] || ok=0
      grep -q 'could not measure the registers' "$tmp/$mode.log" || ok=0
      grep -q 'gcc mock hardening probe' "$tmp/$mode.log" || ok=0
      grep -q 'GNU objdump mock 2.42' "$tmp/$mode.log" || ok=0
      grep -q '<blake2b_hardening_probe>:' "$tmp/$mode.log" || ok=0 ;;
    gnu-not-gcc)
      [ "$status" -eq 2 ] || ok=0
      grep -q 'the probe compiler is not GCC' "$tmp/$mode.log" || ok=0 ;;
    gnu-weak-helper)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^NOT inlined into the scrubbed bodies .*: blake2b__hashing__fill_block$' \
        "$tmp/$mode.log" || ok=0 ;;
    gnu-stray-helper)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^NOT inlined into the scrubbed bodies .*: blake2b__hashing__add_counter blake2b__hashing__update.part.0$' \
        "$tmp/$mode.log" || ok=0 ;;
    gnu-core-compress)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^NOT inlined: blake2b-core.o defines blake2b__core__compress ' \
        "$tmp/$mode.log" || ok=0
      grep -q '^NOT inlined: blake2b-hashing.o calls blake2b__core__compress ' \
        "$tmp/$mode.log" || ok=0 ;;
    gnu-core-helper)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^NOT inlined: blake2b-hashing.o calls Blake2b.Core helpers .*: blake2b__core__load_words$' \
        "$tmp/$mode.log" || ok=0 ;;
    gnu-cold)
      [ "$status" -eq 0 ] || ok=0
      grep -q '^cold parts of the functions whose returns are checked, with no return: none; whose returns clear the registers: blake2b__hashing__final.cold; of other clones or public operations: blake2b__hashing__update.strub.0.cold$' \
        "$tmp/$mode.log" || ok=0
      grep -q '^jumps out of .* (allowed): blake2b__hashing__final->blake2b__hashing__final.cold$' \
        "$tmp/$mode.log" || ok=0 ;;
    gnu-cold-section)
      [ "$status" -eq 0 ] || ok=0
      grep -q '^jumps out of .* (allowed): blake2b__hashing__final->.text.unlikely.blake2b__hashing__final$' \
        "$tmp/$mode.log" || ok=0 ;;
    gnu-cold-hot-section)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^JUMPS OUT of blake2b__hashing__final (only into its own cold part is allowed): .text.blake2b__hashing__final$' \
        "$tmp/$mode.log" || ok=0 ;;
    gnu-cold-dirty)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^NOT cleared on return from cold part blake2b__hashing__final.cold: v0$' \
        "$tmp/$mode.log" || ok=0 ;;
    gnu-cold-rejoin)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^JUMPS OUT of cold part blake2b__hashing__final.cold (a cold part may jump nowhere): blake2b__hashing__final$' \
        "$tmp/$mode.log" || ok=0 ;;
    gnu-tail-jump)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^JUMPS OUT of blake2b__hashing__update (only into its own cold part is allowed): blake2b__hashing__helper$' \
        "$tmp/$mode.log" || ok=0 ;;
    gnu-clone-cold-dirty)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^NOT cleared on return from cold part blake2b__hashing__digest_of.strub.0.cold: v0 x0$' \
        "$tmp/$mode.log" || ok=0
      grep -q '^jumps out of .* (allowed): blake2b__hashing__digest_of.strub.0->blake2b__hashing__digest_of.strub.0.cold$' \
        "$tmp/$mode.log" || ok=0 ;;
    gnu-self-reloc)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^JUMPS OUT of blake2b__hashing__final (only into its own cold part is allowed): blake2b__hashing__final+0xc$' \
        "$tmp/$mode.log" || ok=0 ;;
    gnu-cold-indirect)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^cold parts of the functions whose returns are checked, with no return: blake2b__hashing__final.cold; ' \
        "$tmp/$mode.log" || ok=0
      grep -q '^JUMPS OUT of cold part blake2b__hashing__final.cold (a cold part may jump nowhere): \*indirect\*$' \
        "$tmp/$mode.log" || ok=0 ;;
    gnu-clone-cold-section)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^JUMPS OUT of blake2b__hashing__final.strub.0 (only into its own cold part is allowed): .text.unlikely.blake2b__hashing__final$' \
        "$tmp/$mode.log" || ok=0
      grep -q '^jumps out of .* (allowed): blake2b__hashing__final.strub.0->.text.unlikely.blake2b__hashing__final.strub.0$' \
        "$tmp/$mode.log" || ok=0 ;;
    gnu-cold-falls-through)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^FALLS THROUGH the end of blake2b__hashing__final.cold: mov x0, #0x2a$' \
        "$tmp/$mode.log" || ok=0
      grep -q '^FALLS THROUGH the end of blake2b__hashing__update.strub.0: b.ne 0 <blake2b__hashing__update.strub.0>$' \
        "$tmp/$mode.log" || ok=0
      [ "$(grep -c '^FALLS THROUGH' "$tmp/$mode.log")" -eq 2 ] || ok=0 ;;
    gnu-clone-indirect)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^JUMPS OUT of blake2b__hashing__update.strub.0 (only into its own cold part is allowed): \*indirect\*$' \
        "$tmp/$mode.log" || ok=0 ;;
    gnu-counter-out-of-line)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^NOT inlined: blake2b-hashing-counter_arithmetic.o defines .*: blake2b__hashing__counter_arithmetic__add_counter blake2b__hashing__counter_arithmetic__add_counter.constprop.0$' \
        "$tmp/$mode.log" || ok=0 ;;
    gnu-other-reference)
      [ "$status" -eq 1 ] || ok=0
      grep -q '^NOT allowed: blake2b-hashing.o references symbols outside the classes above: abort_mock$' \
        "$tmp/$mode.log" || ok=0 ;;
  esac
  if [ "$ok" -eq 0 ]; then
    echo "FAILED: $mode (exit status $status):"
    sed 's/^/  /' "$tmp/$mode.log"
    exit 1
  fi
  # LLVM disassembles three objects with the option: the probe,
  # blake2b-hashing.o and blake2b-wipe.o.
  if [ "$mode" = llvm ] || [ "$mode" = llvm-libc ]; then
    if [ "$(grep -c -- '--show-all-symbols' "$MOCK_LOG")" -ne 3 ]; then
      echo "FAILED: $mode did not pass --show-all-symbols three times"
      exit 1
    fi
  elif grep -q -- '--show-all-symbols' "$MOCK_LOG"; then
    echo "FAILED: unexpected --show-all-symbols for $mode"
    exit 1
  fi
  pass=$((pass + 1))
done

echo "hardening disassembler: $pass passed, 0 failed"
