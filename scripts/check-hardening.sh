#!/usr/bin/env bash
# Builds the library in its release profile (-O3 -gnatn -gnatp) and checks
# that the hardening survived optimisation:
#
#  * a GCC stack-scrubbing (strub) clone of every entry point that handles
#    keys or input (the one-shot Digest_Of, Init, Update, Final);
#  * calls from Blake2b.Hashing to both wipe routines (never inlined or
#    dropped as dead stores);
#  * no big-integer code (the ghost proof model) in any release object;
#  * nothing proof-only in Blake2b.Hashing's object: no model, lemma or
#    theorem code, and no secondary-stack use. (GNAT sets up the secondary
#    stack for a Static assertion that calls a function returning an
#    unconstrained array, even though it then drops the assertion);
#  * register clearing: at every return of every hardened entry point,
#    the instructions after its last call zero at least the registers
#    that GCC's zero_call_used_regs ("all") zeroes for this target. That
#    is every call-used register, including ones only its callees (the
#    compression function) used. The set is measured, not hard-coded: a
#    probe function with the attribute is compiled by the same toolchain
#    for the same target, so the check holds for each ABI CI runs (x86-64
#    SysV and Windows, AArch64 Linux and macOS).
#
# Usage: scripts/check-hardening.sh
#        ALR=/path/to/alr NM=/path/to/nm OBJDUMP=/path/to/objdump \
#          scripts/check-hardening.sh
# (By default objdump is the toolchain's, run through `alr exec`.)

set -euo pipefail

ALR=${ALR:-alr}
NM=${NM:-nm}
OBJDUMP=${OBJDUMP:-}
cd "$(dirname "$0")/.."

if [ -n "$OBJDUMP" ]; then
  objdump_help=$("$OBJDUMP" --help)
  objdump_version=$("$OBJDUMP" --version)
else
  objdump_help=$("$ALR" -n exec -- objdump --help)
  objdump_version=$("$ALR" -n exec -- objdump --version)
fi
disassembly_args=(-d --no-show-raw-insn)
# LLVM hides Mach-O function symbols behind section-start aliases unless
# all symbols are requested. GNU AArch64 objdump also supports this option,
# but it exposes ELF mapping symbols ($d/$x) within functions, interrupting
# the function boundaries the register parser tracks. GNU's default output
# already labels the functions correctly.
if grep -qi 'LLVM' <<< "$objdump_version" &&
   grep -q -- '--show-all-symbols' <<< "$objdump_help"; then
  disassembly_args+=(--show-all-symbols)
fi

disassemble () {
  if [ -n "$OBJDUMP" ]; then
    "$OBJDUMP" "${disassembly_args[@]}" "$1"
  else
    "$ALR" -n exec -- objdump "${disassembly_args[@]}" "$1"
  fi
}

"$ALR" -n build --release
obj=obj/release-profile-profile
syms=$("$NM" "$obj/blake2b-hashing.o")

fail=0
for entry in digest_of init update final; do
  if grep -q "blake2b__hashing__${entry}\.strub" <<< "$syms"; then
    echo "strub clone present: $entry"
  else
    echo "MISSING strub clone: $entry"
    fail=1
  fi
done
for wipe in sanitize_words8 sanitize_block; do
  if grep -qE "U .*blake2b__wipe__${wipe}" <<< "$syms"; then
    echo "wipe call present: $wipe"
  else
    echo "MISSING wipe call: $wipe"
    fail=1
  fi
done
if "$NM" "$obj"/*.o | grep -qi 'big_numbers'; then
  echo "FOUND big-integer code in release objects"
  fail=1
else
  echo "no big-integer code in release objects"
fi
proof_only='ghost|model|lemma|theorem|secondary_stack'
if grep -qiE "$proof_only" <<< "$syms"; then
  echo "FOUND proof-only code in blake2b-hashing.o:"
  grep -iE "$proof_only" <<< "$syms"
  fail=1
else
  echo "no proof-only code in blake2b-hashing.o"
fi

# Register clearing. The probe gives the registers the attribute zeroes
# for this target; each hardened exit must zero at least those.
probe_dir=obj/hardening-probe
mkdir -p "$probe_dir"
printf '%s\n' \
  '__attribute__ ((zero_call_used_regs ("all")))' \
  'void blake2b_hardening_probe (void) { }' > "$probe_dir/probe.c"
"$ALR" -n exec -- gcc -O2 -c "$probe_dir/probe.c" -o "$probe_dir/probe.o"
probe_dis=$(disassemble "$probe_dir/probe.o")
printf '%s\n' "$probe_dis" > "$probe_dir/probe.dis"
want=$(awk -v fn=blake2b_hardening_probe \
           -f scripts/zeroed-at-return.awk <<< "$probe_dis")
want=${want#ret:}
if [ "$want" = none ] || [ -z "${want// /}" ]; then
  echo "could not measure the registers zero_call_used_regs zeroes"
  echo "probe compiler:" >&2
  "$ALR" -n exec -- gcc --version >&2
  echo "probe disassembler:" >&2
  printf '%s\n' "$objdump_version" >&2
  echo "probe disassembly ($probe_dir/probe.dis):" >&2
  printf '%s\n' "$probe_dis" >&2
  fail=1
else
  echo "call-used registers on this target:$want"
  hashing_dis=$(disassemble "$obj/blake2b-hashing.o")
  for entry in init update final digest_of.strub.0; do
    rets=$(awk -v fn="blake2b__hashing__${entry}" \
               -f scripts/zeroed-at-return.awk <<< "$hashing_dis")
    if [ "$rets" = none ]; then
      echo "MISSING: no return found in $entry"
      fail=1
      continue
    fi
    missing=""
    while IFS= read -r ret; do
      for reg in $want; do
        case " ${ret#ret:} " in
          *" $reg "*) ;;
          *) missing="$missing $reg" ;;
        esac
      done
    done <<< "$rets"
    if [ -z "$missing" ]; then
      echo "registers cleared on return: $entry"
    else
      echo "NOT cleared on return from $entry:$missing"
      fail=1
    fi
  done
fi

if [ "$fail" -eq 0 ]; then
  echo "hardening: present"
else
  exit 1
fi
