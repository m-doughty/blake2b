#!/usr/bin/env bash
# Builds the library in its release profile (-O3 -gnatn -gnatp) and checks
# that the hardening survived optimisation. The hardened entry points are
# Init, Update, Final and the one-shot Digest_Of (behind both Hash
# procedures). Each carries GCC's strub ("internal"), zero_call_used_regs
# ("all") and flatten attributes, and the compression function is
# Inline_Always, so that every secret the hash handles stays in a stack
# frame that is scrubbed on return.
#
# In the source (src/blake2b-hashing.ads and .adb, comments removed):
#  * each entry point carries the three attributes. flatten cannot be seen
#    in the object: at -O3 GCC inlines the helpers without it, and the
#    code is the same. The object checks below show that everything is
#    inlined today; this check shows it is not left to the inliner's
#    heuristics.
#
# In obj/release-profile-profile/blake2b-hashing.o:
#  * a strub clone (<name>.strub.<n>, the scrubbed body) of each entry
#    point;
#  * register clearing: at every return of Init, Update and Final (the
#    wrappers strub leaves under the entry points' own names), and of
#    Digest_Of's clone (its wrapper is inlined into Hash), at least the
#    registers that zero_call_used_regs ("all") zeroes for this target
#    hold zero: zeroed after the last call, branch or branch target before
#    the return, and not written again (zeroed-at-return.awk). The set is
#    measured, not hard-coded: a probe function with the attribute is
#    compiled by the same toolchain's GCC for the same target, so the
#    check holds for each ABI CI runs (x86-64 SysV and Windows, AArch64
#    Linux and macOS);
#  * no jump out (zeroed-at-return.awk, report=exits: a jump, not a call,
#    to another symbol, read from its label or, in this object file, from
#    the relocation record after it) of an entry point, a wrapper, a clone
#    or a cold part, but from a function into its own cold part
#    (<name>.cold or <name>.cold.<n>, or in an object file its own cold
#    section, .text.unlikely.<name> with <name> exact: a clone's is not
#    its wrapper's). A path that leaves by a jump skips
#    the clearing at the function's returns; a cold part that rejoins its
#    function or tail-jumps elsewhere fails by name. So does a jump whose
#    record names the function itself (listed with its addend: its real
#    target is not the one the instruction shows), and an indirect jump
#    (jmp *%rax, br x1: listed as *indirect*), whose target is not known;
#  * none of them falls through its end (zeroed-at-return.awk,
#    report=exits): its last instruction, after any trailing nop padding,
#    is a return, an unconditional jump, a trap or a call (to a routine
#    that does not return, as a cold part ends). Any other fails by name;
#  * the whole computation is inside the scrubbed frames: the object
#    defines no function but
#      - the entry points, their clones and their cold parts
#        (<name>.cold, split off by GCC and run in its function's frame;
#        a cold part of a function whose returns are checked above, a
#        wrapper or Digest_Of's clone, must pass the register check at
#        its returns if it has any, and the others are listed);
#      - the public operations that handle no secret: Hash (both, the
#        wrappers of Digest_Of's clone), Clear, Is_Empty, Is_Absorbing,
#        Is_Finalized, Output_Length and Valid, and the procedures GNAT
#        generates for type State (stateIP, stateDIC, statePartial_DIC),
#        with any GCC clone or cold part of them (.constprop, .isra,
#        .part, .cold).
#    Any other function, the compression function or a helper left out
#    of line, fails the check by name. Section symbols (COFF), assembler
#    temporaries (Mach-O ltmp<n>) and mapping symbols (ELF $x, $d) are not
#    functions and are ignored;
#  * no call out of line into Blake2b.Core, but for Initial_H (its inputs
#    are the key and digest lengths, which are public) and its constant
#    tables; a call to Compress or to a helper that loads the message
#    words fails by name;
#  * calls to both wipe routines (never inlined or dropped as dead
#    stores);
#  * the other symbols the object references in other units are listed:
#    memcpy, memmove and memset (leaf libc routines called inside the
#    scrubbed body; zero_call_used_regs zeroes every call-used register
#    when the entry point returns), the wipe routines, and the GNAT and
#    GCC run-time routines. Any other reference fails by name;
#  * nothing proof-only: no model, lemma or theorem code, and no
#    secondary-stack use. (GNAT sets up the secondary stack for a Static
#    assertion that calls a function returning an unconstrained array,
#    even though it then drops the assertion).
#
# In obj/release-profile-profile/blake2b-core.o:
#  * no definition of Compress (Inline_Always: a symbol means the inlining
#    did not take), and no function outside the exact set the unit is
#    expected to keep out of line: Initial_H, Load64, Load_Words, Out_Byte
#    and the initialisation procedures GNAT generates for its array types
#    Schedule and Schedule_Row (each with any GCC clone or cold part).
#    The functions it defines are listed.
#
# In obj/release-profile-profile/blake2b-hashing-counter_arithmetic.o:
#  * no function at all: Add_Counter is Inline_Always (a definition, a
#    clone or a cold part means a copy outside the scrubbed bodies) and
#    Value is ghost.
#
# In every release object: no big-integer code (the ghost proof model).
#
# Not checked: how much of the stack the wrappers scrub (GCC scrubs the
# clone's frame), nor what the listed external calls leave behind.
#
# The register and jump checks read the code and its relocation records
# (objdump -d -r); the rest reads symbol names (nm). Exit status: 0 if
# every check passes, 1 if one fails, 2 if the toolchain or the objects
# cannot be read.
#
# Usage: scripts/check-hardening.sh
#        ALR=/path/to/alr NM=/path/to/nm OBJDUMP=/path/to/objdump \
#          scripts/check-hardening.sh
# (By default objdump and the probe's gcc are the toolchain's, run through
# `alr exec`.)

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
# -r prints the relocation records, which name the real target of a jump
# out of the function (the instruction shows a placeholder).
disassembly_args=(-d -r --no-show-raw-insn)
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
hashing_o=$obj/blake2b-hashing.o
core_o=$obj/blake2b-core.o
counter_o=$obj/blake2b-hashing-counter_arithmetic.o
for object in "$hashing_o" "$core_o" "$counter_o"; do
  if [ ! -f "$object" ]; then
    echo "missing $object (did the build fail?)"
    exit 2
  fi
done
syms=$("$NM" "$hashing_o")
core_syms=$("$NM" "$core_o")
counter_syms=$("$NM" "$counter_o")

# Mach-O prefixes every symbol with an underscore; names are compared
# without it, and in lower case (nm keeps GNAT's upper-case letters, as in
# stateIP).
prefix=$(awk '$(NF - 1) ~ /^[Tt]$/ && tolower($NF) == "_blake2b__hashing__init" { print "_"; exit }' <<< "$syms")
if ! awk '$(NF - 1) ~ /^[Tt]$/ && tolower($NF) ~ /^_?blake2b__hashing__init$/ { ok = 1 } END { exit !ok }' <<< "$syms"; then
  echo "blake2b-hashing.o does not define blake2b__hashing__init" \
       "(unreadable object?)"
  exit 2
fi

# Prints the functions (text symbols) nm's output $1 defines, one per
# line, without the Mach-O underscore, in lower case, sorted bytewise.
text_functions () {
  awk -v p="$prefix" '
    { sub(/\r$/, "") }
    NF >= 3 && $(NF - 1) ~ /^[Tt]$/ {
      s = $NF
      # A COFF section symbol (.text, .text$name), a Mach-O assembler
      # temporary (ltmp<n>) or an ELF mapping symbol ($x, $d) labels a
      # section or a code region, not a function.
      if (s ~ /^\./ || s ~ /^ltmp[0-9]+$/ || s ~ /^\$/) next
      if (p != "" && substr(s, 1, 1) == p) s = substr(s, 2)
      print tolower(s)
    }' <<< "$1" | LC_ALL=C sort -u
}

# Prints the symbols nm's output $1 references (undefined), one per line,
# without the Mach-O underscore (case kept), sorted bytewise.
references () {
  awk -v p="$prefix" '
    { sub(/\r$/, "") }
    NF >= 2 && $(NF - 1) == "U" {
      s = $NF
      if (p != "" && substr(s, 1, 1) == p) s = substr(s, 2)
      print s
    }' <<< "$1" | LC_ALL=C sort -u
}

# Classifies the functions on stdin, one per line. ENTRIES are the
# hardened entry points: each may appear as itself, its strub clones
# (.strub.<n>) and the cold parts of either. PLAIN are the functions
# allowed outside the scrubbed frames: each may appear as itself or a GCC
# clone or cold part of it. Prints "entry NAME", "plain NAME" or
# "stray NAME" per function.
classify () {
  awk -v entries="$1" -v plain="$2" '
    BEGIN { ne = split(entries, e, " "); np = split(plain, q, " ") }
    {
      fn = $0; class = "stray"
      for (i = 1; i <= ne && class == "stray"; i++)
        if (index(fn, e[i]) == 1 &&
            substr(fn, length(e[i]) + 1) ~ /^(\.strub\.[0-9]+)?(\.cold(\.[0-9]+)?)?$/)
          class = "entry"
      for (i = 1; i <= np && class == "stray"; i++)
        if (index(fn, q[i]) == 1 &&
            substr(fn, length(q[i]) + 1) ~ /^(\.(constprop|isra|part)\.[0-9]+)*(\.cold(\.[0-9]+)?)?$/)
          class = "plain"
      print class, fn
    }'
}

functions=$(text_functions "$syms")
core_functions=$(text_functions "$core_syms")
counter_functions=$(text_functions "$counter_syms")
hashing_refs=$(references "$syms")

fail=0

# The attributes in the source.
attributes=$(perl -e '
  for my $file (@ARGV) {
    open my $fh, "<", $file or die "$file: $!";
    local $/; my $t = <$fh>; close $fh;
    # Comments go; string literals stay (the attribute names are strings).
    $t =~ s{("(?:[^"\r\n]|"")*")|(--[^\r\n]*)}{defined $1 ? $1 : " "}ge;
    # Ada names are not case-sensitive, so they go to lower case; the
    # attribute names are, and keep theirs (GCC ignores "Flatten" with
    # only a warning).
    $t =~ s{("(?:[^"\r\n]|"")*")|([^"]+)}{defined $1 ? $1 : lc $2}ge;
    $t =~ s/\s+/ /g;
    $t =~ s/ ?([(),;]) ?/$1/g;
    print "$t ";
  }' src/blake2b-hashing.ads src/blake2b-hashing.adb)
for entry in init update final digest_of; do
  missing=""
  for attr in '"strub","internal"' '"zero_call_used_regs","all"' '"flatten"'; do
    case $attributes in
      *"pragma machine_attribute($entry,$attr);"*) ;;
      *) missing="$missing pragma Machine_Attribute ($entry, ${attr/,/, });" ;;
    esac
  done
  if [ -z "$missing" ]; then
    echo "source attributes present (strub, zero_call_used_regs, flatten):" \
         "$entry"
  else
    echo "MISSING in the source:$missing"
    fail=1
  fi
done

for entry in digest_of init update final; do
  if grep -qE "^blake2b__hashing__${entry}\.strub\.[0-9]+\$" <<< "$functions"; then
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

# The functions defined in blake2b-hashing.o.
entries="blake2b__hashing__init blake2b__hashing__update"
entries="$entries blake2b__hashing__final blake2b__hashing__digest_of"
plain="blake2b__hashing__hash blake2b__hashing__hash__2"
plain="$plain blake2b__hashing__clear blake2b__hashing__is_empty"
plain="$plain blake2b__hashing__is_absorbing blake2b__hashing__is_finalized"
plain="$plain blake2b__hashing__output_length blake2b__hashing__valid"
plain="$plain blake2b__hashing__stateip blake2b__hashing__statedic"
plain="$plain blake2b__hashing__statepartial_dic"
classes=$(classify "$entries" "$plain" <<< "$functions")
stray=$(awk '$1 == "stray" { printf " %s", $2 }' <<< "$classes")
if [ -n "$stray" ]; then
  echo "NOT inlined into the scrubbed bodies (defined in" \
       "blake2b-hashing.o, outside the allowed set):$stray"
  fail=1
else
  echo "no function in blake2b-hashing.o outside the scrubbed bodies but" \
       "the public ones that handle no secret:$(awk '$1 == "plain" { printf " %s", $2 }' <<< "$classes")"
fi

# The functions defined in blake2b-core.o.
core_plain="blake2b__core__initial_h blake2b__core__load64"
core_plain="$core_plain blake2b__core__load_words blake2b__core__out_byte"
core_plain="$core_plain blake2b__core__tschedulebip"
core_plain="$core_plain blake2b__core__tschedule_rowbip"
echo "blake2b-core.o defines:" $core_functions
if grep -qE '^blake2b__core__compress(\.|$)' <<< "$core_functions"; then
  echo "NOT inlined: blake2b-core.o defines blake2b__core__compress" \
       "(Compress is Inline_Always; the inlining did not take):" \
       $(grep -E '^blake2b__core__compress(\.|$)' <<< "$core_functions")
  fail=1
fi
core_stray=$(classify "" "$core_plain" <<< "$core_functions" \
  | awk '$1 == "stray" && $2 !~ /^blake2b__core__compress(\.|$)/ { printf " %s", $2 }')
if [ -n "$core_stray" ]; then
  echo "blake2b-core.o defines a function outside the expected set" \
       "(a helper left out of line?):$core_stray"
  fail=1
fi

# The functions defined in blake2b-hashing-counter_arithmetic.o: none.
if [ -n "$counter_functions" ]; then
  echo "NOT inlined: blake2b-hashing-counter_arithmetic.o defines" \
       "(Add_Counter is Inline_Always; nothing may be out of line):" \
       $counter_functions
  fail=1
else
  echo "blake2b-hashing-counter_arithmetic.o defines no function"
fi

# What blake2b-hashing.o calls in other units.
libc="" wipes="" runtime="" core_refs="" core_bad="" other=""
for ref in $hashing_refs; do
  lower=$(tr '[:upper:]' '[:lower:]' <<< "$ref")
  case $lower in
    blake2b__core__compress|blake2b__core__compress.*)
      echo "NOT inlined: blake2b-hashing.o calls $ref out of line" \
           "(outside the scrubbed frame)"
      fail=1 ;;
    blake2b__core__initial_h|blake2b__core__iv|blake2b__core__sigma)
      core_refs="$core_refs $ref" ;;
    blake2b__core__*) core_bad="$core_bad $ref" ;;
    blake2b__wipe__*|blake2b__no_bytes) wipes="$wipes $ref" ;;
    *)
      if grep -qE '^_*(memcpy|memmove|memset)(_chk)?$' <<< "$lower"; then
        libc="$libc $ref"
      elif grep -qE '^_*(unwind_resume|gnat_personality_(v0|seh0)|strub_(enter|leave|update)|chkstk(_ms)?|stack_chk_fail)$' <<< "$lower"; then
        runtime="$runtime $ref"
      else
        other="$other $ref"
      fi ;;
  esac
done
if [ -n "$core_bad" ]; then
  echo "NOT inlined: blake2b-hashing.o calls Blake2b.Core helpers out of" \
       "line (outside the scrubbed frame):$core_bad"
  fail=1
fi
echo "references to libc leaf routines (allowed):${libc:- none}"
echo "references to Blake2b.Core (public parameters and constants):${core_refs:- none}"
echo "references to the wipe routines and Blake2b.No_Bytes:${wipes:- none}"
echo "references to the GNAT and GCC run-time:${runtime:- none}"
if [ -n "$other" ]; then
  echo "NOT allowed: blake2b-hashing.o references symbols outside the" \
       "classes above:$other"
  fail=1
fi

# Register clearing. The probe gives the registers the attribute zeroes
# for this target; each hardened exit must zero at least those. Another
# compiler (the system's clang answers to gcc on macOS) could zero a
# different set, so the probe compiler must be GCC.
probe_cc_v=$("$ALR" -n exec -- gcc -v 2>&1 || true)
if ! grep -q '^gcc version' <<< "$probe_cc_v"; then
  echo "the probe compiler is not GCC (gcc -v says:" \
       "$(tail -n 1 <<< "$probe_cc_v"))"
  exit 2
fi
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
  exit 2
fi
echo "call-used registers on this target:$want"
hashing_dis=$(disassemble "$hashing_o")

# Prints the registers of $want that do not hold zero at some return of
# function $1 (see zeroed-at-return.awk); "none" if the function has no
# return; nothing if every return zeroes them all.
not_cleared () {
  local rets ret reg missing=""
  rets=$(awk -v fn="$1" -f scripts/zeroed-at-return.awk <<< "$hashing_dis")
  if [ "$rets" = none ]; then
    echo none
    return
  fi
  while IFS= read -r ret; do
    for reg in $want; do
      case " ${ret#ret:} |$missing " in
        *" $reg "*) ;;
        *) missing="$missing $reg" ;;
      esac
    done
  done <<< "$rets"
  printf '%s' "$missing"
}

# The wrappers of Init, Update and Final; Digest_Of's clones, and its
# wrapper if this target keeps one out of line.
targets="blake2b__hashing__init blake2b__hashing__update blake2b__hashing__final"
targets="$targets $(grep -E '^blake2b__hashing__digest_of(\.strub\.[0-9]+)?$' <<< "$functions" | tr '\n' ' ')"
case " $targets " in
  *" blake2b__hashing__digest_of"*) ;;
  *) targets="$targets blake2b__hashing__digest_of.strub.0" ;;
esac
for fn in $targets; do
  entry=${fn#blake2b__hashing__}
  missing=$(not_cleared "$fn")
  if [ "$missing" = none ]; then
    echo "MISSING: no return found in $entry"
    fail=1
  elif [ -n "$missing" ]; then
    echo "NOT cleared on return from $entry:$missing"
    fail=1
  else
    echo "registers cleared on return: $entry"
  fi
done

# Cold parts. One of a function whose returns are checked above (a
# wrapper, or Digest_Of's clone, whose wrapper is inlined into Hash)
# leaves the scrubbed frame if it returns, so it must clear the registers
# too. One of another clone returns into the wrapper, which clears them;
# one of a public operation holds no secret. Most cold parts cannot
# return (they end in a call that raises).
cold_all="" cold_noret="" cold_cleared="" cold_other=""
for fn in $(awk '$2 ~ /\.cold(\.[0-9]+)?$/ { print $2 }' <<< "$classes"); do
  parent=${fn%.cold*}
  cold_all="$cold_all $fn"
  if ! grep -qE "^[0-9a-fA-F]+ <_?${fn//./\\.}>:" <<< "$hashing_dis"; then
    echo "cold part $fn is not in the disassembly"
    fail=1
  elif [[ " $targets $entries " = *" $parent "* ]]; then
    missing=$(not_cleared "$fn")
    if [ "$missing" = none ]; then
      cold_noret="$cold_noret $fn"
    elif [ -n "$missing" ]; then
      echo "NOT cleared on return from cold part $fn:$missing"
      fail=1
    else
      cold_cleared="$cold_cleared $fn"
    fi
  else
    cold_other="$cold_other $fn"
  fi
done
if [ -z "$cold_all" ]; then
  echo "no cold parts"
else
  echo "cold parts of the functions whose returns are checked, with no" \
       "return:${cold_noret:- none};" \
       "whose returns clear the registers:${cold_cleared:- none};" \
       "of other clones or public operations:${cold_other:- none}"
fi

# Jumps out. A path that leaves a function by a jump does not reach its
# returns, so their clearing says nothing for it. Each entry point,
# wrapper and clone may jump only into its own cold part, which runs in
# its frame; a cold part, of any function, may jump nowhere. Nor may any
# of them run off its end into whatever follows it.
jumps_own=""
for fn in $(awk '$1 == "entry" || $2 ~ /\.cold(\.[0-9]+)?$/ { print $2 }' <<< "$classes"); do
  exits=$(awk -v fn="$fn" -v report=exits -f scripts/zeroed-at-return.awk \
            <<< "$hashing_dis")
  if [ "$exits" = none ]; then
    echo "MISSING: $fn is not in the disassembly (its jumps not checked)"
    fail=1
    continue
  fi
  own_cold="^${fn//./\\.}\\.cold(\\.[0-9]+)?\$"
  bad=""
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    target=${line#exit: }
    # A function that runs off its end leaves into whatever follows it.
    falls='*falls-through* '
    if [ "${target#"$falls"}" != "$target" ]; then
      echo "FALLS THROUGH the end of $fn: ${target#"$falls"}"
      fail=1
      continue
    fi
    lower=$(tr '[:upper:]' '[:lower:]' <<< "$target")
    # ELF and COFF relocate a jump to a .L label in the cold section against
    # the section symbol: GCC names that section .text.unlikely.<function>
    # (under -ffunction-sections, which the release profile sets). Only
    # the function's own is accepted, by its exact name: a clone's is
    # .text.unlikely.<name>.strub.<n>, and a jump from a clone into its
    # wrapper's cold section fails by name.
    own_section="^\\.text\\.unlikely\\.${fn//./\\.}\$"
    if ! [[ $fn =~ \.cold(\.[0-9]+)?$ ]] &&
       { [[ $lower =~ $own_cold ]] || [[ $lower =~ $own_section ]]; }; then
      jumps_own="$jumps_own $fn->$target"
    else
      bad="$bad $target"
    fi
  done <<< "$exits"
  if [ -n "$bad" ]; then
    if [[ $fn =~ \.cold(\.[0-9]+)?$ ]]; then
      echo "JUMPS OUT of cold part $fn (a cold part may jump nowhere):$bad"
    else
      echo "JUMPS OUT of $fn (only into its own cold part is allowed):$bad"
    fi
    fail=1
  fi
done
echo "jumps out of the entry points, wrappers, clones and cold parts," \
     "into a function's own cold part (allowed):${jumps_own:- none}"

if [ "$fail" -eq 0 ]; then
  echo "hardening: present"
else
  exit 1
fi
