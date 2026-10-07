#!/usr/bin/env bash
# Source gate: the library may not contain any of the ways to make
# GNATprove accept something it has not proved.
#
#   pragma Assume                         an unproved fact
#   Annotate (GNATprove, False_Positive)  a check waved through
#   Annotate (GNATprove, Intentional)     a check waved through
#   Skip_Proof / Skip_Flow_And_Proof      a subprogram not analysed
#   SPARK_Mode => Off / (Off)             code outside SPARK
#   Import in Blake2b.Spec (or a child)   an unanalysed specification
#
# Warnings (GNATprove's, or unqualified ones, which GNATprove also obeys)
# may be suppressed only with a recorded Reason. The script lists every
# suppression so that a reviewer sees them all.
#
# The checks run on the source as the compiler reads it, not on its
# spelling:
#   * string literals, character literals and comments are removed first,
#     in one left-to-right pass, so a comment or a string that mentions a
#     forbidden pragma doesn't trip the gate, and "--" inside a string
#     can't hide the code after it;
#   * the rest is lowercased (Ada is case-insensitive), and line breaks
#     and runs of spaces become one space, so a pragma split across lines
#     is caught.
#
# Usage: scripts/check-sources.sh               check src/
#        scripts/check-sources.sh --self-test   check the gate itself
#                                               against known bypasses

set -euo pipefail
cd "$(dirname "$0")/.."

# Prints "file<TAB>normalised text", one line per Ada source given.
normalise () {
  perl -e '
    for my $file (@ARGV) {
      open my $fh, "<", $file or die "$file: $!";
      local $/; my $t = <$fh>; close $fh;
      # One pass, leftmost match first: a string, a character literal (a
      # quote not preceded by an identifier or a closing bracket, which
      # would make it an attribute tick) or a comment.
      $t =~ s{("(?:[^"\n]|"")*")|((?<![A-Za-z0-9_)\]])\x27.\x27)|(--[^\n]*)}
             {defined $1 ? q{""} : " "}ge;
      $t = lc $t;
      $t =~ s/\s+/ /g;
      print "$file\t$t\n";
    }' "$@"
}

# Runs every check over the given files; spec_files are the ones that may
# not import. Prints findings; returns non-zero if there are any.
scan () {
  local spec_files=$1; shift
  local normal found=0 hits
  normal=$(normalise "$@")
  forbid () {
    local what=$1 pattern=$2
    hits=$(grep -E "$pattern" <<< "$normal" | cut -f1 || true)
    if [ -n "$hits" ]; then
      echo "FORBIDDEN ($what) in:"
      printf '  %s\n' $hits
      found=1
    fi
  }
  forbid "pragma Assume"             'pragma ?assume\b'
  forbid "False_Positive annotation" '\bfalse_positive\b'
  forbid "Intentional annotation"    '\bintentional\b'
  forbid "Skip_Proof"                '\bskip_(flow_and_)?proof\b'
  forbid "SPARK_Mode Off"            'spark_mode ?(=> ?off\b|\( ?off ?\))'
  if [ -n "$spec_files" ]; then
    hits=$(normalise $spec_files | grep -E '\bimport\b' | cut -f1 || true)
    if [ -n "$hits" ]; then
      echo "FORBIDDEN (Import in the specification) in:"
      printf '  %s\n' $hits
      found=1
    fi
  fi
  # Every suppression pragma: pragma Warnings ([tool,] Off ...); each must
  # carry "Reason =>" before its closing semicolon.
  local sup without
  sup=$(perl -ne '
    my ($f, $t) = split /\t/, $_, 2;
    while ($t =~ /(pragma warnings ?\( ?(?:(?:gnatprove|gnat) ?, ?)?off\b[^;]*;)/g) {
      print "$f\t$1\n";
    }' <<< "$normal")
  without=$(grep -vE 'reason ?=>' <<< "$sup" | cut -f1 || true)
  if [ -n "$without" ]; then
    echo "FORBIDDEN (warning suppression without a Reason) in:"
    printf '  %s\n' $without
    found=1
  fi
  SUPPRESSIONS=$(grep -c . <<< "$sup" || true)
  return "$found"
}

self_test () {
  local dir pass=0 bad=0
  dir=$(mktemp -d)
  # name | must the gate flag it? | source (\n for line breaks)
  local cases=(
    'lower-assume|yes|pragma assume (True);'
    'split-assume|yes|PRAGMA ASSUME\n   (True);'
    'split-false-positive|yes|pragma Annotate\n  (GNATprove,\n   False_Positive, "x", "y");'
    'aspect-skip|yes|procedure P with Annotate => (gnatprove, skip_proof);'
    'split-spark-off|yes|package P with SPARK_Mode\n   => Off is end P;'
    'pragma-spark-off|yes|pragma spark_mode (off);'
    'string-hides-code|yes|S : constant String := "--"; pragma Assume (False);'
    'char-quote-hides-code|yes|C : constant Character := '"'"'"'"'"'; pragma Assume (X); S : String := "a";'
    'unexplained-warning|yes|pragma Warnings (GNATprove, Off, "msg");'
    'unexplained-plain-warning|yes|pragma Warnings\n  (Off, "msg");'
    'comment-mentions|no|--  pragma Assume (True) would be forbidden'
    'string-mentions|no|S : constant String := "pragma Assume (True)";'
    'explained-warning|no|pragma Warnings (GNATprove, Off, "m",\n   Reason => "why");'
    'warning-on|no|pragma Warnings (GNATprove, On, "msg");'
    'attribute-tick|no|N : constant := X'"'"'Length; pragma Assert (N > 0);'
  )
  local entry name expect src got
  for entry in "${cases[@]}"; do
    IFS='|' read -r name expect src <<< "$entry"
    printf '%b\n' "$src" > "$dir/$name.adb"
    if scan "" "$dir/$name.adb" > /dev/null; then got=no; else got=yes; fi
    if [ "$got" = "$expect" ]; then
      pass=$((pass + 1))
    else
      echo "self-test FAILED: $name (flagged: $got, expected: $expect)"
      bad=$((bad + 1))
    fi
  done
  printf '%b\n' 'package P with Import, Convention => C;' > "$dir/spec-import.ads"
  if scan "$dir/spec-import.ads" "$dir/spec-import.ads" > /dev/null; then
    echo "self-test FAILED: spec-import (not flagged)"; bad=$((bad + 1))
  else
    pass=$((pass + 1))
  fi
  rm -rf "$dir"
  echo "self-test: $pass passed, $bad failed"
  [ "$bad" -eq 0 ]
}

if [ "${1:-}" = --self-test ]; then
  self_test
  exit $?
fi

SUPPRESSIONS=0
fail=0
scan "$(ls src/blake2b-spec.ads src/blake2b-spec-*.ad? 2>/dev/null)" \
     src/*.ads src/*.adb || fail=1

echo "warning suppressions ($SUPPRESSIONS, each with a Reason):"
grep -rn -i -A2 'pragma warnings' src/ | grep -i -E '\boff\b' \
  || echo "  (none)"

if [ "$fail" -eq 0 ]; then
  echo "sources: clean"
else
  exit 1
fi
