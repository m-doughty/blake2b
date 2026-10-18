#!/usr/bin/env bash
# Shows that scripts/check-stack-scan.sh fails when the hardening it
# checks is removed. It runs the scan once per mutation (MUTATE, see that
# script's header), applied to every hardened build (the shipped sources
# and the spill copy), without the injected-raise builds (EXCEPTIONS=0),
# and checks the outcome:
#   nostrub-update     Update's strub pragma removed: must fail (exit 3),
#                      and only in Update scenarios (the mutation touches
#                      nothing else). The spill copy at the start of Update
#                      makes even the calls that compress nothing leave
#                      their secrets.
#   noinline-compress  Compress's Inline_Always and every flatten pragma
#                      removed, the layout before the compression function
#                      was inlined (its frame outside every scrubbed
#                      body): must fail (exit 3).
#   noflatten-update   Update's flatten pragma removed: reported, not
#                      required to fail. Compress stays Inline_Always and
#                      Update's body stays scrubbed, so this mutation may
#                      leave nothing to find (the scan passes, exit 0) or,
#                      where the compiler then keeps a helper out of line
#                      with secrets in its frame, fail (exit 3). Either is
#                      accepted; a harness error or a blind control is not.
#
# Exit status: 0 if both required failures happened and no run ended in a
# harness error; 1 otherwise.
#
# Usage: bash scripts/test-check-stack-scan.sh
#        ALR=/path/to/alr REPEATS=2 bash scripts/test-check-stack-scan.sh
# (REPEATS, PROBE_KIB and ALR are passed on to the scan; REPEATS defaults
# to 2 here.)

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
export REPEATS=${REPEATS:-2}
LOGS="$ROOT/obj/test-stack-scan"
rm -rf "$LOGS"
mkdir -p "$LOGS"

say () { echo "test-check-stack-scan: $*"; }

bad=0
for mutation in nostrub-update noinline-compress noflatten-update; do
  log="$LOGS/$mutation.log"
  status=0
  MUTATE=$mutation EXCEPTIONS=0 bash "$ROOT/scripts/check-stack-scan.sh" \
    > "$log" 2>&1 || status=$?
  failed=$(tr -d '\r' < "$log" \
    | sed -n 's/^check-stack-scan: FAILED: .* in: *//p')
  case $mutation:$status in
    nostrub-update:3)
      others=""
      for scenario in $failed; do
        case $scenario in
          update-*) ;;
          *) others="$others $scenario" ;;
        esac
      done
      if [ -n "$others" ]; then
        say "$mutation: FAILED as required, but also outside Update:$others"
        bad=1
      else
        say "$mutation: the scan failed, as required (exit 3), in: $failed"
      fi
      ;;
    noinline-compress:3)
      say "$mutation: the scan failed, as required (exit 3), in: $failed"
      ;;
    noflatten-update:3)
      say "$mutation: the scan failed (exit 3) in: $failed (accepted)"
      ;;
    noflatten-update:0)
      say "$mutation: the scan passed (exit 0): removing Update's flatten" \
          "left nothing for it to find (accepted; not a failure path)"
      ;;
    *)
      say "$mutation: UNEXPECTED exit $status (see ${log#"$ROOT"/}):"
      tr -d '\r' < "$log" | grep -E 'HARNESS ERROR|BLIND|FAILED|passed' \
        | sed 's/^/  /' || true
      bad=1
      ;;
  esac
done

if [ "$bad" -eq 0 ]; then
  say "passed: the scan fails when the hardening is removed"
else
  say "FAILED"
  exit 1
fi
