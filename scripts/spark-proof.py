#!/usr/bin/env python3
"""Reads GNATprove's per-unit results (the .spark files) for scripts/mutants.sh.

Two commands:

  spark-proof.py margin LIMIT COSTS.json DIR PROVER,... UNIT...
      The step-margin gate for the baseline. For each UNIT (e.g.
      blake2b-streaming-theory.adb), DIR holds baseline.<stem>.spark, the
      proof with every prover, and baseline.<stem>.<prover>.spark, a proof
      with that prover alone, for each PROVER. A check's cost is the
      largest, over the check's VCs, of the fewest steps any prover took to
      prove the VC (in any of those runs): the cheapest prover's steps.
      With every prover at once GNATprove races them and credits the first
      to finish, which depends on timing; each prover's steps alone do
      not, so the cost is the same on every run. Prints each unit's
      costliest checks and writes every check's cost to COSTS.json; exits
      1 if any check costs more than LIMIT steps, 2 if a file is
      unreadable, a check is unproved in the all-provers proof, or a VC
      has no proof in any run.

  spark-proof.py selftest
      Adversarial fixtures for the margin arithmetic; exit 0 if they pass.

  spark-proof.py judge UNIT FILE.spark [COSTS.json]
      Judges one mutant's proof of UNIT (e.g. blake2b-streaming-theory.adb).
      Only unproved checks located in UNIT's own spec or body count, and
      only failed proofs (severity low, medium or high on a VC_ rule), not
      proof warnings. Each is "clean" when one of its VCs was attempted and
      failed on the step budget or on a definite prover answer (Step limit
      exceeded, Unknown, Invalid) for every prover, and "tainted" when no
      VC is clean: it failed through a timeout, a memory exhaustion or a
      prover crash, which a steps-only proof might not reproduce, or no VC
      was attempted. A VC with no attempt (GNATprove stops after a check's
      first failure) is ignored. Prints the checks, with the baseline's cost of
      the same check (file:line:col and rule) where there is one, then one
      verdict line. Exit status: 0 caught (a clean unproved check),
      3 tainted (unproved checks, none clean), 4 none (no unproved check
      in UNIT), 2 the file is missing or unreadable.
"""

import json
import os
import re
import sys

CLEAN_FAILURES = ("step limit exceeded", "unknown", "invalid")
FAILED_SEVERITIES = ("low", "medium", "high")


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)["proof"]


def result_of(attempt):
    """The prover's answer, lower case, whitespace collapsed."""
    return re.sub(r"\s+", " ", str(attempt.get("result", ""))).strip().lower()


def cost(check):
    """Steps of the credited prover, maximised over the check's VCs."""
    stats = check.get("stats") or {}
    return max([int(s.get("max_steps", 0)) for s in stats.values()] or [0])


def where(check):
    return "%s:%d:%d %s" % (check["file"], check["line"], check["col"],
                            check["rule"])


def key(check):
    """A check's identity across runs: where it is checked, and its rule."""
    return "%s:%d:%d %s" % (check.get("check_file", check["file"]),
                            check.get("check_line", check["line"]),
                            check.get("check_col", check["col"]),
                            check["rule"])


def identities(checks):
    """(identity, check) for each check. Several checks can share a place
    and rule, so the identity also counts which one of them it is, in the
    file's order, which is the same on every run of the same sources."""
    seen = {}
    result = []
    for check in checks:
        base = key(check)
        seen[base] = seen.get(base, 0) + 1
        result.append(("%s #%d" % (base, seen[base]), check))
    return result


def node_cost(node):
    """The fewest steps that prove one VC: a prover's own Valid attempt, or
    the dearest subgoal of a transformation that proves it; None when
    nothing here proves it (or a Valid attempt has no step count)."""
    best = None
    for attempt in (node.get("proof_attempts") or {}).values():
        if result_of(attempt) == "valid" and "steps" in attempt:
            steps = int(attempt["steps"])
            best = steps if best is None else min(best, steps)
    for subgoals in (node.get("transformations") or {}).values():
        if not isinstance(subgoals, list) or not subgoals:
            continue
        costs = [node_cost(s) for s in subgoals]
        if all(c is not None for c in costs):
            total = max(costs)
            best = total if best is None else min(best, total)
    return best


def cheapest(check, others):
    """The check's cost: per VC, the fewest steps of any prover in the
    check's own tree or the same check's trees in the other runs; the
    largest over its VCs. None if some VC has no proof anywhere, or if a
    run's tree has another shape (the match between runs is then in
    doubt, and the answer must not be a guess)."""
    trees = [check.get("check_tree") or []]
    trees += [o.get("check_tree") or [] for o in others]
    if any(len(tree) != len(trees[0]) for tree in trees):
        return None
    worst = 0
    for index in range(len(trees[0])):
        costs = [c for c in (node_cost(tree[index]) for tree in trees)
                 if c is not None]
        if not costs:
            return None
        worst = max(worst, min(costs))
    return worst


def node_status(node):
    """proved, clean (failed within the budget), tainted, or unattempted
    (GNATprove stops attempting a check's other VCs once one fails, so a
    VC with no attempt says nothing either way), for one VC."""
    attempts = list((node.get("proof_attempts") or {}).values())
    if any(result_of(a) == "valid" for a in attempts):
        return "proved"
    branches = []
    for subgoals in (node.get("transformations") or {}).values():
        if not isinstance(subgoals, list):
            continue
        statuses = [node_status(s) for s in subgoals]
        if all(s == "proved" for s in statuses):
            return "proved"
        branches.append("clean" if "clean" in statuses else "tainted")
    if not attempts and not branches:
        return "unattempted"
    clean_here = bool(attempts) and all(
        result_of(a).startswith(CLEAN_FAILURES) for a in attempts)
    if not clean_here or "tainted" in branches:
        return "tainted"
    return "clean"


def check_status(check):
    """clean when some VC was attempted and every attempt on it failed
    within the budget; tainted when no VC is clean and some failed through a
    timeout, memory or a crash. A check with no attempted VC at all is
    neither: it is not evidence of anything and counts as tainted."""
    statuses = [node_status(n) for n in check.get("check_tree") or []]
    if "clean" in statuses:
        return "clean"
    return "tainted"


def margin(limit, costs_path, directory, provers, units):
    over = 0
    costs = {}
    for unit in units:
        stem = os.path.splitext(os.path.basename(unit))[0]
        path = os.path.join(directory, "baseline.%s.spark" % stem)
        try:
            checks = load(path)
            singles = [dict(identities(load(os.path.join(
                           directory, "baseline.%s.%s.spark" % (stem, p)))))
                       for p in provers]
        except (OSError, ValueError, KeyError) as error:
            print("%s: unreadable results (%s)" % (stem, error))
            return 2
        unproved = [c for c in checks if c.get("severity") != "info"]
        if unproved:
            print("%s: %d unproved check(s), first %s"
                  % (stem, len(unproved), where(unproved[0])))
            return 2
        ranked = []
        for ident, check in identities(checks):
            others = [s[ident] for s in singles if ident in s]
            if len(others) != len(singles):
                print("%s: %s is missing from a single-prover run"
                      % (stem, where(check)))
                return 2
            steps = cheapest(check, others)
            if steps is None:
                print("%s: no proof found for a VC of %s"
                      % (stem, where(check)))
                return 2
            costs[key(check)] = max(steps, costs.get(key(check), 0))
            ranked.append((steps, cost(check), check))
        ranked.sort(key=lambda r: r[0], reverse=True)
        top = ranked[0][0] if ranked else 0
        print("%s: %d checks, costliest %d steps (limit %d)"
              % (stem, len(checks), top, limit))
        for steps, raced, check in ranked[:3]:
            print("  %6d %s (raced: %d)" % (steps, where(check), raced))
        for steps, raced, check in ranked:
            if steps > limit:
                over += 1
                print("  OVER %d: %s (%d steps)" % (limit, where(check), steps))
    with open(costs_path, "w", encoding="utf-8") as handle:
        json.dump(costs, handle, indent=1, sort_keys=True)
    return 1 if over else 0


def judge(unit, path, baseline_path):
    stem = os.path.splitext(os.path.basename(unit))[0]
    own = {stem + ".ads", stem + ".adb"}
    try:
        checks = load(path)
    except (OSError, ValueError, KeyError) as error:
        print("no proof results: %s (%s)" % (path, error))
        return 2
    baseline = {}
    if baseline_path:
        try:
            with open(baseline_path, encoding="utf-8") as handle:
                baseline = json.load(handle)
        except (OSError, ValueError):
            baseline = {}
    # Only a failed proof counts: severity low, medium or high on a VC_
    # rule. A proof warning (an unreachable branch, an inconsistent
    # precondition) is not an unproved check.
    unproved = [c for c in checks
                if c.get("severity") in FAILED_SEVERITIES
                and str(c.get("rule", "")).startswith("VC_")
                and c["file"] in own]
    clean = 0
    for check in unproved:
        status = check_status(check)
        clean += status == "clean"
        base = baseline.get(key(check))
        print("  %s %s: %s (baseline: %s)"
              % (status, where(check),
                 check.get("message", {}).get("text", "?"),
                 "%d steps" % base if base is not None else "no such check"))
    if clean:
        print("verdict: caught (%d clean unproved check(s) in %s)"
              % (clean, stem))
        return 0
    if unproved:
        print("verdict: tainted (%d unproved check(s) in %s, none within"
              " the step budget)" % (len(unproved), stem))
        return 3
    print("verdict: none (no unproved check in %s)" % stem)
    return 4


def selftest():
    """Adversarial fixtures for the margin arithmetic. Returns 0 if all
    behave as the margin gate needs, 1 otherwise."""
    def valid(steps):
        return {"proof_attempts": {"Z3": {"result": "Valid", "steps": steps}}}

    def check(line, tree):
        return {"file": "u.adb", "line": line, "col": 1, "rule": "VC_ASSERT",
                "severity": "info", "check_tree": tree}

    failures = []

    def expect(name, got, want):
        if got != want:
            failures.append("%s: got %r, want %r" % (name, got, want))

    # A proof by transformation costs its dearest subgoal, not zero.
    transformed = {"transformations": {"split": [valid(9000), valid(10)]}}
    expect("transformed", cheapest(check(1, [transformed]), []), 9000)
    # A cheaper plain proof of the same VC wins over the transformation.
    both = dict(transformed, **valid(40))
    expect("transformed-or-plain", cheapest(check(1, [both]), []), 40)
    # The other runs can only lower a VC's cost.
    expect("other-run", cheapest(check(1, [valid(9000)]),
                                  [check(1, [valid(7)])]), 7)
    # A VC no run proved, or a tree of another shape: no answer.
    expect("unproved", cheapest(check(1, [{}]), []), None)
    expect("shape", cheapest(check(1, [valid(5)]),
                             [check(1, [valid(5), valid(5)])]), None)
    # A valid attempt without a step count proves nothing here.
    expect("stepless", cheapest(
        check(1, [{"proof_attempts": {"Z3": {"result": "Valid"}}}]), []),
        None)
    # Checks that share a place and rule keep their own identities.
    twins = identities([check(1, [valid(9000)]), check(1, [valid(1)])])
    expect("twins", [name for name, _ in twins],
           ["u.adb:1:1 VC_ASSERT #1", "u.adb:1:1 VC_ASSERT #2"])
    lookup = dict(twins)
    expect("twin-costs",
           [cheapest(c, [lookup[n]]) for n, c in twins], [9000, 1])
    for line in failures:
        print("selftest FAILED: " + line)
    print("selftest: %d failed" % len(failures))
    return 1 if failures else 0


def main(argv):
    if argv == ["selftest"]:
        return selftest()
    if len(argv) >= 6 and argv[0] == "margin":
        return margin(int(argv[1]), argv[2], argv[3],
                      [p for p in argv[4].split(",") if p], argv[5:])
    if len(argv) in (3, 4) and argv[0] == "judge":
        return judge(argv[1], argv[2], argv[3] if len(argv) == 4 else None)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
