#!/usr/bin/env bash
# The census gate: decides whether a suite run counts as passed (012-FR-016a).
#
# ⚠️ This lives in its own file so it can be **executed** by a test rather than
# only read. It was previously inline in `run-isolation-tests.sh`, duplicated
# once per phase, and it is the single point where a green run is decided --
# exactly the kind of guard this project has now three times found reads
# correctly and behaves wrongly (`SuiteRunner`'s missing setup, `attempt_self_halt`,
# `attempt_host_process_list`). None of those were caught by review. See
# `docker/census-gate-test.sh` for the cases.
#
# The policy -- "all non-passes are third outcomes" is a pass -- lives here
# rather than in the library because it is a caller's judgement about this
# host, not a property of the contract.

# `census_gate <census-path> <phase-label> <suite-exit-status>`
#
# Echoes an explanation and returns the exit status the phase should carry.
# Every branch fails *closed*: an unreadable or absent run is not a passed one.
# ⚠️ `baseline_key` is separate from `label`, and the two drifting apart is a
# measured defect, not a hypothetical (2026-08-23). This took `$2` for both, and
# `run-isolation-tests.sh` calls it with the label `isolation + reclamation`
# while `census-baseline.txt` keys that phase `isolation`. `census_baseline`
# matches on `$1` under awk, a key with a space cannot be a field, so the lookup
# returned the empty string and the ceiling branch was skipped: the phase ran
# **ungated** for as long as the baseline file has existed.
#
# It was invisible from both ends. The gate printed "No mechanism defects", which
# is true, and silently omitted the `(baseline for ...)` line, which nobody was
# looking for. `census-gate-test.sh` exercised the ceiling thoroughly and passed
# the KEY (`isolation`) every time, so it tested a call the production script
# never makes. Measured when it finally mattered: `unavailable=8` against a
# baseline of 7, gate 0.
#
# The pairing itself is now pinned by `census-gate-test.sh`, which reads the
# real `census_gate` invocations out of `run-isolation-tests.sh` and asserts
# every resolved key exists in the baseline file. A label may still be prose;
# the key it gates on may not be a guess.
census_gate() {
  local census="$1" label="$2" status="${3:-1}" baseline_key="${4:-$2}"

  # ⚠️ A missing census is a failure, never a pass. If the formatter did not run
  # -- a crashed VM, a compile error, a renamed or dropped `--formatter` -- the
  # file is absent, and defaulting that to "no defects" would hand back exit 0
  # for a suite that never reported.
  #
  # ⚠️ Returns 1, **not** `$status`. Deleting the census's `--formatter` flag
  # leaves a suite that passes on its own terms: `mix test` exits 0, no census
  # is written, and propagating that status would exit 0 here while this very
  # branch claims to be treating it as a failure. Measured on the shell, not
  # reasoned about.
  if [ ! -f "$census" ]; then
    echo "No census at $census -- the ${label} phase did not report."
    echo "(mix test exited ${status}; a run that did not report has not passed.)"
    return 1
  fi

  local failed ran unavailable
  failed=$(sed -n 's/^failed=//p' "$census")
  ran=$(sed -n 's/^ran=//p' "$census")
  unavailable=$(sed -n 's/^unavailable=//p' "$census")

  # ⚠️ A run in which nothing executed is not a pass. Measured: with every test
  # excluded by a tag filter the census is a well-formed `failed=0`, and gating
  # on that alone exits 0 for a suite that demonstrated nothing -- the same
  # false pass as a green run on an unhardened host, arriving through the
  # runner. `ran` counts every outcome, so a mistyped `--include`, a bad filter,
  # or a suite that failed to load is caught here rather than reported as
  # success.
  # Same exposure as `failed` below: an empty `ran` skips `:-0` and errors, so
  # test for a readable integer rather than trusting the default.
  if ! [ "$ran" -eq "$ran" ] 2>/dev/null || [ "$ran" -eq 0 ]; then
    echo "No ${label} checks ran at all (ran=0). Treating as failure: a suite that"
    echo "demonstrated nothing has not passed."
    return 1
  fi

  # ⚠️ `${failed:-1}` is NOT enough, and this is the bug the gate's own test
  # found on its first run (005 T060h). `sed -n 's/^failed=//p'` on a census
  # with no `failed=` line yields the **empty string**, not an unset variable,
  # so `:-` never substitutes. `[ "" -ne 0 ]` is a syntax error, the `if`
  # takes its false branch, and the function falls through to the success
  # branch below: a truncated census exited **0**.
  #
  # That is the same defect species as the three already found in the suite --
  # a guard that reads correctly and returns green on the exact path it was
  # written to catch -- and it was sitting in the one place that decides
  # whether a container run is green. Only found by executing it.
  #
  # Match on the shape explicitly rather than leaning on parameter expansion.
  if ! [ "$failed" -eq "$failed" ] 2>/dev/null; then
    echo "The ${label} census has no readable 'failed' count -- it is truncated or"
    echo "malformed. A run that cannot be read has not passed."
    return 1
  fi

  # ⚠️ `return "${status:-1}"` alone is not safe: `:-` only substitutes when the
  # value is unset or empty, so a caller passing a literal `0` alongside
  # `failed=2` returns **0** -- a census reporting genuine defects exiting
  # green. `mix test` does exit non-zero for real failures, so the paths seen so
  # far happen to agree; the gate must not depend on its caller getting that
  # right. Propagate the suite's status when it is non-zero, and fall back to 1.
  if [ "$failed" -ne 0 ]; then
    echo "The ${label} phase reported ${failed} genuine failure(s) -- see above."
    if [ "${status:-0}" -ne 0 ]; then
      return "$status"
    fi
    return 1
  fi

  # ⚠️ `failed=0` is not the whole gate (005 T060e). The third outcome is honest,
  # but a mechanism that quietly stopped demonstrating a guarantee converts
  # failures into `unavailable` and this function would still return 0. The
  # suite would report a smaller set of guarantees every release and stay green.
  #
  # A ceiling rather than an equality: the count legitimately moves both ways,
  # and going down is progress. Going up requires editing the baseline, which is
  # the deliberate step that makes a silent regression impossible.
  local baseline
  baseline=$(census_baseline "$baseline_key")

  if [ -n "$baseline" ] && [ "${unavailable:-0}" -gt "$baseline" ]; then
    echo "The ${label} phase reported ${unavailable} check(s) as 'host capability"
    echo "unavailable', above its baseline of ${baseline}."
    echo
    echo "A check that moved from passing to unavailable is a guarantee that is no"
    echo "longer demonstrated -- a handle no longer published, a probe that started"
    echo "returning false. That is a regression wearing the third outcome's clothes."
    echo
    echo "If the increase is legitimate, raise the baseline in docker/census-baseline.txt"
    echo "deliberately, naming which checks moved and why."
    return 1
  fi

  echo "No mechanism defects in ${label}. ${unavailable:-0} check(s) reported the third"
  echo "outcome (host capability unavailable), which is neither a pass nor a defect."
  [ -n "$baseline" ] && echo "(baseline for ${label}: at most ${baseline})"
  return 0
}

# The baseline for `phase`, or the empty string when the phase is not gated or
# no baseline file is present. `CENSUS_BASELINE` lets the test point at a
# fixture; the runner leaves it unset and gets the checked-in file beside this
# script.
census_baseline() {
  local phase="$1"
  local file="${CENSUS_BASELINE:-$(dirname "${BASH_SOURCE[0]}")/census-baseline.txt}"

  [ -f "$file" ] || return 0
  # Comments and blank lines are skipped by the field match itself: a `#` line
  # has no second field matching a bare integer.
  awk -v p="$phase" '$1 == p && $2 ~ /^[0-9]+$/ { print $2; exit }' "$file"
}
