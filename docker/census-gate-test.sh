#!/usr/bin/env bash
# Executes `census_gate` against every census shape it claims to handle
# (005 T060h).
#
# ⚠️ The gate decides whether a container run is green. It was written with
# careful comments and never run against the cases those comments describe.
# This project has now found three guards that read correctly and returned the
# wrong answer on the exact path they were written to catch, and not one was
# caught by review -- each came from executing it against the failure it claims
# to detect. This file does that for the gate.
#
# Runs on any POSIX host with bash; no container, no Elixir, no Docker.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=docker/census-gate.sh
. "$DIR/census-gate.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0 fail=0

# `expect <expected-status> <description> <census-body-or-NONE> <suite-status>`
expect() {
  local want="$1" desc="$2" body="$3" status="$4"
  local census="$TMP/census.txt"

  rm -f "$census"
  [ "$body" = "NONE" ] || printf '%s\n' "$body" > "$census"

  local out got
  out=$(census_gate "$census" "test" "$status")
  got=$?

  if [ "$got" -eq "$want" ]; then
    printf '  ok   %-56s (exit %s)\n' "$desc" "$got"
    pass=$((pass + 1))
  else
    printf '  FAIL %-56s expected %s, got %s\n' "$desc" "$want" "$got"
    printf '       gate said: %s\n' "$out"
    fail=$((fail + 1))
  fi
}

echo "== census gate (012-FR-016a) =="

# The only shape that may exit 0: checks ran, nothing failed. Third outcomes
# present and forgiven -- the whole reason the gate exists.
expect 0 "clean run with third outcomes is a pass" \
  "passed=195
unavailable=9
failed=0
invalid=0
ran=204" 0

expect 0 "clean run with no third outcomes is a pass" \
  "passed=204
unavailable=0
failed=0
invalid=0
ran=204" 0

# A genuine defect propagates the suite's own status, so the container's
# `--exit-code-from` carries something meaningful.
expect 2 "a genuine failure propagates the suite status" \
  "passed=194
unavailable=9
failed=1
invalid=0
ran=204" 2

# ⚠️ The false pass this gate exists to prevent. `failed=0` is well-formed and
# gating on it alone exits 0 for a suite that demonstrated nothing -- a mistyped
# --include, a bad filter, a suite that failed to load.
expect 1 "ran=0 is a failure even though failed=0" \
  "passed=0
unavailable=0
failed=0
invalid=0
ran=0" 0

# ⚠️ Exit 1 rather than the suite's 0. A dropped --formatter leaves `mix test`
# passing on its own terms and no census written; propagating that status would
# exit 0 while claiming to treat it as a failure.
expect 1 "a missing census fails, even when mix test exited 0" \
  NONE 0

expect 1 "a missing census fails when mix test also failed" \
  NONE 2

# A truncated or malformed census must not read as clean. Both keys absent
# means `failed` defaults to 1 and `ran` to 0; either alone is enough to fail.
expect 1 "a census with no counts at all fails closed" \
  "garbage" 0

expect 1 "a census missing 'failed' fails closed" \
  "passed=10
unavailable=0
invalid=0
ran=10" 0

expect 1 "a census missing 'ran' fails closed" \
  "passed=10
unavailable=0
failed=0
invalid=0" 0

# -- The caller's side of the contract ----------------------------------------
#
# ⚠️ The gate returning the right status is only half of it; the runner has to
# propagate it. The obvious spelling is wrong, and it was written that way and
# caught here: `if ! census_gate ...; then exit $?; fi` exits **0** on a failing
# phase, because `!` inverts the status and `$?` inside the branch is the
# negation's 0 rather than the gate's. A credentials phase reporting 3 genuine
# failures would have let the run continue and exited green.
echo
echo "== the runner's propagation of the gate's status =="

propagation() {
  local want="$1" desc="$2" body="$3" status="$4"
  printf '%s\n' "$body" > "$TMP/prop.txt"

  local got
  (
    set +e
    census_gate "$TMP/prop.txt" "phase" "$status" >/dev/null
    gate_status=$?
    set -e
    [ "$gate_status" -ne 0 ] && exit "$gate_status"
    exit 0
  )
  got=$?

  if [ "$got" -eq "$want" ]; then
    printf '  ok   %-56s (exit %s)\n' "$desc" "$got"
    pass=$((pass + 1))
  else
    printf '  FAIL %-56s expected %s, got %s\n' "$desc" "$want" "$got"
    fail=$((fail + 1))
  fi
}

propagation 2 "a failing phase stops the run with its status" \
  "passed=1
unavailable=0
failed=3
invalid=0
ran=4" 2

propagation 0 "a clean phase lets the run continue" \
  "passed=4
unavailable=1
failed=0
invalid=0
ran=5" 0

# -- The baseline on the third outcome (005 T060e) ----------------------------
#
# ⚠️ `failed=0` alone lets a guarantee stop being demonstrated silently. These
# cases pin the ceiling behaviour: growth fails, equality and shrinkage pass,
# and an ungated phase is unaffected.
echo
echo "== the unavailable baseline (005 T060e) =="

baseline_case() {
  local want="$1" desc="$2" phase="$3" body="$4"
  printf '%s\n' "$body" > "$TMP/bl.txt"

  local got
  CENSUS_BASELINE="$TMP/baseline.txt" census_gate "$TMP/bl.txt" "$phase" 0 >/dev/null
  got=$?

  if [ "$got" -eq "$want" ]; then
    printf '  ok   %-56s (exit %s)\n' "$desc" "$got"
    pass=$((pass + 1))
  else
    printf '  FAIL %-56s expected %s, got %s\n' "$desc" "$want" "$got"
    fail=$((fail + 1))
  fi
}

cat > "$TMP/baseline.txt" <<'BL'
# a comment, and a blank line follows

isolation 9
credentials 3
BL

baseline_case 0 "unavailable equal to the baseline passes" "isolation" \
  "passed=195
unavailable=9
failed=0
invalid=0
ran=204"

# Going down is progress -- T060a is expected to take isolation from 9 to 6 --
# and must never fail.
baseline_case 0 "unavailable below the baseline passes" "isolation" \
  "passed=198
unavailable=6
failed=0
invalid=0
ran=204"

# The regression this exists to catch: a check that moved from passing to
# unavailable. `failed=0`, and without the baseline this exits 0.
baseline_case 1 "unavailable above the baseline fails" "isolation" \
  "passed=194
unavailable=10
failed=0
invalid=0
ran=204"

baseline_case 1 "a one-check regression is caught" "credentials" \
  "passed=34
unavailable=4
failed=0
invalid=0
ran=38"

# A phase with no baseline entry is not gated -- the file lists what it gates
# rather than gating everything at zero.
baseline_case 0 "a phase absent from the baseline is not gated" "reclamation" \
  "passed=1
unavailable=40
failed=0
invalid=0
ran=41"

# ⚠️ A genuine failure must still win. Reporting only the baseline breach for a
# run that also has real defects would bury the more serious result.
baseline_case 1 "a genuine failure outranks a baseline breach" "isolation" \
  "passed=190
unavailable=12
failed=2
invalid=0
ran=204"

# ⚠️ The hole the case above exposed, pinned directly. `return "${status:-1}"`
# substitutes only when the value is unset or empty, so a caller passing a
# literal 0 alongside `failed=2` returned **0** -- genuine defects exiting
# green. `mix test` does exit non-zero for real failures, so every path taken so
# far happened to agree, and the bug was invisible until a test passed 0.
expect 1 "genuine failures never exit 0, even if the suite did" \
  "passed=202
unavailable=0
failed=2
invalid=0
ran=204" 0

# -- The keys the production script actually gates on --------------------------
#
# ⚠️ Every case above passes a baseline key directly, and that is exactly how
# this file passed while the phase it was written to protect ran ungated. The
# gate took one argument for both the prose label and the lookup key;
# `run-isolation-tests.sh` calls it with `isolation + reclamation`;
# `census-baseline.txt` keys that phase `isolation`; `awk '$1 == p'` cannot match
# a key with a space in it. The lookup returned empty, the ceiling branch was
# skipped, and the gate printed "No mechanism defects" -- true, and not the
# question. Measured: `unavailable=8` against a baseline of 7, exit 0.
#
# So this reads the REAL invocations out of the script rather than restating
# them, and fails if any resolved key is absent from the baseline file. A phase
# deliberately left ungated is spelled out in `UNGATED` below, which makes
# "not gated" a decision someone wrote down rather than a typo nobody can see.
echo
echo "== the keys run-isolation-tests.sh gates on =="

UNGATED="credentials-does-not-appear-here"

# ⚠️ Tab-delimited, with `IFS` set for the read, because the failure being
# tested is EXACTLY a key with a space in it. Splitting on ordinary whitespace
# made this loop reproduce the bug instead of catching it: the un-keyed call
# yields the key `isolation + reclamation`, `read -r key label` took the first
# word, `census_baseline isolation` found 7, and the case reported `ok`. A test
# for a whitespace defect cannot itself split on whitespace.
while IFS=$'\t' read -r key label; do
  [ -n "$key" ] || continue

  # Herestring, not `printf | grep -q`: under `pipefail` a matching `grep -q`
  # closes the pipe and the producer's SIGPIPE becomes the pipeline's status,
  # so the match reports as a non-match. `$UNGATED` is short enough today that
  # `printf` finishes first, which makes this a property of the current data
  # rather than of the code.
  if grep -qx "$key" <<<"$UNGATED"; then
    printf '  ok   %-56s (ungated by decision)\n' "$label"
    pass=$((pass + 1))
    continue
  fi

  if [ -n "$(CENSUS_BASELINE="$DIR/census-baseline.txt" census_baseline "$key")" ]; then
    printf '  ok   %-56s (key %s)\n' "$label" "$key"
    pass=$((pass + 1))
  else
    printf '  FAIL %-56s key %s is absent from census-baseline.txt\n' "$label" "$key"
    fail=$((fail + 1))
  fi
done <<EOF
$(grep -oE 'census_gate "[^"]*" "[^"]*" "[^"]*"( "[^"]*")?' "$DIR/run-isolation-tests.sh" |
  awk -F'"' '{ label = $4; key = (NF >= 8 && $8 != "" ? $8 : label); print key "\t" label }')
EOF

echo
echo "  ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
