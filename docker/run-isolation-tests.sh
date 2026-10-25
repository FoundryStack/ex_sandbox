#!/usr/bin/env bash
# Runs `005`'s isolation and reclamation suites inside the systemd container.
#
# ⚠️ The `--include` flags are the entire point of this script. `test_helper.exs`
# excludes both tags off Linux and on a Linux host lacking the capabilities;
# inside this container it excludes neither, but passing them explicitly means an
# accidental change to that helper cannot silently reduce this run to the tests
# that were already passing on the developer's machine.
#
# ## Phases
#
# The variables come from `/etc/isolation.env` (see `compose.isolation.yml` for
# the table and defaults). This library's own run is one census-gated phase.
# A consumer with a database adds `ISOLATION_SETUP` (run first; failure stops
# the run, since checks against a database that does not exist are refused for
# that reason and read as containment) and `ISOLATION_PLAIN_TESTS`, an ordinary
# `mix test` phase with no third outcome, run after the gated one.
set -euo pipefail

# The gate that decides whether a phase counts as passed lives in its own file
# so it can be executed by a test rather than only read. Its first run found that
# a census missing `failed=` exited 0 -- see the comments there.
. "$(dirname "$0")/census-gate.sh"

# ⚠️ Every artefact is cleared **here**, before any phase can bail, and a run
# marker is stamped.
#
# `docker/results` is a bind mount, so files persist across runs and anything a
# run does not overwrite survives. Clearing up front means a missing artefact is
# missing, which every guard below already treats as a failure. The marker makes
# a mismatch legible rather than something a reader has to notice.
mkdir -p /var/log/ex_sandbox
rm -f /var/log/ex_sandbox/census.txt
RUN_ID="$(date -u +%Y-%m-%dT%H:%M:%SZ)-$$"
echo "$RUN_ID" > /var/log/ex_sandbox/run-id.txt

echo "== run =="
echo "run id:        $RUN_ID"
echo "(every artefact in this directory is from this run; they are cleared at start)"
echo

echo "== host facilities =="
echo "kernel:        $(uname -sr)"
echo "cgroup:        $(stat -f -c %T /sys/fs/cgroup 2>/dev/null || echo MISSING)"
echo "storage fs:    $(stat -f -c %T "$ISOLATION_STORAGE_DIR" 2>/dev/null || echo MISSING)"
for bin in systemd-run setpriv bwrap pasta nsenter; do
  printf '%-14s %s\n' "$bin:" "$(command -v "$bin" || echo MISSING)"
done

# Report the capability map before running anything. A suite that skips every
# test still exits 0, so without this an unhardened container is indistinguishable
# from a passing run -- the precise failure this whole harness exists to remove.
echo
echo "== ExSandbox.Hardening.Linux.capabilities/0 =="
cd /app
mix run --no-start -e '
  caps = ExSandbox.Hardening.Linux.capabilities()
  Enum.each(caps, fn {k, v} ->
    IO.puts("  #{if v, do: "\e[32mok  \e[0m", else: "\e[31mMISS\e[0m"} #{k}")
  end)
  available? = ExSandbox.Hardening.Linux.available?()
  IO.puts("\navailable?: #{available?}")

  # ⚠️ The gate refuses when **nothing** can be verified, not when the mechanism
  # is short of a capability.
  #
  # `available?/0` is all-or-nothing, and correctly so: a sandbox missing any
  # capability must not launch, because a partially-confined tenant is worse
  # than none. But using it as the *run* gate conflates two questions -- "can a
  # sandbox launch here?" and "is there anything worth measuring here?" -- and
  # the second is still yes when four of five capabilities are present.
  #
  # Measured, and the reason this changed: once `probe_network_policy/0` stopped
  # over-claiming, `network_restriction` went false, `available?/0` went false,
  # and the harness refused to run **all 371 checks** -- including every one of
  # the four capabilities that do work. Correcting a probe should not blind the
  # census to everything else it can still measure. The groups that need the
  # missing capability report `capability_unavailable`, which is exactly the
  # third outcome `012-FR-016a` provides for.
  present = caps |> Enum.filter(fn {_k, v} -> v end) |> Enum.map(&elem(&1, 0))
  missing = caps |> Enum.reject(fn {_k, v} -> v end) |> Enum.map(&elem(&1, 0))

  if present == [] do
    IO.puts("\e[31m\nRefusing to run: no hardening capability is present, so every
isolation test would skip and this run would exit 0 having verified nothing.\e[0m")
    System.halt(1)
  end

  if missing != [] do
    IO.puts("\e[33m
⚠️  #{length(missing)} of #{map_size(caps)} capabilities are MISSING: #{Enum.join(missing, ", ")}

The suite will still run and will still be meaningful for #{Enum.join(present, ", ")}.
Checks needing a missing capability report `capability_unavailable` -- NOT a pass.
Read the census counts below as `passed` out of `ran`, never out of the total.\e[0m")
  end
'

# A diagnosis hatch. Probing the hardening path needs systemd as PID 1, which
# `--entrypoint /bin/sh` displaces, so a diagnostic script runs here instead:
#
#     docker compose -f docker/compose.isolation.yml \
#       run --rm -v "$PWD/probe.exs:/probe.exs:ro" \
#       -e ISOLATION_SCRIPT=/probe.exs isolation
#
# ⚠️ Read from PID 1's environment: `-e` sets it on systemd, and a unit starts
# with an empty environment. Only this one name is copied across.
if [ -z "${ISOLATION_SCRIPT:-}" ] && [ -r /proc/1/environ ]; then
  while IFS= read -r -d '' entry; do
    case "$entry" in
      ISOLATION_SCRIPT=*) ISOLATION_SCRIPT="${entry#ISOLATION_SCRIPT=}" ;;
    esac
  done < /proc/1/environ
fi

if [ -n "${ISOLATION_SCRIPT:-}" ]; then
  echo
  if [ ! -f "$ISOLATION_SCRIPT" ]; then
    echo "ISOLATION_SCRIPT=$ISOLATION_SCRIPT is set but no such file is in the container."
    echo "Mount it: -v \"\$PWD/probe.exs:$ISOLATION_SCRIPT:ro\""
    exit 1
  fi
  echo "== running ${ISOLATION_SCRIPT} =="
  exec mix run "$ISOLATION_SCRIPT"
fi

# ⚠️ A key absent from the baseline leaves the phase ungated: the ceiling is
# skipped and the gate reports no defects. `census-gate-test.sh` can check this
# library's key statically; a consumer's key is checked here.
if [ -z "$(census_baseline "$ISOLATION_CENSUS_KEY")" ]; then
  echo "ISOLATION_CENSUS_KEY=$ISOLATION_CENSUS_KEY has no line in census-baseline.txt."
  exit 1
fi

if [ -n "$ISOLATION_SETUP" ]; then
  echo
  echo "== setup: ${ISOLATION_SETUP} =="
  (cd "$ISOLATION_APP_DIR" && bash -c "$ISOLATION_SETUP")
fi

echo
echo "== census-gated suite (${ISOLATION_INCLUDE}) =="

# `012-FR-016a`: separate the third outcome from failure in the **exit code**.
#
# ⚠️ Not `exec`, and the `||` shape is load-bearing. `mix test` exits non-zero
# for a mechanism defect AND for a host that cannot demonstrate a check, because
# ExUnit has only two outcomes -- so this container exited 2 on every healthy run
# and `--exit-code-from isolation` carried no information at all. A real
# containment regression looked exactly like the credentials checks that are
# SUPPOSED to report unavailable here.
#
# The census formatter classifies what the suite already decided (it sets no
# verdicts) and writes the counts to $CENSUS. The policy applied below -- "all
# non-passes are third outcomes" is a pass -- lives here rather than in the
# library because it is a caller's judgement about this host, not a property of
# the contract.
CENSUS=/var/log/ex_sandbox/census.txt
export EX_SANDBOX_CENSUS_PATH="$CENSUS"
rm -f "$CENSUS"

include=()
for tag in $ISOLATION_INCLUDE; do include+=(--include "$tag"); done

set +e
# shellcheck disable=SC2086
(
  cd "$ISOLATION_APP_DIR"
  mix test "${include[@]}" \
    --formatter ExUnit.CLIFormatter \
    --formatter ExSandbox.Conformance.Census $ISOLATION_TESTS "$@"
)
suite_status=$?
set -e

echo
echo "== conformance census (012-FR-016a) =="
echo "run id: $RUN_ID"
[ -f "$CENSUS" ] && cat "$CENSUS"

# Every guard -- missing census, `ran=0`, unreadable counts, genuine failures --
# lives in `census_gate` and is exercised by its own test.
#
# ⚠️ Capture the status, then test it. `if ! census_gate ...; then exit $?; fi`
# exits **0** on a failing phase: `!` inverts the status, so `$?` inside the
# branch is the negation's 0. And capture rather than exit, so the plain phase
# below still reports when the gated one fails.
set +e
census_gate "$CENSUS" "${ISOLATION_CENSUS_KEY:-isolation}" "$suite_status"
gate_status=$?
set -e

[ -z "$ISOLATION_PLAIN_TESTS" ] && exit "$gate_status"

echo
echo "== plain suite: ${ISOLATION_PLAIN_TESTS} =="
# No census formatter: these are ordinary checks where a failure is a failure,
# and a census would invite a reader to look for an `unavailable=` line.
set +e
# shellcheck disable=SC2086
(cd "$ISOLATION_APP_DIR" && mix test $ISOLATION_PLAIN_TESTS)
plain_status=$?
set -e

echo
echo "== run verdict =="
echo "census gate: ${gate_status}"
echo "plain suite: ${plain_status}"

if [ "$gate_status" -ne 0 ]; then
  exit "$gate_status"
fi

exit "$plain_status"
