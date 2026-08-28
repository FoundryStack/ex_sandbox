#!/usr/bin/env bash
# Runs `005`'s isolation and reclamation suites inside the systemd container.
#
# ⚠️ The `--include` flags are the entire point of this script. `test_helper.exs`
# excludes both tags off Linux and on a Linux host lacking the capabilities;
# inside this container it excludes neither, but passing them explicitly means an
# accidental change to that helper cannot silently reduce this run to the tests
# that were already passing on the developer's machine.
#
# ## One phase, where Axonn's copy of this script has three
#
# The umbrella version runs a credentials conformance phase and a
# production-path provisioning phase either side of this one, both from
# `apps/axonn`, because both need a database and a host schema. Neither belongs
# here: this library has no data store and `012-FR-001` says it must not grow
# one. What that costs is visible rather than hidden -- the credentials group
# reports `capability_unavailable`, the third outcome, and the census prints the
# count.
#
# So there is no multi-phase verdict block at the foot of this file. The census
# gate's status IS the container's status.
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
echo "storage fs:    $(stat -f -c %T /var/lib/ex_sandbox/sandboxes 2>/dev/null || echo MISSING)"
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

echo
echo "== isolation + reclamation suites =="

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

set +e
mix test --include isolation --include reclamation \
  --formatter ExUnit.CLIFormatter \
  --formatter ExSandbox.Conformance.Census "$@"
suite_status=$?
set -e

echo
echo "== conformance census (012-FR-016a) =="
echo "run id: $RUN_ID"
[ -f "$CENSUS" ] && cat "$CENSUS"

# Every guard -- missing census, `ran=0`, unreadable counts, genuine failures --
# lives in `census_gate` and is exercised by its own test.
#
# ⚠️ This IS the last statement, unlike in Axonn's copy where two further phases
# follow and the gate has to capture rather than exit. Here the gate's verdict is
# the container's verdict, so `exec`-like finality is correct.
census_gate "$CENSUS" "isolation + reclamation" "$suite_status" "isolation"
