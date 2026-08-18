defmodule ExSandbox.Egress.PolicingFailureCleanupTest do
  @moduledoc """
  The cleanup path taken when policing fails must not itself crash
  (005 T060a4e).

  ## Why this file exists

  `police_or_terminate/3` handles the case where a tenant booted but the egress
  policy could **not** be installed. `contracts/egress.md` is explicit that this
  must tear the sandbox down rather than log and continue: a running tenant with
  no allowlist is worse than no tenant, because every denial check passes for
  reasons that have nothing to do with policy.

  The branch called `terminate(launched)` — passing the whole launch map to a
  function that takes a **pid**. `Process.alive?/1` raises `ArgumentError` on a
  map, so the recovery path destroyed the original `{:error, reason}` and
  replaced it with a crash inside the code meant to recover from the failure.

  ⚠️ **Latent since the branch was written, and structurally unreachable until
  T060a4e.** Policing is only attempted once a launch gets far enough to be
  policed, and before the split ordering the tenant died at `setpriv` every
  time. The first container run after the tenant started booting turned all
  five network checks into `ArgumentError: not a pid` naming
  `is_process_alive`, which reads as a defect in the conformance suite rather
  than a one-word error in the launcher.

  So this file pins the *contract* the crash violated, on a host where no launch
  can occur — which is where the bug would have been catchable all along.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Mechanism.Beam.NodeLauncher

  describe "terminate/2's contract" do
    test "accepts a pid and reports an already-dead one as success" do
      # `003`'s idempotency rule: terminating something already gone is :ok.
      pid = spawn(fn -> :ok end)
      ref = Process.monitor(pid)
      assert_receive {:DOWN, ^ref, :process, ^pid, _}

      assert NodeLauncher.terminate(pid) == :ok
    end

    test "raises rather than silently no-ops when handed a launch map" do
      # ⚠️ This asserts the CRASH, deliberately. The bug was not that
      # `terminate/2` is strict -- strictness is what made the mistake visible
      # at all. A version that shrugged at a non-pid would have let the failure
      # path skip the teardown entirely, leaving a booted tenant with no policy
      # running while `provision/2` returned an error: the unenforced-allowlist
      # outcome `contracts/egress.md` names as worse than failing.
      #
      # Pinning it here means a future "tolerant" rewrite of `terminate/2` has
      # to confront that trade rather than make it by accident.
      launched = %{node: :nonode@nohost, os_pid: 1, peer: self(), cookie: :c}

      assert_raise ArgumentError, fn -> NodeLauncher.terminate(launched) end
    end

    test "the peer field of a launch map is what satisfies it" do
      # The fix, stated as the relationship it restores: whatever shape the
      # launch map grows, the thing handed to `terminate/2` is its `:peer`.
      launched = %{node: :nonode@nohost, os_pid: 1, peer: spawn(fn -> :ok end), cookie: :c}

      assert is_pid(launched.peer)
      assert NodeLauncher.terminate(launched.peer) == :ok
    end
  end
end
