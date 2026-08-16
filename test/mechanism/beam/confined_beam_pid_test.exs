defmodule ExSandbox.Mechanism.Beam.ConfinedBeamPidTest do
  @moduledoc """
  `confined_beam_pid/1` selects the process whose confinement gets verified.

  The bug it exists to prevent was silent in the worst direction: `bwrap` forks,
  the port's pid stays in the origin's namespaces, and `verify_applied/1`
  reported `:not_applied` for a sandbox that was genuinely confined. A retry loop
  or a widened check would have "fixed" that by accepting the wrong process.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Mechanism.Beam.NodeLauncher

  describe "selection" do
    @tag :isolation
    test "a BEAM below the root is found by name, not by position" do
      # Rooted at the test runner, which IS a `beam.smp`. With no sandbox
      # running concurrently the tree holds exactly one and the answer is this
      # process; with sandboxes running it holds several and the guard fires.
      # Both are correct -- what must never happen is an arbitrary pick -- so
      # this asserts the disjunction rather than depending on suite ordering.
      #
      # Two earlier versions were each wrong in one direction: asserting
      # `:no_beam_process` passed on macOS only for want of `/proc`, and
      # asserting `{:ok, self}` passed only when nothing else was running.
      case NodeLauncher.confined_beam_pid(self_os_pid()) do
        {:ok, pid} ->
          assert pid == self_os_pid()

        {:error, {:ambiguous_beam_processes, pids}} ->
          assert self_os_pid() in pids
          assert length(pids) > 1
      end
    end

    test "a pid with no /proc entry yields no BEAM rather than crashing" do
      # Off Linux there is no `/proc` at all, and a pid that exits mid-walk looks
      # identical. Both must be ordinary failures -- verification runs on the
      # launch path, and an exception there would turn a recoverable failed
      # launch into a crash in whoever asked to provision.
      assert {:error, :no_beam_process} = NodeLauncher.confined_beam_pid(2_147_483_646)
    end
  end

  defp self_os_pid, do: :os.getpid() |> List.to_integer()
end
