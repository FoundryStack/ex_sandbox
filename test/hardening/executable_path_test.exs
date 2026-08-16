defmodule ExSandbox.Hardening.ExecutablePathTest do
  @moduledoc """
  The launcher's program must be an **absolute path**, not a bare name
  (005 T036b, FR-007 – FR-011).

  ## The bug this exists to prevent

  `build_command/2` returned `{"systemd-run", args}`. Every probe in this module
  resolves binaries with `System.cmd/3`, which searches `PATH` — so the bare name
  works everywhere the capability probes look, and `available?/0` reports a fully
  hardened host.

  The launcher does not use `System.cmd/3`. `:peer` spawns via
  `open_port({:spawn_executable, Prog}, ...)`, and `:spawn_executable` **does not
  search `PATH`** — it requires a path it can `exec` directly. A bare name there
  raises `:enoent` with "invalid port name", from inside `:peer.init/1`, naming
  neither `systemd-run` nor the fact that a lookup was attempted.

  Found by running the isolation suite in a container with all five capabilities
  genuinely present: every launch failed identically. It is not a container
  artifact — the same call fails on any Linux host, because `PATH` resolution was
  never going to happen at that seam. It went unnoticed because the tests that
  would have caught it are the ones that cannot run on the development machine.

  ## Why this test is host-independent

  It asserts on the *shape* of what `compose/3` builds, so it runs on Darwin.
  That is the point: this defect was invisible precisely because it lived in code
  reachable only under Linux, and a check that also skips off Linux would restore
  the blind spot it was written to close.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Hardening.Linux

  defp sandbox do
    %ExSandbox.Sandbox{
      id: "sb-#{System.unique_integer([:positive])}",
      owner_ref: "owner-1",
      template_ref: "tpl",
      memory_limit_mb: 256,
      cpu_limit: 500,
      disk_quota_mb: 1024
    }
  end

  describe "the spawned program" do
    test "is an absolute path, because :spawn_executable does not search PATH" do
      {:ok, {prog, _args}} = Linux.compose_for_inspection(sandbox(), [])

      assert String.starts_with?(prog, "/"),
             """
             build_command/2 returned #{inspect(prog)} — a bare name.

             `:peer` spawns this with `open_port({:spawn_executable, prog}, ...)`,
             which requires a directly executable path. A bare name raises
             :enoent ("invalid port name") for every launch, on every Linux host,
             while all five capability probes still report available.
             """
    end

    test "names systemd-run, not some other resolved binary" do
      {:ok, {prog, _args}} = Linux.compose_for_inspection(sandbox(), [])

      assert Path.basename(prog) == "systemd-run"
    end
  end
end
