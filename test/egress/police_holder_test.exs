defmodule ExSandbox.Egress.PoliceHolderTest do
  @moduledoc """
  `NodeLauncher.police/2` installs the redirect only through a process whose
  network namespace differs from this VM's (D6 of `let-sandboxes-outlive-a-deploy`).
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.LaunchPlan
  alias ExSandbox.Mechanism.Beam.NodeLauncher

  @moduletag :tmp_dir
  @moduletag :capture_log

  defp proc_root(dir, own, holder) do
    for {pid, target} <- [{"self", own}, {"42", holder}] do
      File.mkdir_p!(Path.join([dir, pid, "ns"]))
      File.ln_s!(target, Path.join([dir, pid, "ns", "net"]))
    end

    dir
  end

  test "a holder in this VM's namespace is refused", %{tmp_dir: dir} do
    proc = proc_root(dir, "net:[4026531840]", "net:[4026531840]")
    assert {:error, :host_namespace} = NodeLauncher.confined_holder(42, proc_root: proc)
  end

  test "a holder in its own namespace is accepted", %{tmp_dir: dir} do
    proc = proc_root(dir, "net:[4026531840]", "net:[4026532999]")
    assert {:ok, 42} = NodeLauncher.confined_holder(42, proc_root: proc)
  end

  test "an unreadable or missing holder is refused", %{tmp_dir: dir} do
    proc = proc_root(dir, "net:[1]", "net:[2]")
    assert {:error, :unreadable_namespace} = NodeLauncher.confined_holder(7, proc_root: proc)
    assert {:error, :no_holder} = NodeLauncher.confined_holder(nil)
  end

  test "police installs nothing through a host-namespace holder", %{tmp_dir: dir} do
    proc = proc_root(dir, "net:[4026531840]", "net:[4026531840]")
    test = self()

    result =
      NodeLauncher.police(%LaunchPlan{source_key: {10, 0, 0, 0}, pool_port: 18_080},
        holder_pid: 42,
        proc_root: proc,
        runner: fn steps ->
          send(test, {:ran, steps})
          :ok
        end,
        acceptor_starter: fn _, _, _ ->
          send(test, :started)
          {:ok, self()}
        end
      )

    assert result == {:error, :mechanism_error}
    refute_received {:ran, _}
    refute_received :started
  end
end
