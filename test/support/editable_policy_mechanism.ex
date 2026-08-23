defmodule ExSandbox.EditablePolicyMechanism do
  @moduledoc """
  A mechanism whose allowlist is **enforced but editable from inside**
  (005 T060a7; `005-FR-011b`).

  ## The shape a first implementation actually produces

  `ExSandbox.OpenNetworkMechanism` declares every handle and confines nothing.
  That is the *careless* failure, and it is easy to catch: every denial check
  has something to observe going wrong.

  This module is the *diligent* failure, and it is the one worth guarding
  against. The allowlist here is real. Denied destinations are genuinely
  refused, the permitted destination is genuinely reachable, and one sandbox
  genuinely cannot reach another. It would pass a review. It would pass a demo.
  Four of the five network checks pass honestly.

  Its single defect is that the policy file it consults lives where tenant code
  can append to it. Nothing leaks *yet* — the boundary holds against every
  connection the suite attempts. It holds until the subject decides otherwise,
  which is not a boundary, and `FR-011b` is the only check in the group that
  can tell the difference.

  ## Why it must fail exactly one check

  A fixture that failed several would not prove `FR-011b` is doing any work: the
  meta-test could stay green on the strength of the others while the widening
  check silently rotted. So this mechanism is deliberately built to be
  conformant in every other respect, and the meta-test asserts both halves —
  that `FR-011b` fails, and that the other four still pass.

  ⚠️ The policy is consulted, not merely stored. `check_permitted/2` reads the
  file on every connect, so an append by tenant code changes behaviour for real.
  A fixture that ignored its own file would be testing that the suite notices a
  writable file, which is a much weaker claim than the one `FR-011b` makes.
  """
  @behaviour ExSandbox.Mechanism

  # The one destination the environment permits. Reachable, and reachable for a
  # real reason -- the suite's permitted-direction check must pass honestly here.
  @permitted {"127.0.0.1", 9}

  @impl true
  def required_capabilities, do: []

  @impl true
  def provision(sandbox), do: {:ok, %{sandbox | mechanism_ref: "editable-" <> sandbox.id}}

  @impl true
  def start(sandbox) do
    path = policy_path(sandbox)

    # A real allowlist, written at start. Default-deny: only what is listed.
    File.write!(path, "127.0.0.1/32\n")

    context =
      (sandbox.context || %{})
      |> Map.put(:exec, &host_exec/1)
      |> Map.put(:address, {"127.0.0.1", unique_port(sandbox)})
      |> Map.put(:permitted, @permitted)
      |> Map.put(:policy_handle, path)
      |> Map.put(:connect, &check_permitted(path, &1, &2))

    {:ok, %{sandbox | context: context}}
  end

  @impl true
  def stop(sandbox), do: {:ok, sandbox}

  @impl true
  def destroy(sandbox) do
    File.rm(policy_path(sandbox))
    :ok
  end

  @impl true
  def status(_sandbox), do: {:ok, :running}

  @impl true
  def list_running, do: {:ok, []}

  @impl true
  def usage(_sandbox), do: {:ok, %{}}

  # ⚠️ Enforcement is genuine and re-reads the policy every time. The permitted
  # destination connects; everything else is refused. This is what makes the
  # fixture dangerous rather than a strawman: the boundary really does hold
  # against every connection the suite attempts.
  defp check_permitted(policy_path, host, port) do
    allowed = File.read!(policy_path)

    cond do
      # `127.0.0.1/32` is the only entry until tenant code appends. Matched by
      # prefix rather than parsed -- a fixture, not a router.
      String.contains?(allowed, "#{host}/32") and {host, port} == @permitted -> :connected
      String.contains?(allowed, "0.0.0.0/0") -> :connected
      true -> :refused
    end
  end

  # Inside the "sandbox", by construction: the whole defect is that the policy
  # is configured *in* the confined space rather than enforced *around* it.
  #
  # Distinct per sandbox for the same reason as `unique_port/1` below. A fixed
  # path is one file shared by every test that starts this mechanism, so a
  # second test's `start` resets the allowlist the first has just widened, and
  # its `destroy` deletes the file the first is still reading. `sandbox.id` is
  # unique across VM runs (`Conformance.Helpers.build_sandbox/1`), so two
  # concurrent `mix test` invocations stay apart too, which a bare counter
  # would not.
  defp policy_path(sandbox), do: "/tmp/ex-sandbox-editable-allowlist-#{sandbox.id}"

  # Distinct per sandbox so the peer-crossing check has a real address to aim
  # at. Nothing listens there, so the attempt is refused -- correctly, because
  # this mechanism does confine sandboxes from each other.
  defp unique_port(sandbox), do: 20_000 + :erlang.phash2(sandbox.id, 10_000)

  defp host_exec(command) do
    {output, _status} = System.cmd("sh", ["-c", command], stderr_to_stdout: true)
    {:ok, output}
  rescue
    error -> {:error, error}
  end
end
