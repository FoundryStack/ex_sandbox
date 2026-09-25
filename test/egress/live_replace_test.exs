defmodule ExSandbox.Egress.LiveReplaceTest do
  @moduledoc """
  Changing a running sandbox's allowlist without restarting it.

  `Registry.replace/3` is the only path that overwrites a policy, and it must
  refuse the state `assign/3` accepts: a /30 with no entry. The acceptor-level
  proof that the next connection sees the new list is in
  `acceptor_relay_wiring_test.exs`; the Linux end to end one is
  `ExSandbox.Mechanism.Beam.UpdateEgressTest`.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Conformance.Helpers
  alias ExSandbox.Egress.Binding
  alias ExSandbox.Egress.Policy
  alias ExSandbox.Egress.Registry
  alias ExSandbox.Mechanism.Beam

  @old [{"a.example.com", 443}]
  @new [{"b.example.com", 443}]

  setup do
    registry =
      start_supervised!({Registry, name: :"replace_#{System.unique_integer([:positive])}"})

    %{registry: registry, key: Policy.source_key({10, 0, 0, 1})}
  end

  describe "Registry.replace/3" do
    test "replaces the list of a registered /30", %{registry: r, key: key} do
      :ok = Registry.assign(key, @old, r)

      assert :ok = Registry.replace(key, @new, r),
             "replace refused a registered /30, so no running sandbox can be updated"

      assert Registry.lookup(key, r) == @new
    end

    test "refuses a /30 with no policy, and creates none", %{registry: r, key: key} do
      assert {:error, :not_registered} = Registry.replace(key, @new, r)
      refute Registry.registered?(key, r)
    end

    test "refuses a released /30", %{registry: r, key: key} do
      :ok = Registry.assign(key, @old, r)
      :ok = Registry.release(key, r)

      assert {:error, :not_registered} = Registry.replace(key, @new, r)
      refute Registry.registered?(key, r)
    end

    test "keeps what the sandbox resolved", %{registry: r, key: key} do
      :ok = Registry.assign(key, [{"api.example.com", 443}], r)
      :ok = Registry.record_resolution(key, "api.example.com", [{93, 184, 216, 34}], r)

      :ok = Registry.replace(key, [{"api.example.com", 443}, {"b.example.com", 443}], r)

      assert Policy.permits?(
               Registry.lookup(key, r),
               {{93, 184, 216, 34}, 443},
               Registry.resolutions(key, r)
             ),
             "a name resolved before the replace no longer matches after it"
    end

    test "assign/3 still refuses to overwrite after a replace", %{registry: r, key: key} do
      :ok = Registry.assign(key, @old, r)
      :ok = Registry.replace(key, @new, r)

      assert {:error, {:still_registered, ^key}} = Registry.assign(key, @old, r)
      assert Registry.lookup(key, r) == @new
    end
  end

  describe "Binding.rebind/3" do
    test "replaces the policy under the binding's /30", %{registry: r} do
      {:ok, binding} = Binding.acquire(@old, registry: r)

      assert :ok = Binding.rebind(binding, @new, registry: r)
      assert Registry.lookup(binding.source_key, r) == @new

      :ok = Binding.release(binding, registry: r)
    end

    test "refuses a released binding", %{registry: r} do
      {:ok, binding} = Binding.acquire(@old, registry: r)
      :ok = Binding.release(binding, registry: r)

      assert {:error, :not_registered} = Binding.rebind(binding, @new, registry: r)
      refute Registry.registered?(binding.source_key, r)
    end
  end

  describe "ExSandbox.update_egress/4" do
    test "a mechanism without the callback answers :egress_not_enforced" do
      sandbox = Helpers.build_sandbox()

      assert {:error, :egress_not_enforced} =
               ExSandbox.update_egress(ExSandbox.Mechanism.Docker, sandbox, ["1.1.1.1:443"],
                 host_aliases: []
               )
    end

    test "entries are parsed as at provision, and a refused one is refused" do
      sandbox = Helpers.build_sandbox()

      assert {:error, {:refused_entries, [{"169.254.169.254:80", :cloud_metadata}]}} =
               ExSandbox.update_egress(Beam, sandbox, ["169.254.169.254:80"], host_aliases: [])

      assert {:error, {:invalid_entries, ["api.example.com"]}} =
               ExSandbox.update_egress(Beam, sandbox, ["api.example.com"], host_aliases: [])
    end

    test "Beam replaces the live policy and records the list for the next start" do
      {:ok, binding} = Binding.acquire(@old)
      sandbox = beam_row(%{binding: binding})
      on_exit(fn -> Binding.release(binding) end)

      assert {:ok, updated} =
               ExSandbox.update_egress(Beam, sandbox, ["b.example.com:443"], host_aliases: [])

      assert Registry.lookup(binding.source_key) == @new
      assert updated.context.network_allowlist == @new
      assert updated.context.kept == :yes, "the caller's context was replaced, not updated"
    end

    test "Beam refuses a sandbox launched with no policy to replace" do
      sandbox = beam_row(%{binding: nil})

      assert {:error, :no_live_policy} =
               ExSandbox.update_egress(Beam, sandbox, ["b.example.com:443"], host_aliases: [])
    end

    test "Beam refuses a sandbox it does not hold" do
      sandbox = Helpers.build_sandbox()

      assert {:error, :absent} =
               ExSandbox.update_egress(Beam, sandbox, ["b.example.com:443"], host_aliases: [])
    end
  end

  # A launched row written straight into Beam's table: the launch that writes
  # it runs only on Linux.
  defp beam_row(fields) do
    sandbox = Helpers.build_sandbox(context: %{kept: :yes})
    table = ExSandbox.Mechanism.Beam.Registry
    true = :ets.insert(table, {sandbox.id, Map.merge(%{peer: nil, acceptor_pid: nil}, fields)})
    on_exit(fn -> :ets.delete(table, sandbox.id) end)
    sandbox
  end
end
