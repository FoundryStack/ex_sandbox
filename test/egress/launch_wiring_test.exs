defmodule ExSandbox.Egress.LaunchWiringTest do
  @moduledoc """
  What the launch path does with an egress binding, and what it does when it
  cannot get one (005 T060a3b/T060a5, `005-FR-011a`–`FR-011e`).

  ## The rule this suite exists to enforce

  `ExSandbox.Egress.LaunchPlan` and `ExSandbox.Egress.Binding` are both
  complete and both tested. The part that is neither is the *decision* the
  launch path makes when one of them refuses -- and there is exactly one
  acceptable answer.

  ⚠️ **A host that cannot build the policed path must refuse to launch, never
  fall back to `--unshare-net`.** The fallback is tempting because it looks
  strictly safer: an empty namespace reaches nothing, so no tenant is exposed.
  What it actually produces is the state this entire feature exists to end --
  a sandbox that denies everything, passes every denial check in the
  conformance suite, and is recorded in the census as a demonstrated network
  boundary. The tenant's allowlist is not enforced; it is *unreachable*, and
  nothing reports that.

  So the failure mode of the fallback is not "a sandbox is too restrictive".
  It is "the suite reports a guarantee that was never established", which is
  the one outcome `contracts/egress.md` names as worse than failing.

  These tests run on any host: they exercise the decision, not the commands.
  Whether `ip netns` actually works is a container question, and answering it
  here would mean the decision goes untested everywhere else.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Binding
  alias ExSandbox.Egress.LaunchPlan

  @confined [
    "/usr/bin/systemd-run",
    "--scope",
    "--unit=sandbox-x.scope",
    "-p",
    "MemoryMax=128M",
    "setpriv",
    "--reuid=4242",
    "--regid=4242",
    "--clear-groups",
    "--no-new-privs",
    "bwrap",
    "--unshare-net",
    "--die-with-parent",
    "erlexec"
  ]

  describe "the plan replaces network isolation rather than adding to it" do
    test "a confined command is rewritten to join the policed namespace" do
      {:ok, plan} = LaunchPlan.build({10, 0, 0, 0}, 9999, @confined)

      refute "--unshare-net" in plan.tenant_command,
             "the tenant would unshare a fresh empty namespace while the policy sat on the configured one"

      # The tenant runs *under* pasta rather than joining a pre-built namespace.
      # ⚠️ pasta is mid-chain, not at the head: it is inserted after `setpriv`
      # so the drop happens in the host's fully mapped namespace rather than
      # inside pasta's empty one (T060a4e, measured).
      pasta = Enum.find(plan.pasta_command, &(Path.basename(&1) == "pasta"))
      assert pasta, "the tenant must run under pasta"
      assert String.starts_with?(pasta, "/"), "must be a path that can be exec'd"

      tenant = plan.pasta_command |> Enum.drop_while(&(&1 != "--")) |> Enum.drop(1)
      assert List.last(tenant) == List.last(plan.tenant_command)
    end

    test "an unconfined command is refused rather than policed" do
      # ⚠️ Refusing is the only answer that cannot be wrong. Handed a command
      # that never confined the network, this module cannot distinguish "already
      # converted" from "never confined" -- and the second, if policed anyway,
      # launches a tenant sharing the host's own network stack while every
      # downstream check reads as normal.
      assert {:error, :no_network_confinement} =
               LaunchPlan.build({10, 0, 0, 0}, 9999, ["bwrap", "erlexec"])
    end

    test "a pool that never bound is refused rather than redirected to port 0" do
      # A redirect to port 0 sends the namespace's traffic nowhere, which from
      # inside the sandbox is indistinguishable from correct denial: the denial
      # checks pass, the reachability checks fail, and nothing points here.
      assert {:error, :no_pool_port} = LaunchPlan.build({10, 0, 0, 0}, 0, @confined)
    end
  end

  describe "a binding and a plan agree on which namespace is policed" do
    setup do
      start_supervised!(
        {ExSandbox.Egress.Registry, name: :"reg_#{System.unique_integer([:positive])}"}
      )

      :ok
    end

    test "the plan's namespace is derived from the /30 the policy is keyed by" do
      # ⚠️ The join that makes the whole thing hold. The policy is filed under a
      # `/30`; the namespace carries an address in that `/30`; the plan's name is
      # derived from the same `/30`. If any of the three drifted, the sandbox
      # would send from an address whose policy is filed elsewhere -- and the
      # pool would apply default-deny, which passes every denial check while
      # enforcing nothing the tenant configured.
      source_key = {10, 0, 0, 4}
      {:ok, plan} = LaunchPlan.build(source_key, 9999, @confined)

      assert plan.source_key == source_key
      assert plan.pidfile == LaunchPlan.default_pidfile(source_key)

      # ⚠️ The address is no longer configured by us -- `pasta --config-net`
      # assigns it, copying the host's default-route interface. What must still
      # hold is that the acceptor decides using the key this plan was built for.
      # `Acceptor.verdict/3` reconstructs the sandbox address from the key, so
      # the two cannot drift apart the way a separately-configured address could.
      %{sandbox: sandbox} = ExSandbox.Egress.Netns.addresses(source_key)
      {:ok, parsed} = :inet.parse_address(String.to_charlist(sandbox))

      assert ExSandbox.Egress.Policy.source_key(parsed) == source_key,
             "the sandbox address does not mask back to the /30 its policy is filed under"
    end

    test "every redirect step enters the holder's namespace" do
      # ⚠️ A step that omits `nsenter` configures the *host*. On a developer
      # machine that fails; in the isolation container it **succeeds**, and the
      # host acquires a NAT rule redirecting its own outbound TCP while the
      # sandbox is left entirely unpoliced.
      {:ok, plan} = LaunchPlan.build({10, 0, 0, 0}, 9999, @confined)

      for step <- LaunchPlan.redirect_steps(plan, 7788) do
        assert ["nsenter", "-t", "7788", "-n" | _] = step
      end
    end
  end

  describe "Binding.acquire refuses rather than issuing an unpoliced sandbox" do
    test "an exhausted pool refuses instead of returning a sandbox with no policy" do
      # The launch path's contract with the pool: there is no partial success.
      # A sandbox without a policy entry is one the pool default-denies, which
      # is the silent-pass state again.
      registry = :"reg_#{System.unique_integer([:positive])}"
      allocator = :"alloc_#{System.unique_integer([:positive])}"
      start_supervised!({ExSandbox.Egress.Registry, name: registry})
      # ⚠️ `count:`, not `pool_size:`. The first draft of this test passed
      # `pool_size: 1`, which `Allocator.init/1` does not read -- so it silently
      # took the default pool of 64 and the exhaustion assertion tested nothing.
      # `Keyword.get/3` with a default cannot report an unknown option, so a
      # typo'd option name is invisible at every layer.
      start_supervised!({ExSandbox.Egress.Allocator, name: allocator, count: 1})

      assert {:ok, _first} =
               Binding.acquire([{"example.com", 443}], allocator: allocator, registry: registry)

      assert {:error, :pool_exhausted} =
               Binding.acquire([{"example.com", 443}], allocator: allocator, registry: registry)
    end
  end

  describe "a binding's lifetime matches the sandbox's, not its running state" do
    setup do
      registry = :"reg_#{System.unique_integer([:positive])}"
      allocator = :"alloc_#{System.unique_integer([:positive])}"
      start_supervised!({ExSandbox.Egress.Registry, name: registry})
      start_supervised!({ExSandbox.Egress.Allocator, name: allocator, count: 2})
      %{registry: registry, allocator: allocator}
    end

    test "releasing returns the /30 to the pool for reuse", ctx do
      opts = [allocator: ctx.allocator, registry: ctx.registry]
      {:ok, binding} = Binding.acquire([{"example.com", 443}], opts)
      {:ok, _second} = Binding.acquire([{"example.com", 443}], opts)

      assert {:error, :pool_exhausted} = Binding.acquire([{"a.example.com", 443}], opts)

      :ok = Binding.release(binding, opts)

      assert {:ok, reissued} = Binding.acquire([{"b.example.com", 443}], opts)

      assert reissued.source_key == binding.source_key,
             "the released /30 was not reissued, so the pool leaks one address per sandbox lifetime"
    end

    test "a reissued /30 carries the new tenant's allowlist, not the previous one", ctx do
      # ⚠️ The reuse race, asserted end to end rather than trusted. Every
      # outward check still passes when this breaks: the new sandbox reaches
      # destinations, denied destinations are refused, the policy is not
      # editable from inside. The allowlist being enforced is simply the *wrong
      # tenant's*, and nothing outward-facing distinguishes that from correct
      # operation.
      opts = [allocator: ctx.allocator, registry: ctx.registry]
      {:ok, first} = Binding.acquire([{"tenant-a.example.com", 443}], opts)
      :ok = Binding.release(first, opts)

      {:ok, second} = Binding.acquire([{"tenant-b.example.com", 443}], opts)

      assert ExSandbox.Egress.Registry.lookup(second.source_key, ctx.registry) ==
               [{"tenant-b.example.com", 443}],
             "the reissued /30 still carries the previous tenant's allowlist"
    end

    test "releasing twice is not an error", ctx do
      # `003-FR-013`. A destroy that ran partway and is retried must converge
      # rather than refuse -- and a caller who cannot retry destroy leaks the
      # /30 permanently.
      opts = [allocator: ctx.allocator, registry: ctx.registry]
      {:ok, binding} = Binding.acquire([{"example.com", 443}], opts)

      assert :ok = Binding.release(binding, opts)
      assert :ok = Binding.release(binding, opts)
    end
  end
end
