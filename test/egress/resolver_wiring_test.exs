defmodule ExSandbox.Egress.ResolverWiringTest do
  @moduledoc """
  The resolver reaches the rule, and a bad one stops the launch (029 T015).

  ⚠️ **The whole point of this file is the refusal, not the plumbing.** Before
  T015 nothing supplied a resolver: `redirect_commands/3`'s third argument
  defaulted to `nil` and `LaunchPlan.redirect_steps/2` called arity 2, so every
  sandbox dropped all UDP with a rule set that installed perfectly. The
  dangerous repair is one that *degrades* — a resolver address that cannot be
  read producing "no exemption" rather than an error — because the result is a
  sandbox with no DNS whose rules all installed cleanly, which is
  indistinguishable from one that was never given a resolver and reads as
  success.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.LaunchPlan
  alias ExSandbox.Egress.Netns

  @source_key {10, 0, 0, 0}

  defp command do
    ~w(systemd-run --scope -p MemoryMax=64M -- setpriv --reuid=60000 --regid=60000 --clear-groups
       bwrap --unshare-net --ro-bind / / erlexec)
  end

  defp build!(opts), do: LaunchPlan.build(@source_key, 44_697, command(), opts)

  describe "the resolver reaches the installed rules" do
    test "the exemption names the configured address and port" do
      {:ok, plan} = build!(resolver: {{10, 0, 0, 53}, 53})
      steps = LaunchPlan.redirect_steps(plan, 1234)

      assert Enum.any?(steps, fn step ->
               "accept" in step and "10.0.0.53" in step and "53" in step
             end),
             """
             No accept rule named the resolver. Every step:
             #{inspect(steps, pretty: true)}
             """
    end

    test "the terminal drop comes after the exemption" do
      # ⚠️ `nft` evaluates in order, so an exemption placed after the drop never
      # runs -- and the symptom is DNS that does not work, with a ruleset that
      # installed without complaint.
      {:ok, plan} = build!(resolver: {{10, 0, 0, 53}, 53})
      steps = LaunchPlan.redirect_steps(plan, 1234)

      drop_at = Enum.find_index(steps, &("drop" in &1))
      accept_positions = for {step, i} <- Enum.with_index(steps), "accept" in step, do: i

      assert drop_at
      assert accept_positions != []

      # ⚠️ EVERY accept, not the first one. There are two -- the query and its
      # answer -- and a check on `find_index` alone would keep passing with the
      # second one stranded after the drop, which is a sandbox whose lookups all
      # time out under a ruleset that installed cleanly.
      assert Enum.all?(accept_positions, &(&1 < drop_at)),
             "an exemption placed after the terminal drop never runs"
    end

    test "the default plan carries a resolver rather than nil" do
      # The regression this guards is the one that was live until T015: a plan
      # built with no explicit option supplying no resolver at all.
      {:ok, plan} = build!([])
      assert {_address, _port} = plan.resolver

      assert Enum.any?(LaunchPlan.redirect_steps(plan, 1234), &("accept" in &1))
    end

    test "an explicit nil resolver drops all UDP, and that is expressible" do
      {:ok, plan} = build!(resolver: nil)
      steps = LaunchPlan.redirect_steps(plan, 1234)

      refute Enum.any?(steps, &("accept" in &1))
      assert Enum.any?(steps, &("drop" in &1))
    end
  end

  describe "an unreadable resolver raises rather than degrading" do
    test "at build time, before the tenant is running" do
      # ⚠️ Build time specifically. `Netns.resolver_exemption/2` also raises,
      # but it runs after `pasta` has already started the tenant -- so the same
      # configuration error would terminate a running sandbox instead of
      # refusing a launch.
      assert_raise ArgumentError, ~r/not an IP address/, fn ->
        build!(resolver: {"not-an-address", 53})
      end
    end

    test "a hostname is not an address, however plausible" do
      # ⚠️ An `nft` rule cannot resolve a name, and the thing that would resolve
      # it is the resolver this names.
      assert_raise ArgumentError, ~r/not an IP address/, fn ->
        build!(resolver: {"resolver.internal", 53})
      end
    end

    test "a malformed pair is refused too" do
      assert_raise ArgumentError, ~r/must be/, fn -> build!(resolver: {{10, 0, 0, 53}, 0}) end
      assert_raise ArgumentError, ~r/must be/, fn -> build!(resolver: "10.0.0.53:53") end
    end

    test "validate_resolver!/1 and the rule builder agree on what is readable" do
      # They share `parse_resolver_address/1` so they cannot disagree; this pins
      # that they still do, since the cost of a drift is an address accepted at
      # build time and rejected mid-launch.
      assert Netns.validate_resolver!({"10.0.0.53", 53}) == {"10.0.0.53", 53}
      assert Netns.validate_resolver!({{10, 0, 0, 53}, 53}) == {{10, 0, 0, 53}, 53}
      assert Netns.validate_resolver!(nil) == nil

      assert_raise ArgumentError, fn -> Netns.validate_resolver!({"nope", 53}) end
    end
  end

  describe "the listener is bound where the rule permits" do
    test "the acceptor is started with the plan's own resolver address" do
      # ⚠️ From the plan, not from configuration read a second time. If the two
      # diverged the resolver socket would sit where nothing may send: DNS
      # silently dead, every denial check green.
      #
      # This used to assert on `Acceptor.listener_command/7`'s argv, because the
      # listener was an OS process and the address reached it as a string. It is
      # now a process on this node started with options, so the same fact is
      # asserted against the state it actually holds.
      {:ok, plan} = build!(resolver: {{10, 0, 0, 53}, 5353})

      {:ok, state} =
        ExSandbox.Egress.Acceptor.init(
          source_key: plan.source_key,
          holder_pid: 1234,
          port: plan.pool_port,
          resolver: plan.resolver,
          listen: false
        )

      assert state.resolver == {{10, 0, 0, 53}, 5353}
    end

    test "a plan with no resolver leaves the acceptor with no DNS leg" do
      {:ok, plan} = build!(resolver: nil)

      {:ok, state} =
        ExSandbox.Egress.Acceptor.init(
          source_key: plan.source_key,
          holder_pid: 1234,
          port: plan.pool_port,
          resolver: plan.resolver,
          listen: false
        )

      assert state.resolver == nil
    end

    test "the launcher passes the plan's resolver, not a configured one" do
      # ⚠️ Wiring, not behaviour. The two tests above are worth nothing if the
      # launcher never passes the value -- the shape of four earlier defects in
      # this feature, each correct code that nothing reached.
      #
      # Read from source because reaching `start_acceptor/3` needs a real
      # namespace, which is Linux only. Verifying this only where the whole
      # launch works is the arrangement that let those four survive.
      source =
        File.read!(
          Path.join([
            __DIR__,
            "..",
            "..",
            "lib",
            "ex_sandbox",
            "mechanism",
            "beam",
            "node_launcher.ex"
          ])
        )

      assert source =~ "resolver: plan.resolver",
             "the acceptor is started without the plan's resolver, so DNS is dead"
    end
  end
end
