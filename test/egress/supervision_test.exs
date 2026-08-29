defmodule ExSandbox.Egress.SupervisionTest do
  @moduledoc """
  That the egress enforcement point is actually running (005 T060a3b).

  ## Why this needs a test rather than being obvious

  `ExSandbox.Egress.Registry` and `ExSandbox.Egress.Allocator` were supervised;
  `ExSandbox.Egress.Pool` was not. It was referenced by its own two test files
  and by nothing else in the system.

  ⚠️ Nothing failed, and nothing could have. The pool was the component every
  sandbox's traffic was supposed to be redirected *to*, so its absence broke no
  build, no boot, and no host-side test -- `LaunchPlan` would install a redirect
  to a port where nothing listened, and from inside the sandbox that is
  indistinguishable from a destination correctly denied by policy. Every denial
  check in the conformance suite would pass. The allowlist would be enforced by
  nothing, and the only visible symptom would be permitted destinations also
  failing -- which reads as a boundary that is slightly too strict rather than as
  an enforcement point that does not exist.

  That is the same shape as `--unshare-net`, one layer further out: a boundary
  that denies everything looks correct to a suite that tests denial.

  ## ⚠️ Three tests here asserted on the pool, and are gone with it (2026-08-29)

  They asserted that `Egress.Pool` was a supervised child, that it started after
  the registry, and that it reported a real listening port rather than 0. All
  three were true and none of them meant anything by the end: an `nft` `redirect`
  is DNAT to the local machine as the *sandbox's* namespace sees it, so the
  pool's host listener could not receive a tenant connection, and the launcher
  had stopped naming its port. A supervised, correctly-ordered, genuinely-bound
  socket that nothing can reach passes all three while enforcing nothing.

  ⚠️ Read this as coverage moving rather than coverage lost, and check the
  claim: the thing those tests were really asking -- "is an enforcement point
  listening for this sandbox?" -- is now answered at launch rather than at boot,
  because there is one acceptor per sandbox instead of one pool for all of them.
  `NodeLauncher.start_acceptor/3` returns only once `Acceptor.init/1` has, and
  `acceptor_transport_test.exs` pins that an acceptor which cannot enter its
  namespace refuses to start rather than binding the host. Deleting the three
  without those two landing first would have been exactly the silent narrowing
  this file exists to make impossible.
  """
  use ExUnit.Case, async: false

  test "the resolver is supervised, because names stop resolving without it" do
    # ⚠️ This replaced three tests covering the **verdict server**: that it was
    # supervised, that its socket existed, and that it answered over the wire.
    # All three are gone with the server, and the reason is worth stating so a
    # reader does not go looking for coverage that was quietly dropped.
    #
    # The verdict server existed because the acceptor was a separate OS process
    # that could not call `Pool.decide/3`. It is now a process on this node and
    # calls it directly, so there is no socket, no wire, and no framing -- the
    # reply-framing bug those tests were written against is not expressible.
    # `pool_decide_test.exs` covers the decision itself, which is what the wire
    # was carrying.
    #
    # The resolver is the one that still has to be up: the acceptor's DNS leg
    # calls it, and its absence means names do not resolve.
    children = Supervisor.which_children(ExSandbox.Supervisor)
    ids = Enum.map(children, fn {id, _pid, _type, _mods} -> id end)

    assert ExSandbox.Egress.Resolver in ids,
           """
           The egress resolver is not supervised, so no sandbox can resolve a
           name and every hostname allowlist entry denies.

           Started: #{inspect(ids)}
           """
  end

  test "the decision and the registry agree on which registry holds policy" do
    # ⚠️ `decide/3` defaults its registry argument, and a default naming a
    # different registry than the one `Binding.acquire/2` writes to would
    # default-deny every sandbox -- the acceptors would be running, the policies
    # would be filed, and the two would never meet. Silent in the safe
    # direction, which is why it is pinned rather than read off the code.
    source = {10, 0, 0, 2}
    :ok = ExSandbox.Egress.Registry.assign({10, 0, 0, 0}, [{"example.com", 443}])

    on_exit(fn -> ExSandbox.Egress.Registry.release({10, 0, 0, 0}) end)

    assert ExSandbox.Egress.Pool.decide(source, {"example.com", 443}) == :permitted,
           "the shared decision's default registry is not the one policies are assigned to"
  end
end
