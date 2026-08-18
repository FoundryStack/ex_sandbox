defmodule ExSandbox.Egress.SupervisionTest do
  @moduledoc """
  That the egress enforcement point is actually running (005 T060a3b).

  ## Why this needs a test rather than being obvious

  `ExSandbox.Egress.Registry` and `ExSandbox.Egress.Allocator` were supervised;
  `ExSandbox.Egress.Pool` was not. It was referenced by its own two test files
  and by nothing else in the system.

  ⚠️ Nothing failed, and nothing could have. The pool is the component every
  sandbox's traffic is redirected *to*, so its absence does not break a build,
  a boot, or any host-side test -- `LaunchPlan` would install a redirect to a
  port where nothing listens, and from inside the sandbox that is
  indistinguishable from a destination correctly denied by policy. Every denial
  check in the conformance suite would pass. The allowlist would be enforced by
  nothing, and the only visible symptom would be permitted destinations also
  failing -- which reads as a boundary that is slightly too strict rather than
  as an enforcement point that does not exist.

  That is the same shape as `--unshare-net`, one layer further out: a boundary
  that denies everything looks correct to a suite that tests denial.
  """
  use ExUnit.Case, async: false

  test "the acceptor pool is running under the application supervisor" do
    children = Supervisor.which_children(ExSandbox.Supervisor)
    ids = Enum.map(children, fn {id, _pid, _type, _mods} -> id end)

    assert ExSandbox.Egress.Pool in ids,
           """
           The egress acceptor pool is not supervised, so nothing is listening at
           the address `LaunchPlan` redirects each sandbox's traffic to.

           Started: #{inspect(ids)}

           This cannot fail loudly: a redirect to a dead port looks exactly like
           a correctly denied destination from inside the sandbox, so every
           denial check passes while no allowlist is enforced by anything.
           """
  end

  test "the verdict server is running under the application supervisor" do
    # ⚠️ Same failure shape as the pool's, one component further along, and
    # equally silent. The per-namespace acceptors treat any unobtainable
    # verdict as DENY -- correctly, since "allow when the check could not run"
    # would make a dead platform indistinguishable from a permissive allowlist.
    #
    # But that means this server's absence does not fail loudly: it converts
    # every sandbox's egress into blanket denial while every denial check in the
    # conformance suite passes. That is the `--unshare-net` state wearing the
    # appearance of an enforced allowlist.
    children = Supervisor.which_children(ExSandbox.Supervisor)
    ids = Enum.map(children, fn {id, _pid, _type, _mods} -> id end)

    assert ExSandbox.Egress.Verdict in ids,
           """
           The egress verdict server is not supervised, so no per-namespace
           acceptor can obtain a verdict.

           Started: #{inspect(ids)}

           Acceptors deny when they cannot ask, so this fails closed and
           silently: every sandbox loses egress entirely while the suite stays
           green, because a boundary that denies everything passes every denial
           check.
           """
  end

  test "the verdict server is bound to a socket that exists" do
    # Not merely "a process is alive". A server whose bind failed could not
    # answer, and the acceptors would deny everything without any local sign.
    path = ExSandbox.Egress.Verdict.path()

    assert File.exists?(path),
           "the verdict server reports #{path} but nothing is bound there"
  end

  test "the verdict server answers over the wire it publishes" do
    # ⚠️ The end-to-end check the two above cannot make. A supervised process
    # bound to an existing path can still be unable to answer -- the reply
    # framing bug did exactly that, and its symptom was every destination
    # silently refused.
    path = ExSandbox.Egress.Verdict.path()

    {:ok, socket} =
      :gen_tcp.connect({:local, path}, 0, [:binary, active: false, packet: :line])

    :ok = :gen_tcp.send(socket, "10.0.99.0 example.com 443\n")
    assert {:ok, reply} = :gen_tcp.recv(socket, 0, 2_000)
    :gen_tcp.close(socket)

    # DENY, because nothing is registered for that /30 -- the point is that a
    # verdict came back at all, framed as a line the acceptor can read.
    assert String.trim(reply) == "DENY"
  end

  test "the running pool reports a real listening port" do
    # ⚠️ Not merely "a process is alive". A pool whose `listen/2` failed would
    # report port 0, and `LaunchPlan.build/4` refuses port 0 precisely because
    # redirecting there sends traffic nowhere -- so the supervised-but-unbound
    # case has to be distinguished from the working one here.
    port = ExSandbox.Egress.Pool.port()

    assert is_integer(port) and port > 0,
           "the pool is supervised but bound nothing; every redirect would point at port #{inspect(port)}"
  end

  test "the pool and the registry agree on which registry holds policy" do
    # A pool consulting a different registry than the one `Binding.acquire/2`
    # writes to would default-deny every sandbox -- the pool would be running,
    # the policies would be filed, and the two would never meet.
    source = {10, 0, 0, 2}
    :ok = ExSandbox.Egress.Registry.assign({10, 0, 0, 0}, [{"example.com", 443}])

    on_exit(fn -> ExSandbox.Egress.Registry.release({10, 0, 0, 0}) end)

    assert ExSandbox.Egress.Pool.decide(source, {"example.com", 443}) == :permitted,
           "the pool's default registry is not the one policies are assigned to"
  end

  test "the pool starts after the registry it consults" do
    # ⚠️ Order, asserted rather than assumed. `:one_for_one` starts children in
    # list order and restarts them independently, so a pool listed before the
    # registry would accept its first connection with no registry to ask.
    #
    # That failure is *silent in the safe direction*: `Registry.lookup/2` on a
    # dead registry raises, the connection is refused, and refusal is what a
    # correct denial looks like. So the sandbox is denied everything, every
    # denial check passes, and the misordering never surfaces -- the same trap
    # as the missing pool, which is why the order is pinned here rather than
    # left to the comment beside it.
    children = Supervisor.which_children(ExSandbox.Supervisor)

    # `which_children/1` reports in reverse start order.
    ids = children |> Enum.map(&elem(&1, 0)) |> Enum.reverse()

    registry_at = Enum.find_index(ids, &(&1 == ExSandbox.Egress.Registry))
    pool_at = Enum.find_index(ids, &(&1 == ExSandbox.Egress.Pool))

    assert registry_at < pool_at,
           "the pool starts before the registry it consults (start order: #{inspect(ids)})"
  end
end
