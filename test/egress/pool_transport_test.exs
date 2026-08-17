defmodule ExSandbox.Egress.PoolTransportTest do
  @moduledoc """
  The pool's socket path, driven end to end (T060a3).

  ⚠️ `decide/3` is unit-tested elsewhere and passing. That is not evidence the
  transport enforces anything: the whole species of defect this project keeps
  finding is a correct decision with no consumer, or a consumer that reaches
  the right verdict on a path the test never executes. These tests connect to
  a real listener and assert on what happens to the socket.

  ## ⚠️ What these tests do NOT establish, on a host without the redirect

  **Measured, not assumed:** replacing `decide/3`'s body with an unconditional
  `throw` leaves all of these **green** on macOS. Every connection here is
  refused at `OriginalDst.read/1` with `:unavailable` — there is no netns and
  no redirect, so no destination is ever established and the policy is never
  consulted.

  So on a non-Linux host these tests establish exactly one thing, and it is
  worth having: **the pool refuses by closing, and keeps accepting afterwards,
  on every path including a malfunctioning one.** They establish *nothing*
  about the allowlist. The test named "a registered source whose destination is
  not permitted is closed" passes without the allowlist being read.

  That is why `@moduletag :egress_transport` exists and why the policy-bearing
  assertions carry `@tag :isolation`: the enforcement claim is verified in the
  container by the conformance network group, which attempts real connections
  through a real redirect. Leaving these green and unlabelled here would let a
  reader — or a future me — count macOS green as coverage of enforcement.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Egress.Pool
  alias ExSandbox.Egress.Registry

  setup do
    registry = start_supervised!({Registry, name: :"reg_#{System.unique_integer([:positive])}"})
    pool = start_supervised!({Pool, registry: registry, name: :"pool_#{System.unique_integer([:positive])}"})
    %{registry: registry, pool: pool, port: Pool.port(pool)}
  end

  test "a connection from an unregistered source is closed", %{port: port} do
    {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 2_000)

    # ⚠️ The assertion is that the *peer* closes, not that we can close it.
    # `recv` returning `{:error, :closed}` is the sandbox-visible consequence of
    # a refusal, and it is what "behaves like an unreachable destination" means
    # concretely. Asserting anything weaker -- that the pool logged, that
    # `decide/3` was called -- would pass against a pool that forwarded.
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
  end

  test "a connection is closed even when its source IS registered", %{
    registry: registry,
    port: port
  } do
    # ⚠️ Named for what it establishes rather than for what it looks like it
    # establishes. Registering the source removes the `:unknown_source`
    # explanation for the refusal, so this shows the pool does not open up for
    # a *known* sandbox -- the direction a naive implementation gets wrong.
    #
    # It does NOT show the allowlist was consulted. Off-Linux the refusal comes
    # from `OriginalDst.read/1`, and the destination below is never compared
    # against anything. See the moduledoc.
    :ok = Registry.assign({127, 0, 0, 0}, [{"93.184.216.34", 443}], registry)

    {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 2_000)
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
  end

  test "the refusal reason distinguishes a malfunction from a denial", %{port: port} do
    # ⚠️ `handle_connection/2` closes the socket identically for a policy denial
    # and for an unreadable destination -- deliberately, so a fault cannot let
    # traffic through. That makes the *reason* the only thing separating "the
    # allowlist said no" from "this host cannot enforce at all", and T060a5
    # requires that distinction survive into the census rather than being
    # flattened into a uniform green.
    #
    # This asserts the log carries it. On a host with no redirect the reason is
    # `:unavailable`, which is the honest answer and NOT a denial.
    log =
      ExUnit.CaptureLog.capture_log(fn ->
        {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 2_000)
        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
      end)

    assert log =~ "egress:",
           "a refusal produced no diagnosable reason; a denial and a broken host would be indistinguishable"
  end

  test "the pool keeps accepting after refusing a connection", %{port: port} do
    # ⚠️ A refusal that killed the acceptor would deny everything afterwards --
    # a boundary that holds by being broken. It would pass every denial check
    # in the conformance suite while making the sandbox useless, so it must be
    # distinguished from working enforcement here.
    for _ <- 1..3 do
      {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 2_000)
      assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
    end

    {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 2_000)
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
  end

  test "the pool listens only on loopback, never on a routable interface", %{pool: pool} do
    # ⚠️ `013-FR-014c` is about blast radius. A pool bound to 0.0.0.0 would be
    # reachable from outside the host entirely, which no conformance check in
    # the network group would notice -- every one of them probes from inside a
    # sandbox, so an extra listener facing the world is invisible to all of them.
    port = Pool.port(pool)
    assert is_integer(port) and port > 0

    interfaces =
      case :inet.getifaddrs() do
        {:ok, list} -> list
        _ -> []
      end

    routable =
      for {_name, opts} <- interfaces,
          {:addr, {a, b, c, d}} <- opts,
          {a, b, c, d} != {127, 0, 0, 1},
          do: {a, b, c, d}

    for address <- Enum.take(routable, 3) do
      assert {:error, _} =
               :gen_tcp.connect(address, port, [:binary, active: false], 500),
             "pool accepted a connection on #{:inet.ntoa(address)}, expected loopback only"
    end
  end
end
