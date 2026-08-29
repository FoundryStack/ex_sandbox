defmodule ExSandbox.Egress.AcceptorTransportTest do
  @moduledoc """
  The acceptor's socket path, driven end to end (T060a3).

  ⚠️ `decide/3` is unit-tested elsewhere and passing. That is not evidence the
  transport enforces anything: the whole species of defect this project keeps
  finding is a correct decision with no consumer, or a consumer that reaches the
  right verdict on a path the test never executes. These tests connect to a real
  listener the real accept loop is running over, and assert on what happens to
  the socket.

  ## ⚠️ This file used to drive a listener nothing could reach

  It was `pool_transport_test.exs`, and it started an `Egress.Pool`, which binds
  `127.0.0.1` in the **host** namespace. An `nft` `redirect` is DNAT to the local
  machine as the *sandbox's* namespace sees it, so no tenant connection ever
  arrived there — measured, with the pool listening and the redirect installed,
  the tenant's connect returned OK and the pool never saw it. Every assertion
  below used to stand over a copy of this logic that production could not run.

  The listener is now supplied by the test rather than by the module, because
  the real one is created inside a namespace with `setns(2)` and cannot exist on
  macOS at all. What runs over it is `Acceptor.accept_loop/1` itself.

  ## ⚠️ What these tests do NOT establish, on a host without the redirect

  **Measured, not assumed:** replacing `decide/3`'s body with an unconditional
  `throw` leaves all of these **green** on macOS. Every connection here is
  refused at `OriginalDst.read/1` with `:unavailable` — there is no netns and no
  redirect, so no destination is ever established and the policy is never
  consulted.

  So on a non-Linux host these tests establish exactly one thing, and it is worth
  having: **the acceptor refuses by closing, and keeps accepting afterwards, on
  every path including a malfunctioning one.** They establish *nothing* about the
  allowlist. The test named "a connection is closed even when its source IS
  registered" passes without the allowlist being read.

  That is why `@moduletag :egress_transport` exists: the enforcement claim is
  verified in the container by the conformance network group, which attempts real
  connections through a real redirect. Leaving these green and unlabelled would
  let a reader — or a future me — count macOS green as coverage of enforcement.

  The allowlist's own coverage on this path is `acceptor_relay_wiring_test.exs`,
  which stubs the one thing macOS cannot do and runs the real decision.
  """
  use ExUnit.Case, async: false

  @moduletag :egress_transport

  alias ExSandbox.Egress.Acceptor
  alias ExSandbox.Egress.NetnsSocket
  alias ExSandbox.Egress.Registry

  @source_key {127, 0, 0, 0}

  setup do
    registry = start_supervised!({Registry, name: :"reg_#{System.unique_integer([:positive])}"})

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listener)

    # ⚠️ The **real** destination reader, deliberately, unlike the wiring test's
    # stub. That is what makes these two hosts behave differently and what the
    # moduledoc above is about: on macOS every read fails and the refusal is a
    # malfunction; in the container a plain loopback socket answers
    # `SO_ORIGINAL_DST` with its own address, so the read succeeds and the
    # refusal is a policy denial. Both must close the socket, and both must
    # leave the loop accepting.
    {:ok, state} =
      Acceptor.init(
        source_key: @source_key,
        holder_pid: 1,
        port: 18_080,
        resolver: nil,
        registry: registry,
        listen: false
      )

    # ⚠️ `spawn`, not `Task.async`. `on_exit/1` runs in a process of ExUnit's
    # own, and `Task.shutdown/2` may only be called by the task's owner -- which
    # fails every test in this file with an `ArgumentError` raised from the
    # teardown rather than from anything under test.
    loop = spawn(fn -> Acceptor.accept_loop(%{state | listener: listener}) end)

    on_exit(fn ->
      :gen_tcp.close(listener)
      Process.exit(loop, :kill)
    end)

    %{registry: registry, port: port}
  end

  test "a connection from an unregistered source is closed", %{port: port} do
    {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 2_000)

    # ⚠️ The assertion is that the *peer* closes, not that we can close it.
    # `recv` returning `{:error, :closed}` is the sandbox-visible consequence of
    # a refusal, and it is what "behaves like an unreachable destination" means
    # concretely. Asserting anything weaker -- that the acceptor logged, that
    # `decide/3` was called -- would pass against an acceptor that forwarded.
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
  end

  test "a connection is closed even when its source IS registered", %{
    registry: registry,
    port: port
  } do
    # ⚠️ Named for what it establishes rather than for what it looks like it
    # establishes. Registering the source removes the `:unknown_source`
    # explanation for the refusal, so this shows the acceptor does not open up
    # for a *known* sandbox -- the direction a naive implementation gets wrong.
    #
    # It does NOT show the allowlist was consulted. Off-Linux the refusal comes
    # from `OriginalDst.read/1`, and the destination below is never compared
    # against anything. See the moduledoc.
    :ok = Registry.assign(@source_key, [{"93.184.216.34", 443}], registry)

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

  test "the acceptor keeps accepting after refusing a connection", %{port: port} do
    # ⚠️ A refusal that killed the accept loop would deny everything afterwards
    # -- a boundary that holds by being broken. It would pass every denial check
    # in the conformance suite while making the sandbox useless, so it must be
    # distinguished from working enforcement here.
    for _ <- 1..3 do
      {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 2_000)
      assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
    end

    {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 2_000)
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
  end

  test "an acceptor that cannot enter its namespace binds nothing at all" do
    # ⚠️ This replaced "the pool listens only on loopback, never on a routable
    # interface", which was a statement about a HOST listener that no longer
    # exists. The acceptor's version of that property is stronger and is the one
    # worth pinning: it does not bind a narrower host address, it binds **no**
    # host address, ever.
    #
    # `013-FR-014c` is about blast radius, and the failure this guards is the
    # fallback nobody would notice: an acceptor that could not enter the
    # namespace and bound the host instead would come up, be supervised, report
    # healthy, accept nothing a tenant sent, and leave that tenant's traffic
    # going wherever the redirect pointed. No conformance check in the network
    # group probes from outside a sandbox, so an extra host listener is
    # invisible to every one of them.
    #
    # The pid names a namespace that cannot be opened on either host, so the
    # refusal is host-agnostic while its *reason* is not: macOS has no NIF at
    # all, and Linux fails at `open`.
    result =
      Acceptor.init(
        source_key: @source_key,
        holder_pid: 4_294_967_295,
        port: 18_080,
        resolver: nil
      )

    assert {:stop, {:listen_failed, reason}} = result,
           "the acceptor started without its namespace; a host-namespace listener enforces nothing"

    if NetnsSocket.available?() do
      # ENOENT from `open`, not a fallback and not a partial success.
      assert {:open, 2} = reason
    else
      assert reason == :netns_sockets_unavailable
    end
  end
end
