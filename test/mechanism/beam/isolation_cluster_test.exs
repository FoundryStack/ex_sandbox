defmodule ExSandbox.Mechanism.Beam.IsolationClusterTest do
  @moduledoc """
  A sandbox cannot join the platform's cluster (005 T030, `FR-003`, R4).

  ## What actually enforces this, as measured

  Not the cookie, and not `-hidden`. A sandbox runs under `--unshare-net` with no
  network interfaces at all, so `net_kernel` cannot start: an earlier version
  passed `name:` to `:peer`, and every such sandbox died at boot with
  "Can't set long node name!" and `nodistribution` before running an
  instruction. The sandbox now boots **undistributed** (`:nonode@nohost`) and is
  reached over the stdio control channel instead.

  That is a stronger guarantee than the cookie was. A node with no distribution
  cannot connect to the platform or to another sandbox whatever cookie it holds,
  so `FR-003` no longer rests on cookie secrecy — it rests on the absence of a
  network stack, which tenant code cannot talk its way past.

  ## The contrast is still the test

  Asserting "the sandbox is not connected" proves nothing unless something in
  this file shows a connection *could* have been observed. The final test
  therefore starts distribution **on the platform side**, confirms the platform
  is genuinely reachable by a node that is allowed to reach it, and only then
  asserts the sandbox cannot. Without that control, every assertion here would
  pass on a machine where clustering was broken for unrelated reasons.
  """
  use ExUnit.Case, async: false

  @moduletag :isolation

  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  setup_all do
    # The platform side must really be distributed, or `Node.connect/1` fails for
    # reasons unrelated to sandboxing and every assertion below passes vacuously.
    #
    # ⚠️ Skipped rather than failed when distribution cannot start. The isolation
    # container has no usable network for the *platform* node either, and a
    # `setup_all` that raises there invalidates the whole file — reporting a
    # cluster-isolation failure when the truth is that this host cannot host the
    # control. Skipping says that plainly; the tests that do not need
    # distribution still run.
    cond do
      Node.alive?() ->
        :ok

      match?({:ok, _}, Node.start(:"platform_test@127.0.0.1", :longnames)) ->
        :ok

      true ->
        {:ok, skip_distribution: true}
    end
  end

  setup context do
    if context[:skip_distribution] do
      # Not an `@tag :skip`: whether this host can start distribution is only
      # knowable at runtime.
      {:ok, skip: "this host cannot start distribution on the platform node"}
    else
      :ok
    end
  end

  defp sandbox(tag) do
    %Sandbox{
      id: "clus-#{tag}-#{System.unique_integer([:positive])}",
      owner_ref: "owner-#{tag}",
      template_ref: "conformance-template",
      cpu_limit: 500,
      memory_limit_mb: 128,
      disk_quota_mb: 256
    }
  end

  defp launch(tag) do
    ExSandbox.Test.IsolationLaunch.provision_or_skip(Beam, sandbox(tag))
  end

  # ⚠️ The **transport** is stdio; the **subject** is distribution. This file
  # asks whether a sandbox can reach other nodes, so it must not use the thing it
  # is testing to ask the question: with `:erpc` as the transport, a refuted
  # connect and an unreachable sandbox both surface as `:noconnection`, and the
  # suite cannot tell "the boundary held" from "the test never ran".
  # ⚠️ OTP modules only. `Node` is Elixir's, and the sandbox boots a bare `erl`
  # with no Elixir on its code path, so `Node.list/0` there raises `:undef` --
  # which in a test asserting "the sandbox is not connected to anything" is
  # indistinguishable from success. `:erlang.nodes/0` and
  # `:net_kernel.connect_node/1` are the primitives behind them.
  #
  # ⚠️ `connect_node/1` has **three** returns, and only two are booleans:
  # `true`, `false`, and `:ignored` -- the last meaning distribution is not
  # running at all. A sandbox launched without a network never starts
  # distribution (`:erlang.is_alive/0` is `false` there), so `:ignored` is what
  # a correctly isolated sandbox actually returns. Measured:
  #
  #     connect_node(platform) => {:ok, :ignored}
  #     erlang:nodes           => {:ok, []}
  #     is_alive               => {:ok, false}
  #
  # `refute` therefore reported the **strongest** refusal as a breach, because
  # `:ignored` is truthy -- the isolation working is what made the check fail.
  # The checks below name the accepted values instead of relying on
  # truthiness, so a real connection (`true`) still fails them.
  defp eval(sb, module, function, args) do
    assert {:ok, result} = Beam.call(sb, module, function, args)
    result
  end

  test "a sandbox sees an empty cluster" do
    sb = launch("a")

    assert eval(sb, :erlang, :nodes, []) == [],
           "sandbox is connected to other nodes"
  end

  test "an explicit connect to the platform is refused" do
    sb = launch("a")

    # Explicit, not discovery. `-connect_all false` stops automatic meshing;
    # this asks whether a *deliberate* attempt is stopped, which is what hostile
    # tenant code would actually do.
    assert eval(sb, :net_kernel, :connect_node, [Node.self()]) in [false, :ignored],
           "sandbox connected to the platform node -- the cookie is not isolating it"

    refute Node.self() in eval(sb, :erlang, :nodes, [])
  end

  test "an explicit connect to another sandbox is refused" do
    sb_a = launch("a")
    sb_b = launch("b")

    # `mechanism_ref` is the sandbox id now, not a node name -- an undistributed
    # sandbox has no node name to connect to. Constructing the name a *named*
    # sandbox would have had is the strongest form of the attempt: it is what
    # hostile tenant code would guess.
    node_b = :"sandbox-#{sb_b.id}@127.0.0.1"

    assert eval(sb_a, :net_kernel, :connect_node, [node_b]) in [false, :ignored],
           "one sandbox connected to another -- cookies are shared between sandboxes"
  end

  test "the platform IS reachable by a node that has a network (the positive control)" do
    # Without this, every refutation above could be passing because clustering is
    # broken on this host for reasons having nothing to do with sandboxing --
    # and the suite would report isolation it never established.
    #
    # A `:peer` node started WITHOUT the hardening wrapper: same OTP, same
    # cookie, same platform, but with a network stack. It must connect.
    # ⚠️ The platform node must be distributed *before* the peer starts, and this
    # is not incidental setup -- the assertions below are meaningless without it.
    #
    # `mix test` runs undistributed: `Node.self()` is `nonode@nohost` and
    # `Node.alive?()` is false. The control then asked a peer to connect to a
    # node that does not exist on any network, which cannot succeed however
    # healthy the host is. It failed as `{:boot_failed, {:exit_status, 1}}` and
    # read as "clustering is broken here", i.e. the exact misattribution the
    # comment below warns about, produced by the control itself.
    #
    # `:longnames` with an IP is what works in this container. The short-name
    # form (`name:` + `host: ~c"127.0.0.1"`) makes `net_kernel` try to set a
    # short name from an address and abort with `Can't set short node name!`.
    # Measured, both forms, inside the isolation container.
    # ⚠️ `epmd` is started explicitly, because nothing else in this container
    # starts it. Distribution needs the port mapper, and `Node.start/2` reports
    # its absence as `{:EXIT, :nodistribution}` -- a message that names the
    # symptom (no distribution) rather than the cause (no epmd), and reads like
    # a kernel or hostname problem. `erl` normally spawns epmd on demand; this
    # suite never starts a distributed node any other way, so nothing does.
    #
    # Idempotent: a second `-daemon` on a live epmd exits non-zero and is
    # ignored, so this is safe whether or not one is already running.
    _ = System.cmd("epmd", ["-daemon"], stderr_to_stdout: true)

    unless Node.alive?() do
      {:ok, _} = Node.start(:"control_host@127.0.0.1", :longnames)
      Node.set_cookie(:isolation_control_cookie)
    end

    {:ok, peer, node} =
      :peer.start_link(%{
        name: :"control_#{System.unique_integer([:positive])}",
        host: ~c"127.0.0.1",
        longnames: true,
        args: [~c"-setcookie", Atom.to_string(Node.get_cookie()) |> String.to_charlist()],
        connection: :standard_io,
        wait_boot: 20_000,
        peer_down: :continue
      })

    # ⚠️ `Process.alive?/1` is checked and then *ignored on failure*: the peer can
    # exit between the check and the stop, and `:peer.stop/1` on a dead peer
    # exits with `:noproc`. Raising from `on_exit` fails a test whose assertions
    # all passed, which is a teardown race reported as a defect.
    on_exit(fn ->
      try do
        if Process.alive?(peer), do: :peer.stop(peer)
      catch
        :exit, _ -> :ok
      end
    end)

    # ⚠️ `:net_kernel`, not `Node` -- the same rule the sandbox checks follow.
    # This peer is unconfined but still a bare `erl` with no Elixir on its code
    # path, so `Node.connect/1` raises `:undef` here. The control then failed
    # while reporting "an unconfined node could not connect", i.e. it accused
    # the host of broken clustering when the real cause was a missing module.
    assert :peer.call(peer, :net_kernel, :connect_node, [Node.self()], 10_000) == true,
           """
           an UNCONFINED node could not connect to the platform either.

           That sounds like good news and is not: it means the refutations above
           pass for some reason other than confinement, so `FR-003` is unproven
           and this suite cannot tell a real boundary from a broken host.
           """

    assert Node.self() in :peer.call(peer, :erlang, :nodes, [], 10_000)

    # Left disconnected: a connected node would leak into later tests.
    :peer.call(peer, :net_kernel, :disconnect, [Node.self()], 10_000)
    assert node != Node.self()
  end
end
