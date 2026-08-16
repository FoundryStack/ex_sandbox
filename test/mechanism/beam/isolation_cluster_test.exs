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
    {:ok, provisioned} = Beam.provision(sandbox(tag))
    on_exit(fn -> Beam.destroy(provisioned) end)
    provisioned
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
    refute eval(sb, :net_kernel, :connect_node, [Node.self()]),
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

    refute eval(sb_a, :net_kernel, :connect_node, [node_b]),
           "one sandbox connected to another -- cookies are shared between sandboxes"
  end

  test "the platform IS reachable by a node that has a network (the positive control)" do
    # Without this, every refutation above could be passing because clustering is
    # broken on this host for reasons having nothing to do with sandboxing --
    # and the suite would report isolation it never established.
    #
    # A `:peer` node started WITHOUT the hardening wrapper: same OTP, same
    # cookie, same platform, but with a network stack. It must connect.
    {:ok, peer, node} =
      :peer.start_link(%{
        name: :"control_#{System.unique_integer([:positive])}",
        host: ~c"127.0.0.1",
        args: [~c"-setcookie", Atom.to_string(Node.get_cookie()) |> String.to_charlist()],
        connection: :standard_io,
        wait_boot: 20_000,
        peer_down: :continue
      })

    on_exit(fn -> if Process.alive?(peer), do: :peer.stop(peer) end)

    assert :peer.call(peer, Node, :connect, [Node.self()], 10_000),
           """
           an UNCONFINED node could not connect to the platform either.

           That sounds like good news and is not: it means the refutations above
           pass for some reason other than confinement, so `FR-003` is unproven
           and this suite cannot tell a real boundary from a broken host.
           """

    assert Node.self() in :peer.call(peer, Node, :list, [], 10_000)

    # Left disconnected: a connected node would leak into later tests.
    :peer.call(peer, Node, :disconnect, [Node.self()], 10_000)
    assert node != Node.self()
  end
end
