defmodule ExSandbox.Mechanism.Beam.IsolationClusterTest do
  @moduledoc """
  A sandbox cannot join the platform's cluster (005 T030, `FR-003`, R4).

  ## The contrast is the test

  Asserting `Node.list/0` is empty proves almost nothing on its own: `-hidden`
  makes a node invisible to discovery whether or not the cookie differs, so that
  assertion passes on a sandbox sharing the platform's cookie — the exact
  configuration where any sandbox could `Node.connect/1` to the platform and
  call `:erlang.halt/0` on it.

  The final test therefore deliberately gives a sandbox the platform's cookie
  and asserts it **can** connect. That contrast is what establishes the cookie
  as the control and `-hidden` as cosmetic. Without it, this file would be a
  test of nothing.
  """
  use ExUnit.Case, async: false

  @moduletag :isolation

  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  setup_all do
    # These tests need the platform node to actually be a distributed node;
    # otherwise `Node.connect/1` fails for a reason that has nothing to do with
    # cookies and every assertion below would pass vacuously.
    unless Node.alive?() do
      {:ok, _} = Node.start(:"platform_test@127.0.0.1", :longnames)
    end

    :ok
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
    {provisioned, String.to_atom(provisioned.mechanism_ref)}
  end

  test "a sandbox sees an empty cluster" do
    {_sb, node} = launch("a")

    assert :erpc.call(node, Node, :list, [], 10_000) == [],
           "sandbox is connected to other nodes"
  end

  test "an explicit connect to the platform is refused" do
    {_sb, node} = launch("a")

    # Explicit, not discovery. `-connect_all false` stops automatic meshing;
    # this asks whether a *deliberate* attempt is stopped, which is what hostile
    # tenant code would actually do.
    refute :erpc.call(node, Node, :connect, [Node.self()], 10_000),
           "sandbox connected to the platform node -- the cookie is not isolating it"

    refute Node.self() in :erpc.call(node, Node, :list, [], 10_000)
  end

  test "an explicit connect to another sandbox is refused" do
    {_a, node_a} = launch("a")
    {_b, node_b} = launch("b")

    refute :erpc.call(node_a, Node, :connect, [node_b], 10_000),
           "one sandbox connected to another -- cookies are shared between sandboxes"
  end

  test "with the platform's cookie a sandbox CAN connect (proving the cookie is the control)" do
    {_sb, node} = launch("a")

    # Deliberately weakening the boundary, in-process and reverted immediately.
    # If this connect fails, the earlier refutations were passing because of
    # `-hidden` or some unrelated cause, and this file's guarantees would be
    # unproven.
    :erpc.call(node, :erlang, :set_cookie, [Node.self(), Node.get_cookie()], 10_000)

    assert :erpc.call(node, Node, :connect, [Node.self()], 10_000),
           """
           a sandbox holding the platform's cookie could NOT connect.

           That sounds like good news and is not: it means the refutations above
           pass for some reason other than the cookie, so `FR-003` is unproven
           and this suite cannot tell a real boundary from a cosmetic one.
           """

    # Left disconnected: a connected sandbox would leak into later tests.
    :erpc.call(node, Node, :disconnect, [Node.self()], 10_000)
  end
end
