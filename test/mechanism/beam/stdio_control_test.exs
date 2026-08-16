defmodule ExSandbox.Mechanism.Beam.StdioControlTest do
  @moduledoc """
  The launcher must reach a sandbox over `:peer`'s stdio channel, never over
  Erlang distribution (005 T036g, FR-011, 003-FR-022).

  ## The conflict this resolves

  `FR-011` requires the sandbox get a private network namespace with no
  interfaces — `--unshare-net`, which is what denies it a path to the platform
  and to peer sandboxes. That construction works: verified inside the container,
  a sandbox under `--unshare-net` has no interfaces at all, not even loopback.

  Erlang distribution needs the network. So `:erpc.call/5` to a correctly
  confined sandbox **cannot** succeed:

      launched node sandbox-env-2499@... but could not read its OS pid:
      %ErlangError{original: {:erpc, :noconnection}}

  The launcher used `:erpc` to read the sandbox's OS pid — the pid
  `verify_applied/1` needs — so every launch failed *because the isolation
  worked*. The stronger the confinement, the more reliably it broke.

  ## Why `:peer.call/4` is the answer rather than relaxing the namespace

  `:peer` was already started with `connection: :standard_io`, an out-of-band
  control channel over the spawned process's stdin/stdout. It needs no network,
  no epmd, and no distribution — which is exactly why it survives
  `--unshare-net`. Measured, both under the same namespace:

  | Call | Result inside `--unshare-net` |
  |---|---|
  | `:peer.call(peer, :os, :getpid, [])` | `~c"2"` |
  | `:erpc.call(node, :os, :getpid, [], 3000)` | raises — no connection |

  The alternative — dropping `--unshare-net` so distribution reaches the
  sandbox — trades `FR-011` for convenience and would make `SC-001`'s cluster
  isolation tests pass by giving tenant code the network path they exist to deny.

  ## The related trap: `HOME` under `env -i`

  Reaching this required one more fix. With a cleared environment the sandbox's
  `auth` module cannot resolve a cookie directory and the kernel refuses to
  start:

      {failed_to_start_child,auth,{{badmatch,error},[{filename,basedir_join_home,...

  `HOME` must be granted, pointed at the sandbox's own storage. That is not a
  hole in `FR-004`'s allowlist — it is an entry in it, and it points somewhere
  the sandbox already owns.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Mechanism.Beam.NodeLauncher

  describe "the control channel" do
    test "is stdio, so confinement does not sever it" do
      source = File.read!("lib/ex_sandbox/mechanism/beam/node_launcher.ex")

      assert source =~ "connection: :standard_io",
             "`:peer` must be started with the stdio channel, or a confined " <>
               "sandbox is unreachable."
    end

    test "reads the OS pid without Erlang distribution" do
      source = File.read!("lib/ex_sandbox/mechanism/beam/node_launcher.ex")

      refute source =~ ~r/:erpc\.call\([^)]*:os,\s*:getpid/,
             """
             The OS pid is read with `:erpc`, which needs distribution. A sandbox
             under `--unshare-net` has no interfaces, so this fails for every
             correctly confined sandbox — the isolation working is what breaks it.

             Use `:peer.call/4`, which rides the stdio channel.
             """
    end
  end

  describe "the granted environment" do
    test "includes HOME, without which the sandbox kernel will not boot" do
      {:ok, {_prog, args}} =
        ExSandbox.Hardening.Linux.compose_for_inspection(
          %ExSandbox.Sandbox{
            id: "home-#{System.unique_integer([:positive])}",
            owner_ref: "o",
            template_ref: "t",
            memory_limit_mb: 256,
            cpu_limit: 500,
            disk_quota_mb: 1024
          },
          []
        )

      assert Enum.any?(args, &String.starts_with?(to_string(&1), "HOME=")),
             """
             No HOME in the cleared environment. `auth` resolves the cookie
             directory through it, and without it the sandbox dies with

                 failed_to_start_child,auth,{{badmatch,error},...

             before any tenant code runs.
             """
    end

    test "points HOME at the sandbox's own storage, not a shared directory" do
      sb = %ExSandbox.Sandbox{
        id: "home-scope-#{System.unique_integer([:positive])}",
        owner_ref: "o",
        template_ref: "t",
        memory_limit_mb: 256,
        cpu_limit: 500,
        disk_quota_mb: 1024
      }

      {:ok, {_prog, args}} = ExSandbox.Hardening.Linux.compose_for_inspection(sb, [])

      home =
        Enum.find_value(args, fn a ->
          a = to_string(a)
          if String.starts_with?(a, "HOME="), do: String.replace_prefix(a, "HOME=", "")
        end)

      assert home =~ sb.id,
             "HOME=#{home} is not this sandbox's storage; a shared HOME lets " <>
               "one sandbox read another's cookie."
    end
  end
end
