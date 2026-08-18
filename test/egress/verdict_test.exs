defmodule ExSandbox.Egress.VerdictTest do
  @moduledoc """
  The verdict protocol (005 T060a1), tested without a namespace or a redirect.

  The acceptor that consumes this runs inside a sandbox's network namespace and
  cannot be exercised off Linux. The *protocol* it speaks can be, and that is
  most of what can go wrong: a malformed request, an unknown source, a reply
  that widens the boundary when the check could not run.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Registry
  alias ExSandbox.Egress.Verdict

  setup do
    server =
      start_supervised!({Registry, name: :"verdict_#{System.unique_integer([:positive])}"})

    %{registry: server}
  end

  @source_key {10, 0, 4, 0}
  @allowed {"api.example.com", 443}

  describe "answer/2" do
    test "a permitted destination is PERMIT", %{registry: r} do
      :ok = Registry.assign(@source_key, [@allowed], r)
      assert Verdict.answer("10.0.4.0 api.example.com 443", r) == "PERMIT"
    end

    test "a destination outside the allowlist is DENY", %{registry: r} do
      :ok = Registry.assign(@source_key, [@allowed], r)
      assert Verdict.answer("10.0.4.0 evil.example.com 443", r) == "DENY"
    end

    test "a source with no policy is DENY, never a default-allow", %{registry: r} do
      # ⚠️ The /30 was never assigned, or was already released. Treating that as
      # "no restrictions" is the failure `Registry.lookup/2` returning `[]`
      # exists to prevent, and it would arrive here as a widened boundary.
      assert Verdict.answer("10.0.8.0 api.example.com 443", r) == "DENY"
    end

    test "the port is honoured, not just the host", %{registry: r} do
      :ok = Registry.assign(@source_key, [@allowed], r)
      assert Verdict.answer("10.0.4.0 api.example.com 80", r) == "DENY"
    end
  end

  describe "answer/2 refuses everything it cannot parse" do
    # ⚠️ Each of these is a request the acceptor should never send. The point is
    # what happens when one arrives anyway: a malformed request is not a reason
    # to widen a boundary, and the tempting `else -> allow` clause is the one
    # bug in this subsystem that fails open.
    for {name, line} <- [
          {"an empty line", ""},
          {"a missing port", "10.0.4.0 api.example.com"},
          {"a non-numeric port", "10.0.4.0 api.example.com https"},
          {"a partial port", "10.0.4.0 api.example.com 443x"},
          {"a malformed source key", "not-an-address api.example.com 443"},
          {"an out-of-range octet", "10.0.999.0 api.example.com 443"},
          {"a three-octet source", "10.0.4 api.example.com 443"},
          {"pure noise", "PERMIT"}
        ] do
      test "#{name} is DENY", %{registry: r} do
        assert Verdict.answer(unquote(line), r) == "DENY"
      end
    end
  end

  describe "the wire" do
    setup %{registry: r} do
      path =
        Path.join(
          System.tmp_dir!(),
          "axonn-verdict-#{System.unique_integer([:positive])}.sock"
        )

      server =
        start_supervised!(
          {Verdict,
           name: :"verdict_srv_#{System.unique_integer([:positive])}", path: path, registry: r}
        )

      on_exit(fn -> File.rm(path) end)
      %{path: path, server: server}
    end

    test "answers a request over AF_UNIX", %{path: path, registry: r} do
      :ok = Registry.assign(@source_key, [@allowed], r)

      assert ask(path, "10.0.4.0 api.example.com 443") == "PERMIT"
      assert ask(path, "10.0.4.0 evil.example.com 443") == "DENY"
    end

    test "reports the path it is actually bound to", %{server: server, path: path} do
      # Read from the running server rather than from configuration: a
      # configured path names a socket that may not exist.
      assert Verdict.path(server) == path
      assert File.exists?(path)
    end

    test "serves more than one request", %{path: path, registry: r} do
      # A verdict server that answers once and stops would let the first
      # connection through and deny the rest -- which reads as a flaky network
      # rather than a broken platform.
      :ok = Registry.assign(@source_key, [@allowed], r)

      for _ <- 1..5 do
        assert ask(path, "10.0.4.0 api.example.com 443") == "PERMIT"
      end
    end
  end

  defp ask(path, request) do
    {:ok, socket} =
      :gen_tcp.connect({:local, path}, 0, [:binary, active: false, packet: :line])

    :ok = :gen_tcp.send(socket, request <> "\n")
    {:ok, reply} = :gen_tcp.recv(socket, 0, 2_000)
    :gen_tcp.close(socket)
    String.trim(reply)
  end
end
