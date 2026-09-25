defmodule ExSandbox.Hardening.ConfinementEgressTest do
  @moduledoc """
  `egress: {:loopback_only, port}` leaves a confined process one way out: the
  proxy on `port`.

  Every assertion is a real connection. The target is an HTTP listener on this
  host's first non-loopback IPv4 address, which stands in for a public host: it
  is not loopback, so the profile must refuse a direct dial to it, and it needs
  no internet, so the test means the same thing on a laptop and a runner.

  ⚠️ Each refusal has a control. The same `curl` unconfined reaches the target,
  and the same `curl` confined reaches it through the proxy. A profile that
  denied everything would pass the refusal and fail the second control, and a
  target nothing could reach would pass the refusal and fail the first.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Hardening.Confinement

  setup do
    curl = System.find_executable("curl") || flunk("curl is not on PATH")

    ip =
      outside_ip() ||
        flunk("this host has no non-loopback IPv4 address to stand in for a public host")

    permit =
      Path.join(System.tmp_dir!(), "confinement-egress-#{System.unique_integer([:positive])}")

    File.mkdir_p!(permit)
    on_exit(fn -> File.rm_rf(permit) end)

    {:ok, target} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {0, 0, 0, 0}])

    {:ok, target_port} = :inet.port(target)

    serve(target, fn socket ->
      :gen_tcp.send(socket, "HTTP/1.0 200 OK\r\ncontent-length: 7\r\n\r\ntarget\n")
    end)

    {:ok, proxy} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, proxy_port} = :inet.port(proxy)
    serve(proxy, &connect_tunnel/1)

    {:ok, other} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, other_port} = :inet.port(other)
    serve(other, fn socket -> :gen_tcp.send(socket, "HTTP/1.0 200 OK\r\n\r\n") end)

    {:ok,
     curl: curl,
     permit: permit,
     url: "http://#{ip}:#{target_port}/",
     proxy_port: proxy_port,
     other_port: other_port}
  end

  test "the target is reachable unconfined, so a refusal below is the profile's", ctx do
    assert {"target\n", 0} = System.cmd(ctx.curl, ["-sS", "--noproxy", "*", "-m", "5", ctx.url])
  end

  test "a confined direct dial to a non-loopback host is refused", ctx do
    {out, status} = confined(ctx, ["-sS", "--noproxy", "*", "-m", "5", ctx.url])

    assert status != 0, "a direct dial got through: #{out}"
    refute out =~ "target"
  end

  test "the same request through the proxy port succeeds", ctx do
    {out, status} =
      confined(ctx, ["-sS", "-m", "10", "-p", "-x", "http://127.0.0.1:#{ctx.proxy_port}", ctx.url])

    assert {out, status} == {"target\n", 0}
  end

  # MEASURED 2026-09-25 on Ubuntu 24.04: a platform's permit path was
  # `/var/lib/axonn/tenants/<uuid>/<uuid>`, the bridge socket inside it came to
  # 127 bytes, and `socat` refused it ("max length is 108"). Every connection
  # the confined process made was reset, the model endpoint included. A path
  # that deep is ordinary, so the socket must not depend on it.
  test "a permit path deeper than a unix socket address allows still reaches the proxy", ctx do
    deep = Path.join([ctx.permit | List.duplicate(String.duplicate("d", 40), 3)])
    File.mkdir_p!(deep)
    assert byte_size(deep) > 108

    {out, status} =
      confined(%{ctx | permit: deep}, [
        "-sS",
        "-m",
        "10",
        "-p",
        "-x",
        "http://127.0.0.1:#{ctx.proxy_port}",
        ctx.url
      ])

    assert {out, status} == {"target\n", 0}
  end

  # Linux only: macOS confines the network with sandbox-exec and has no bridge.
  @tag :isolation
  test "a temp dir too deep for the bridge's socket refuses the launch rather than resetting every connection",
       ctx do
    deep = Path.join([ctx.permit | List.duplicate(String.duplicate("t", 40), 3)])
    File.mkdir_p!(deep)
    previous = System.get_env("TMPDIR")
    System.put_env("TMPDIR", deep)

    on_exit(fn ->
      if previous, do: System.put_env("TMPDIR", previous), else: System.delete_env("TMPDIR")
    end)

    assert {:error, {:cannot_enforce, :network_restriction, detail}} =
             Confinement.confine({ctx.curl, ["-sS", ctx.url]},
               permit_path: ctx.permit,
               egress: {:loopback_only, ctx.proxy_port}
             )

    assert detail =~ "TMPDIR"
  end

  test "another loopback port is refused", ctx do
    {out, status} =
      confined(ctx, ["-sS", "--noproxy", "*", "-m", "5", "http://127.0.0.1:#{ctx.other_port}/"])

    assert status != 0, "a second loopback port got through: #{out}"
  end

  test "an egress value it does not know is refused, never read as open", ctx do
    assert {:error, {:cannot_enforce, :network_restriction, _}} =
             Confinement.confine({ctx.curl, []},
               permit_path: ctx.permit,
               egress: {:loopback_only, 0}
             )

    assert {:error, {:cannot_enforce, :network_restriction, _}} =
             Confinement.confine({ctx.curl, []}, permit_path: ctx.permit, egress: :none)
  end

  defp confined(ctx, args) do
    case Confinement.confine({ctx.curl, args},
           permit_path: ctx.permit,
           egress: {:loopback_only, ctx.proxy_port}
         ) do
      {:ok, %{cmd: cmd, args: args, env: env, cd: cd}} ->
        System.cmd(cmd, args, env: env, cd: cd, stderr_to_stdout: true)

      {:error, reason} ->
        flunk("the confinement could not be built: #{inspect(reason)}")
    end
  end

  defp outside_ip do
    {:ok, interfaces} = :inet.getifaddrs()

    Enum.find_value(interfaces, fn {_name, opts} ->
      flags = Keyword.get_values(opts, :flags) |> List.flatten()

      if :up in flags and :loopback not in flags do
        Enum.find_value(Keyword.get_values(opts, :addr), fn
          {a, _, _, _} = ip when a not in [127, 169] -> :inet.ntoa(ip) |> to_string()
          _ -> nil
        end)
      end
    end)
  end

  defp serve(listen, handler) do
    pid =
      spawn(fn ->
        accept = fn accept ->
          case :gen_tcp.accept(listen) do
            {:ok, socket} ->
              spawn(fn -> handler.(socket) end) |> then(&:gen_tcp.controlling_process(socket, &1))
              accept.(accept)

            {:error, _} ->
              :ok
          end
        end

        accept.(accept)
      end)

    on_exit(fn ->
      :gen_tcp.close(listen)
      Process.exit(pid, :kill)
    end)
  end

  # The smallest CONNECT proxy that is one: read the request line, dial what it
  # names, answer 200, and carry bytes both ways until either side closes.
  defp connect_tunnel(client) do
    {:ok, head} = read_head(client, "")
    [_, target] = Regex.run(~r/^CONNECT (\S+) /, head)
    [host, port] = String.split(target, ":")

    {:ok, upstream} =
      :gen_tcp.connect(String.to_charlist(host), String.to_integer(port), [:binary, active: false])

    :ok = :gen_tcp.send(client, "HTTP/1.1 200 Connection established\r\n\r\n")
    me = self()

    spawn(fn ->
      pump(upstream, client)
      send(me, :done)
    end)

    pump(client, upstream)
    receive do: (:done -> :ok), after: (5_000 -> :ok)
  end

  defp read_head(socket, acc) do
    if String.contains?(acc, "\r\n\r\n") do
      {:ok, acc}
    else
      {:ok, more} = :gen_tcp.recv(socket, 0, 5_000)
      read_head(socket, acc <> more)
    end
  end

  defp pump(from, to) do
    case :gen_tcp.recv(from, 0, 10_000) do
      {:ok, data} ->
        :gen_tcp.send(to, data)
        pump(from, to)

      {:error, _} ->
        :gen_tcp.shutdown(to, :write)
    end
  end
end
