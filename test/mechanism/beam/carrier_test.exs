defmodule ExSandbox.Mechanism.Beam.CarrierTest do
  @moduledoc """
  Both directions of the gateway's carrier on a running sandbox (D6 of
  `let-sandboxes-outlive-a-deploy`): a host connection to `Beam.address/1`
  reaches a listener inside the loopback-only namespace, and SMTP submission on
  587 to a granted host connects.
  """
  use ExUnit.Case, async: false

  @moduletag :isolation

  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  defp sandbox(tag, overrides) do
    struct!(
      %Sandbox{
        id: "carrier-#{tag}-#{System.unique_integer([:positive])}",
        owner_ref: "tenant-carrier",
        template_ref: "conformance-template",
        cpu_limit: 500,
        memory_limit_mb: 128,
        disk_quota_mb: 256
      },
      overrides
    )
  end

  defp eval_source(sandbox, source) do
    {:ok, tokens, _} = source |> String.to_charlist() |> :erl_scan.string()
    {:ok, exprs} = :erl_parse.parse_exprs(tokens)

    case Beam.call(sandbox, :erl_eval, :exprs, [exprs, []], 10_000) do
      {:ok, {:value, value, _bindings}} -> value
      other -> other
    end
  end

  @echo_server """
  Parent = self(),
  spawn(fun() ->
    case gen_tcp:listen(4000, [binary, {active, false}, {reuseaddr, true}, {ip, {127,0,0,1}}]) of
      {ok, L} ->
        Parent ! listening,
        Loop = fun Loop() ->
          case gen_tcp:accept(L) of
            {ok, S} ->
              {ok, D} = gen_tcp:recv(S, 0, 5000),
              gen_tcp:send(S, <<"echo:", D/binary>>),
              gen_tcp:close(S),
              Loop();
            _ -> ok
          end
        end,
        Loop();
      Error ->
        Parent ! Error
    end
  end),
  receive Reply -> Reply after 5000 -> timeout end.
  """

  test "a host connection to the published address reaches the sandbox's listener" do
    sandbox =
      ExSandbox.Test.IsolationLaunch.provision_or_skip(
        Beam,
        sandbox("inbound", service_port: 4000, context: %{network_allowlist: []})
      )

    assert eval_source(sandbox, @echo_server) == :listening

    assert {:ok, "127.0.0.1:" <> port} = Beam.address(sandbox)

    {:ok, socket} =
      :gen_tcp.connect({127, 0, 0, 1}, String.to_integer(port), [:binary, active: false], 5_000)

    :ok = :gen_tcp.send(socket, "ping")

    assert {:ok, "echo:ping"} = :gen_tcp.recv(socket, 0, 5_000),
           "the published address did not reach the listener inside the sandbox"

    :gen_tcp.close(socket)
  end

  test "SMTP submission on 587 to a granted host connects" do
    {:ok, ip} = :inet.getaddr(~c"smtp.gmail.com", :inet)
    address = ip |> :inet.ntoa() |> to_string()

    case :gen_tcp.connect(ip, 587, [], 5_000) do
      {:ok, socket} -> :gen_tcp.close(socket)
      {:error, reason} -> flunk("the host cannot reach #{address}:587 (#{inspect(reason)})")
    end

    sandbox =
      ExSandbox.Test.IsolationLaunch.provision_or_skip(
        Beam,
        sandbox("smtp", context: %{network_allowlist: [{address, 587}, {address, 25}]})
      )

    assert sandbox.context.connect.(address, 587) == :connected,
           "submission on 587 to a granted host was refused"

    refute sandbox.context.connect.(address, 25) == :connected,
           "port 25 was reached although it is never granted"
  end
end
