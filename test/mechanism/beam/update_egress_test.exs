defmodule ExSandbox.Mechanism.Beam.UpdateEgressTest do
  @moduledoc """
  A running sandbox's allowlist changes without a restart.

  The same sandbox dials the same destination twice. The first dial is refused
  because the allowlist does not name it; `ExSandbox.update_egress/4` then adds
  it, and the second dial connects. The sandbox is never stopped in between, so
  the only thing that can explain the second verdict is the replaced policy.

  The first dial also proves the launch hands the acceptor the sandbox's
  `owner_ref` and `sandbox_id`: the refusal event carries both.
  """
  use ExUnit.Case, async: false

  @moduletag :isolation

  alias ExSandbox.Conformance.Network
  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  test "a destination added to a running sandbox is reachable on the next dial" do
    # ⚠️ The destination that moves onto the list is `permitted_address/0`,
    # not `denied_address/0`. The probe sends one byte and reads, and 8.8.8.8:53
    # closes on it: measured from the host with no sandbox at all, it answers
    # `{error, closed}`, which the probe scores `:refused`. A test adding it
    # could never see `:connected`, however well the update worked.
    initial = Network.denied_address()
    {host, port} = added = Network.permitted_address()

    sandbox =
      ExSandbox.Test.IsolationLaunch.provision_or_skip(Beam, %Sandbox{
        id: "update-egress-#{System.unique_integer([:positive])}",
        owner_ref: "tenant-update-egress",
        template_ref: "conformance-template",
        cpu_limit: 500,
        memory_limit_mb: 128,
        disk_quota_mb: 256,
        context: %{network_allowlist: [initial]}
      })

    # ⚠️ The host must reach the destination itself, or "still refused after
    # the update" would be the host's egress, not the sandbox's policy.
    case :gen_tcp.connect(String.to_charlist(host), port, [], 3_000) do
      {:ok, socket} -> :gen_tcp.close(socket)
      {:error, reason} -> flunk("the host cannot reach #{host}:#{port} (#{inspect(reason)})")
    end

    handler = "update-egress-#{System.unique_integer([:positive])}"
    test_process = self()

    :telemetry.attach(
      handler,
      [:ex_sandbox, :egress, :refused],
      fn _event, _measurements, metadata, _ -> send(test_process, {:refused_event, metadata}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler) end)

    refute sandbox.context.connect.(host, port) == :connected,
           "#{host}:#{port} was reachable before the allowlist named it"

    # The launch threads the sandbox's identity to its acceptor, so the refusal
    # arrives attributed without the host mapping a /30 back to a sandbox.
    sandbox_id = sandbox.id

    assert_receive {:refused_event,
                    %{
                      owner_ref: "tenant-update-egress",
                      sandbox_id: ^sandbox_id,
                      port: ^port,
                      reason: :not_permitted
                    }},
                   5_000

    assert {:ok, updated} =
             ExSandbox.update_egress(Beam, sandbox, [initial, added], host_aliases: [])

    assert updated.context.network_allowlist == [initial, added]

    assert sandbox.context.connect.(host, port) == :connected,
           "the running sandbox still refused #{host}:#{port} after the update"
  end
end
