defmodule ExSandbox.Egress.AcceptBackoffTest do
  @moduledoc """
  A failing accept waits between attempts.

  An accept that fails with `:emfile` leaves its connection queued, so an
  immediate retry fails the same way. `:gen_tcp.accept/1` on a socket that is not
  listening fails at once too, which gives the loop the same shape on any host
  without exhausting this VM's descriptors.
  """
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ExSandbox.Egress.Acceptor

  @loopback {127, 0, 0, 1}

  test "the accept loop logs a handful of failures in a second, not thousands" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: @loopback])
    {:ok, port} = :inet.port(listener)
    {:ok, not_listening} = :gen_tcp.connect(@loopback, port, [:binary, active: false])

    log =
      capture_log(fn ->
        loop = spawn(fn -> Acceptor.accept_loop(%{listener: not_listening}) end)
        Process.sleep(1_000)
        Process.exit(loop, :kill)
      end)

    failures = length(String.split(log, "egress acceptor accept failed")) - 1
    assert failures in 1..5, "#{failures} failed accepts logged in one second"
  end
end
