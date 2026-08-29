defmodule ExSandbox.Mechanism.DockerAddressTest do
  @moduledoc """
  A server inside the sandbox answers at the address the mechanism reports, and
  a sandbox that is not running reports none (`studio/FR-007/S1`,
  `studio/FR-007/S3`).

  ⚠️ The request is made from the host, over TCP, to the address `address/1`
  returned -- not to a port this test chose. A test that published a port it
  picked and then fetched that same port would confirm its own arithmetic and
  would pass unchanged if `address/1` returned a stale or invented binding,
  which is the failure that reaches a person as an empty preview frame.

  `ExSandbox.Mechanism.DockerNetworkPostureTest` holds the half this cannot: a
  published port answers this host either way, so nothing here can tell loopback
  from every interface.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Mechanism.Docker
  alias ExSandbox.Sandbox

  @moduletag :docker

  # Long enough for `docker run` to pull nothing and start a shell on a loaded
  # machine, short enough that a container which never listens is a failure
  # rather than a hang.
  @listen_timeout_ms 15_000

  @service_port 8080

  defp provisioned(overrides) do
    sandbox =
      struct!(
        %Sandbox{
          id: "docker-address-#{System.unique_integer([:positive])}",
          owner_ref: "test",
          template_ref: Docker.default_image()
        },
        overrides
      )

    {:ok, provisioned} = Docker.provision(sandbox)
    on_exit(fn -> Docker.destroy(provisioned) end)
    provisioned
  end

  describe "a running sandbox serving on its service port" do
    setup do
      sandbox = provisioned(service_port: @service_port)
      {:ok, started} = Docker.start(sandbox)

      # `nc` is in busybox, which is what the default image is. One connection,
      # one response, then it exits -- so a second request failing is the
      # server's own doing rather than an address that stopped working.
      spawn(fn ->
        Docker.execute(
          started,
          {"sh",
           [
             "-c",
             "while true; do printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nok' " <>
               "| nc -l -p #{@service_port}; done"
           ]},
          timeout: @listen_timeout_ms
        )
      end)

      {:ok, sandbox: started}
    end

    test "reports an address the host can reach", %{sandbox: sandbox} do
      address = await_address(sandbox)

      assert is_binary(address)

      assert {host, port} = split(address)
      assert host == "127.0.0.1"

      assert await_answer(host, port, @listen_timeout_ms),
             """
             Nothing answered at #{address}, which is the address the mechanism
             reported for a running sandbox with a server inside it.
             """
    end

    test "reports the port the daemon allocated, not the port inside", %{sandbox: sandbox} do
      assert {_host, port} = split(await_address(sandbox))

      # The published host port is the daemon's choice. Asserting only that it
      # is not the container's own port keeps this from restating the
      # allocation, while still failing if the container port is echoed back --
      # which would be an address that answers only by coincidence.
      assert port != @service_port
    end
  end

  describe "a sandbox that is not running" do
    test "reports no address rather than an error" do
      sandbox = provisioned(service_port: @service_port)
      {:ok, started} = Docker.start(sandbox)
      {:ok, stopped} = Docker.stop(started)

      assert {:ok, nil} = Docker.address(stopped)
    end

    test "reports no address before it has ever been started" do
      assert {:ok, nil} = Docker.address(provisioned(service_port: @service_port))
    end

    test "reports no address when it was never provisioned" do
      assert {:ok, nil} =
               Docker.address(%Sandbox{
                 id: "never-provisioned",
                 owner_ref: "test",
                 template_ref: Docker.default_image(),
                 service_port: @service_port
               })
    end
  end

  describe "a running sandbox that names no service port" do
    test "reports no address" do
      sandbox = provisioned(service_port: nil)
      {:ok, started} = Docker.start(sandbox)

      assert {:ok, nil} = Docker.address(started)
    end
  end

  # ⚠️ Polled, and the mechanism is deliberately not made to poll on the caller's
  # behalf.
  #
  # The daemon realises a port binding as part of starting the container and
  # reports it a moment later; asked in that window it answers with no binding
  # at all. MEASURED: two runs of this file, one test in each read an address
  # immediately after `start/1` and the other did not. `address/1` reports what
  # it observed, which is the honest answer and the one a re-read corrects. A
  # mechanism that blocked until a binding appeared would turn "not published
  # yet" into a stall inside every caller, including the ones rendering a
  # stopped sandbox.
  defp await_address(sandbox, timeout_ms \\ @listen_timeout_ms) do
    await_address_until(sandbox, System.monotonic_time(:millisecond) + timeout_ms, timeout_ms)
  end

  defp await_address_until(sandbox, deadline, timeout_ms) do
    case Docker.address(sandbox) do
      {:ok, address} when is_binary(address) ->
        address

      _not_yet ->
        if System.monotonic_time(:millisecond) < deadline do
          Process.sleep(250)
          await_address_until(sandbox, deadline, timeout_ms)
        else
          flunk("no address was reported for a running sandbox within #{timeout_ms}ms")
        end
    end
  end

  defp split(address) do
    [host, port] = String.split(address, ":", parts: 2)
    {host, String.to_integer(port)}
  end

  defp await_answer(host, port, timeout_ms) do
    await_answer_until(host, port, System.monotonic_time(:millisecond) + timeout_ms)
  end

  # ⚠️ A connection that opens and returns nothing is retried, not scored as an
  # answer and not as a refusal.
  #
  # MEASURED, and it is why this file was flaky in roughly one run in three: a
  # published port with nothing listening **inside** the container still
  # completes the TCP handshake -- the daemon's proxy accepts on the host and
  # only then fails to reach the container, closing the connection. So a
  # connect that succeeds proves the publication, not the server, and the first
  # attempt lands in the window before `docker exec` has the listener up.
  defp await_answer_until(host, port, deadline) do
    cond do
      answered?(host, port) ->
        true

      System.monotonic_time(:millisecond) >= deadline ->
        false

      true ->
        Process.sleep(250)
        await_answer_until(host, port, deadline)
    end
  end

  defp answered?(host, port) do
    case :gen_tcp.connect(~c"#{host}", port, [:binary, active: false], 1_000) do
      {:ok, socket} ->
        :gen_tcp.send(socket, "GET / HTTP/1.0\r\n\r\n")
        answered? = match?({:ok, _data}, :gen_tcp.recv(socket, 0, 2_000))
        :gen_tcp.close(socket)
        answered?

      {:error, _reason} ->
        false
    end
  end
end
