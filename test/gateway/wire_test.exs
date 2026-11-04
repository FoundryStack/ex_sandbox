defmodule ExSandbox.Gateway.WireTest do
  @moduledoc """
  How a sandbox crosses the gateway socket across wire versions
  (`hosting/FR-002`): the version 3 map at both ends, the version 2 struct an
  older peer still sends, and the named refusal when the gateway speaks
  neither.

  Not async: `ExSandbox.Mechanism.Gateway` is one named process per VM, and
  `ExSandbox.GatewayTest` starts it too.
  """
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ExSandbox.Gateway.Protocol
  alias ExSandbox.Gateway.Wire
  alias ExSandbox.Sandbox

  defmodule RecordingMechanism do
    @moduledoc false
    @behaviour ExSandbox.Mechanism

    @impl true
    def required_capabilities, do: []
    @impl true
    def provision(sandbox), do: {:ok, %{sandbox | mechanism_ref: "rec-" <> sandbox.id}}
    @impl true
    def start(sandbox) do
      :ets.insert(__MODULE__, {sandbox.id, sandbox})
      {:ok, sandbox}
    end

    @impl true
    def stop(sandbox), do: {:ok, sandbox}
    @impl true
    def destroy(_sandbox), do: :ok
    @impl true
    def status(_sandbox), do: {:ok, :running}
    @impl true
    def list_running, do: {:ok, ["rec-a"]}
    @impl true
    def usage(_sandbox), do: {:ok, %{memory_mb: 1}}
    @impl true
    def execute(_sandbox, _command, _opts \\ []), do: {:error, {:could_not_run, :not_supported}}
    @impl true
    def update_egress(sandbox, _allowed), do: {:ok, sandbox}

    def received(id) do
      [{^id, sandbox}] = :ets.lookup(__MODULE__, id)
      sandbox
    end
  end

  # `{:request, 1, :start, {:start, sandbox}}` as ex_sandbox d09d6f4 encodes
  # it: the struct itself, with the fields of that ref and no `listed`.
  @v2_start_frame Base.decode64!(
                    "g2gEdwdyZXF1ZXN0YQF3BXN0YXJ0aAJ3BXN0YXJ0dAAAAA13AmlkbQAAAAp2Mi1maXh0" <>
                      "dXJldwR1c2VydwNuaWx3B2NvbnRleHR0AAAAAXcFcHJvYmV3AXB3Cl9fc3RydWN0X193GEVs" <>
                      "aXhpci5FeFNhbmRib3guU2FuZGJveHcJb3duZXJfcmVmbQAAAAVvd25lcncMdGVtcGxhdGVf" <>
                      "cmVmbQAAAAh0ZW1wbGF0ZXcJY3B1X2xpbWl0YgAAAfR3DndvcmtzcGFjZV9wYXRobQAAAAcv" <>
                      "c3J2L3dzdxNleHRyYV9zZXJ2aWNlX3BvcnRzbAAAAAFiAAAfkWp3D21lbW9yeV9saW1pdF9t" <>
                      "YncDbmlsdw1kaXNrX3F1b3RhX21idwNuaWx3DW1lY2hhbmlzbV9yZWZ3A25pbHcMc2Vydmlj" <>
                      "ZV9wb3J0dwNuaWw="
                  )

  @v2_fields [
    :id,
    :owner_ref,
    :template_ref,
    :cpu_limit,
    :memory_limit_mb,
    :disk_quota_mb,
    :mechanism_ref,
    :workspace_path,
    :service_port,
    :user,
    :extra_service_ports,
    :listed,
    :context
  ]

  setup_all do
    :ets.new(RecordingMechanism, [:named_table, :public])
    :ok
  end

  defp sandbox(attrs \\ []) do
    struct!(
      Sandbox,
      Keyword.merge(
        [id: "wire-#{System.unique_integer([:positive])}", owner_ref: "o", template_ref: "t"],
        attrs
      )
    )
  end

  defp socket_path, do: "/tmp/exsw-#{System.unique_integer([:positive])}.sock"

  defp start_gateway(path) do
    name = :"gateway_#{System.unique_integer([:positive])}"

    start_supervised!(
      {ExSandbox.Gateway, socket_path: path, mechanism: RecordingMechanism, name: name},
      id: name
    )
  end

  defp connect(path) do
    {:ok, socket} = :gen_tcp.connect({:local, path}, 0, [:binary, packet: 4, active: false])
    socket
  end

  defp send_frame(socket, term), do: :ok = :gen_tcp.send(socket, Protocol.encode(term))

  defp recv(socket) do
    {:ok, frame} = :gen_tcp.recv(socket, 0, 5_000)
    {:ok, {:reply, id, result}} = Protocol.decode(frame)
    {:reply, id, Protocol.unwrap(result)}
  end

  defp hello(socket, versions) do
    send_frame(socket, {:request, 0, :hello, %{versions: versions}})
    assert {:reply, 0, {:ok, %{version: version}}} = recv(socket)
    version
  end

  describe "Wire" do
    test "a struct round-trips through its wire form, context atoms included" do
      sb = sandbox(cpu_limit: 250, listed: false, context: %{probe: :p, net: [{:public, 443}]})
      wire = Wire.to_wire(sb)

      assert wire["v"] == 3
      assert Enum.all?(Map.keys(wire), &is_binary/1)
      assert {:opaque, _} = wire["context"]
      assert Wire.from_wire(wire) == {:ok, sb}
    end

    test "a key the reader does not know is ignored" do
      wire = Map.put(Wire.to_wire(sandbox()), "colour", "blue")
      assert {:ok, %Sandbox{}} = Wire.from_wire(wire)
    end

    test "a key the writer did not send takes the struct's default" do
      wire = Map.delete(Wire.to_wire(sandbox(listed: false)), "listed")
      assert {:ok, %Sandbox{listed: true}} = Wire.from_wire(wire)
    end

    test "a sandbox without its identity is refused by key" do
      wire = Wire.to_wire(sandbox()) |> Map.delete("id") |> Map.delete("template_ref")
      assert Wire.from_wire(wire) == {:error, {:bad_sandbox, ["id", "template_ref"]}}
    end
  end

  describe "the gateway at version 3" do
    test "a field the gateway does not know reaches the mechanism without it (S1)" do
      path = socket_path()
      start_gateway(path)
      socket = connect(path)
      assert hello(socket, [Protocol.client_version()]) == 3

      sb = sandbox()
      wire = Map.put(Wire.to_wire(sb), "colour", "blue")
      send_frame(socket, {:request, 1, :start, {:start, wire}})

      assert {:reply, 1, {:ok, started}} = recv(socket)
      assert Wire.from_wire(started) == {:ok, sb}
      assert RecordingMechanism.received(sb.id) == sb
    end

    test "a field the client does not send reaches the mechanism at its default (S2)" do
      path = socket_path()
      start_gateway(path)
      socket = connect(path)
      hello(socket, [3])

      sb = sandbox(listed: false)
      wire = Map.delete(Wire.to_wire(sb), "listed")
      send_frame(socket, {:request, 1, :start, {:start, wire}})

      assert {:reply, 1, {:ok, _}} = recv(socket)
      assert RecordingMechanism.received(sb.id).listed == true
    end

    test "a field the client sets off its default reaches the mechanism as set" do
      path = socket_path()
      start_gateway(path)
      socket = connect(path)
      hello(socket, [3])

      sb = sandbox(listed: false)
      send_frame(socket, {:request, 1, :start, {:start, Wire.to_wire(sb)}})

      assert {:reply, 1, {:ok, _}} = recv(socket)
      assert RecordingMechanism.received(sb.id).listed == false
    end

    test "a sandbox without its identity is answered, not raised on" do
      path = socket_path()
      start_gateway(path)
      socket = connect(path)
      hello(socket, [3])

      send_frame(socket, {:request, 1, :status, {:status, %{"v" => 3, "owner_ref" => "o"}}})
      assert recv(socket) == {:reply, 1, {:error, {:bad_sandbox, ["id", "template_ref"]}}}
    end
  end

  describe "the gateway at version 2" do
    test "a frame d09d6f4 encoded reaches the mechanism with listed at its default" do
      path = socket_path()
      start_gateway(path)
      socket = connect(path)
      assert hello(socket, [2, 1]) == 2

      :ok = :gen_tcp.send(socket, @v2_start_frame)
      assert {:reply, 1, {:ok, %Sandbox{} = started}} = recv(socket)

      received = RecordingMechanism.received("v2-fixture")
      assert received.listed == true
      assert received.cpu_limit == 500
      assert received.extra_service_ports == [8081]
      assert received.context == %{probe: :p}
      assert started == received
    end

    test "a reply carries the struct as version 2 knew it" do
      path = socket_path()
      start_gateway(path)
      socket = connect(path)
      hello(socket, [2, 1])

      send_frame(socket, {:request, 1, :start, {:provision, sandbox()}})
      assert {:reply, 1, {:ok, %Sandbox{} = provisioned}} = recv(socket)
      assert Enum.sort(Map.keys(provisioned)) == Enum.sort([:__struct__ | @v2_fields])
    end

    test "version 1 is no longer spoken" do
      path = socket_path()
      start_gateway(path)
      socket = connect(path)

      send_frame(socket, {:request, 0, :hello, %{versions: [1]}})
      assert recv(socket) == {:reply, 0, {:error, {:unsupported_versions, [3, 2]}}}
    end
  end

  describe "the client" do
    defp refusing_gateway(path, test) do
      _ = File.rm(path)

      {:ok, listen} =
        :gen_tcp.listen(0, [:binary, ifaddr: {:local, path}, packet: 4, active: false])

      spawn_link(fn -> refuse_loop(listen, test) end)
      on_exit(fn -> File.rm(path) end)
    end

    defp refuse_loop(listen, test) do
      {:ok, socket} = :gen_tcp.accept(listen)
      {:ok, frame} = :gen_tcp.recv(socket, 0, 5_000)
      {:ok, {:request, id, :hello, hello}} = Protocol.decode(frame)
      send(test, {:hello, hello})

      :ok =
        :gen_tcp.send(
          socket,
          Protocol.encode({:reply, id, {:error, {:unsupported_versions, [2, 1]}}})
        )

      :gen_tcp.close(socket)
      refuse_loop(listen, test)
    end

    test "a sandbox set off its defaults arrives at the mechanism as set" do
      path = socket_path()
      start_gateway(path)
      start_supervised!({ExSandbox.Mechanism.Gateway, socket_path: path})

      sb = sandbox(listed: false, context: %{probe: :p})
      assert {:ok, %Sandbox{} = started} = ExSandbox.Mechanism.Gateway.start(sb)
      assert started == sb
      assert RecordingMechanism.received(sb.id) == sb
    end

    test "a gateway that speaks versions 2 and 1 refuses by name, at once (S3)" do
      path = socket_path()
      refusing_gateway(path, self())

      log =
        capture_log(fn ->
          start_supervised!({ExSandbox.Mechanism.Gateway, socket_path: path})
          assert_receive {:hello, %{versions: [3]}}, 5_000
          Process.sleep(1_200)

          {elapsed_us, result} =
            :timer.tc(fn -> ExSandbox.Mechanism.Gateway.status(sandbox()) end)

          assert result == {:error, {:gateway_version, %{client: 3, gateway: [2, 1]}}}
          assert elapsed_us < 5_000_000
        end)

      assert log =~ "client speaks 3"
      assert log =~ "gateway speaks [2, 1]"
      assert log =~ "gateway step"
      assert length(String.split(log, "gateway speaks [2, 1]")) == 2
    end
  end
end
