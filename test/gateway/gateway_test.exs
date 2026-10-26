defmodule ExSandbox.GatewayTest do
  @moduledoc """
  `ExSandbox.Gateway`'s socket protocol and `ExSandbox.Mechanism.Gateway`'s
  client, against a mechanism that runs calls in this VM.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Gateway.PeerCred
  alias ExSandbox.Gateway.Protocol
  alias ExSandbox.Sandbox

  defmodule LocalMechanism do
    @moduledoc false
    @behaviour ExSandbox.Mechanism

    @impl true
    def required_capabilities, do: []
    @impl true
    def provision(sandbox) do
      context = %{probe: fn tag -> {tag, self()} end}
      {:ok, %{sandbox | mechanism_ref: "local-" <> sandbox.id, context: context}}
    end

    @impl true
    def start(sandbox), do: {:ok, sandbox}
    @impl true
    def stop(sandbox), do: {:ok, sandbox}
    @impl true
    def destroy(_sandbox), do: :ok
    @impl true
    def status(_sandbox), do: {:ok, :running}
    @impl true
    def list_running, do: {:ok, ["local-a"]}
    @impl true
    def usage(_sandbox), do: {:ok, %{memory_mb: 1}}
    @impl true
    def execute(_sandbox, _command, _opts \\ []), do: {:error, {:could_not_run, :not_supported}}
    @impl true
    def update_egress(sandbox, allowed),
      do: {:ok, %{sandbox | context: %{network_allowlist: allowed}}}

    def call(_sandbox, m, f, a, _timeout), do: {:ok, apply(m, f, a)}
  end

  def after_ms(ms, value) do
    Process.sleep(ms)
    value
  end

  def notify_after(ms, pid, message) do
    Process.sleep(ms)
    send(pid, message)
  end

  defp sandbox,
    do: %Sandbox{
      id: "gw-#{System.unique_integer([:positive])}",
      owner_ref: "o",
      template_ref: "t"
    }

  defp socket_path, do: "/tmp/exsg-#{System.unique_integer([:positive])}.sock"

  defp start_gateway(path, opts \\ []) do
    name = :"gateway_#{System.unique_integer([:positive])}"

    start_supervised!(
      {ExSandbox.Gateway,
       Keyword.merge([socket_path: path, mechanism: LocalMechanism, name: name], opts)},
      id: name
    )
  end

  defp connect(path) do
    {:ok, socket} = :gen_tcp.connect({:local, path}, 0, [:binary, packet: 4, active: false])
    socket
  end

  defp send_request(socket, id, verb, args),
    do: :ok = :gen_tcp.send(socket, Protocol.encode({:request, id, verb, args}))

  defp recv(socket) do
    {:ok, frame} = :gen_tcp.recv(socket, 0, 5_000)
    {:ok, term} = Protocol.decode(frame)
    term
  end

  defp hello(socket) do
    send_request(socket, 0, :hello, %{versions: Protocol.versions()})
    assert {:reply, 0, {:ok, %{version: 1}}} = recv(socket)
    socket
  end

  describe "the protocol" do
    test "hello negotiates the newest shared version, and nothing is served before it" do
      path = socket_path()
      start_gateway(path)
      socket = connect(path)

      send_request(socket, 1, :list, nil)
      assert recv(socket) == {:reply, 1, {:error, :hello_first}}

      send_request(socket, 2, :hello, %{versions: [99]})
      assert {:reply, 2, {:error, {:unsupported_versions, [1]}}} = recv(socket)

      hello(socket)
      send_request(socket, 3, :list, nil)
      assert recv(socket) == {:reply, 3, {:ok, ["local-a"]}}
    end

    test "replies match their requests whatever order they finish in" do
      path = socket_path()
      start_gateway(path)
      socket = hello(connect(path))
      sb = sandbox()

      for round <- 1..20 do
        requests =
          for n <- 1..Enum.random(2..12), into: %{} do
            id = round * 100 + n
            {id, {:rand.uniform(30), make_ref()}}
          end

        for {id, {delay, value}} <- Enum.shuffle(Map.to_list(requests)) do
          send_request(
            socket,
            id,
            :call,
            {:call, sb, __MODULE__, :after_ms, [delay, value], 5_000}
          )
        end

        replies =
          for _ <- requests, into: %{}, do: (fn {:reply, id, r} -> {id, r} end).(recv(socket))

        assert replies == Map.new(requests, fn {id, {_delay, value}} -> {id, {:ok, value}} end)
      end
    end

    test "a frame naming an atom this VM does not know is refused, and the connection stays" do
      path = socket_path()
      start_gateway(path)
      socket = hello(connect(path))

      name = "zz_unknown_#{System.unique_integer([:positive])}"
      placeholder = String.duplicate("q", byte_size(name))
      template = Protocol.encode({:request, 7, String.to_atom(placeholder), nil})
      frame = :binary.replace(template, placeholder, name)

      :ok = :gen_tcp.send(socket, frame)
      assert recv(socket) == {:reply, nil, {:error, :bad_frame}}
      assert_raise ArgumentError, fn -> String.to_existing_atom(name) end

      send_request(socket, 8, :list, nil)
      assert recv(socket) == {:reply, 8, {:ok, ["local-a"]}}
    end

    test "a peer whose uid is not allowed is disconnected" do
      path = socket_path()
      start_gateway(path, allowed_uids: [PeerCred.own_uid() + 1])
      socket = connect(path)

      send_request(socket, 1, :hello, %{versions: Protocol.versions()})
      assert {:error, :closed} = :gen_tcp.recv(socket, 0, 5_000)
    end

    test "a call whose client disconnects runs to completion" do
      path = socket_path()
      start_gateway(path)
      socket = hello(connect(path))

      send_request(
        socket,
        1,
        :call,
        {:call, sandbox(), __MODULE__, :notify_after, [200, self(), :done], 5_000}
      )

      :ok = :gen_tcp.close(socket)

      assert_receive :done, 2_000
    end

    test "an allowlist is on the gateway's disk when the change is acknowledged" do
      path = socket_path()
      store = Path.join(System.tmp_dir!(), "exsg-store-#{System.unique_integer([:positive])}")
      start_gateway(path, store_dir: store)
      socket = hello(connect(path))
      sb = sandbox()

      send_request(socket, 1, :allowlist, {sb, [{:public, 443}]})
      assert {:reply, 1, {:ok, _}} = recv(socket)
      assert ExSandbox.Gateway.AllowlistStore.get(store, sb.id) == {:ok, [{:public, 443}]}
    end
  end

  describe "the client" do
    test "a request made before any gateway listens waits for one and answers" do
      path = socket_path()

      start_supervised!({ExSandbox.Mechanism.Gateway, socket_path: path})

      task = Task.async(fn -> request(path, :list, nil) end)
      Process.sleep(300)
      start_gateway(path)

      assert Task.await(task, 10_000) == {:ok, ["local-a"]}
    end

    test "a context function in a reply runs on the gateway, not in the client" do
      path = socket_path()
      start_gateway(path)
      start_supervised!({ExSandbox.Mechanism.Gateway, socket_path: path})

      assert {:ok, provisioned} = ExSandbox.Mechanism.Gateway.provision(sandbox())
      assert {:tagged, runner} = provisioned.context.probe.(:tagged)
      assert runner != self()
      refute Process.alive?(runner)

      assert {:ok, started} = ExSandbox.Mechanism.Gateway.start(provisioned)
      assert {:again, other} = started.context.probe.(:again)
      assert other != self()
    end
  end

  defp request(_path, verb, args), do: ExSandbox.Mechanism.Gateway.request(verb, args)
end
