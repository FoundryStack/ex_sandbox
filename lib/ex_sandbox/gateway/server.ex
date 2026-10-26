defmodule ExSandbox.Gateway.Server do
  @moduledoc """
  Listens on the gateway socket, admits connections whose peer uid is
  allowed, and answers each request from a task of its own (D3 of
  `let-sandboxes-outlive-a-deploy`).
  """
  use GenServer

  require Logger

  alias ExSandbox.Gateway.AllowlistStore
  alias ExSandbox.Gateway.PeerCred
  alias ExSandbox.Gateway.Protocol

  @config_keys [:beam, :egress]

  @doc false
  def child_spec(opts), do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}}

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @impl true
  def init(opts) do
    path = Keyword.fetch!(opts, :socket_path)
    File.mkdir_p!(Path.dirname(path))
    _ = File.rm(path)

    {:ok, listen} =
      :gen_tcp.listen(0, [
        :binary,
        ifaddr: {:local, path},
        packet: 4,
        active: false,
        reuseaddr: false,
        backlog: 128
      ])

    File.chmod!(path, 0o660)

    state = %{
      listen: listen,
      path: path,
      tasks: Keyword.fetch!(opts, :tasks),
      mechanism: Keyword.get(opts, :mechanism, ExSandbox.Mechanism.Beam),
      allowed_uids: Keyword.get_lazy(opts, :allowed_uids, fn -> [PeerCred.own_uid()] end),
      store_dir: Keyword.get(opts, :store_dir)
    }

    server = self()
    spawn_link(fn -> accept_loop(server, state) end)
    {:ok, state}
  end

  @impl true
  def terminate(_reason, state) do
    _ = File.rm(state.path)
    :ok
  end

  defp accept_loop(server, state) do
    case :gen_tcp.accept(state.listen) do
      {:ok, socket} ->
        {:ok, pid} =
          Task.Supervisor.start_child(state.tasks, fn ->
            receive do
              :go -> admit(socket, state)
            end
          end)

        :ok = :gen_tcp.controlling_process(socket, pid)
        send(pid, :go)
        accept_loop(server, state)

      {:error, reason} ->
        exit({:accept_failed, reason})
    end
  end

  defp admit(socket, state) do
    case PeerCred.uid(socket) do
      {:ok, uid} ->
        if uid in state.allowed_uids do
          serve(socket, Map.put(state, :version, nil))
        else
          Logger.warning("ex_sandbox gateway: refused a connection from uid #{uid}")
          :gen_tcp.close(socket)
        end

      {:error, reason} ->
        Logger.warning("ex_sandbox gateway: refused a connection: #{inspect(reason)}")
        :gen_tcp.close(socket)
    end
  end

  defp serve(socket, conn) do
    :ok = :inet.setopts(socket, active: :once)

    receive do
      {:tcp, ^socket, frame} ->
        serve(socket, handle_frame(socket, frame, conn))

      {:reply, id, result} ->
        _ = :gen_tcp.send(socket, Protocol.encode({:reply, id, result}))
        serve(socket, conn)

      {:tcp_closed, ^socket} ->
        :ok

      {:tcp_error, ^socket, _reason} ->
        :ok
    end
  end

  defp handle_frame(socket, frame, conn) do
    case Protocol.decode(frame) do
      {:ok, {:request, id, :hello, args}} ->
        {result, conn} = hello(args, conn)
        reply(socket, id, result)
        conn

      {:ok, {:request, id, _verb, _args}} when is_nil(conn.version) ->
        reply(socket, id, {:error, :hello_first})
        conn

      {:ok, {:request, id, verb, args}} ->
        connection = self()

        {:ok, _pid} =
          Task.Supervisor.start_child(conn.tasks, fn ->
            send(connection, {:reply, id, run(verb, args, conn)})
          end)

        conn

      {:ok, _other} ->
        reply(socket, nil, {:error, :bad_request})
        conn

      {:error, :bad_frame} ->
        reply(socket, nil, {:error, :bad_frame})
        conn
    end
  end

  defp reply(socket, id, result), do: :gen_tcp.send(socket, Protocol.encode({:reply, id, result}))

  defp hello(%{versions: offered} = args, conn) do
    case Protocol.negotiate(offered) do
      {:ok, version} ->
        apply_config(Map.get(args, :config, []))

        {{:ok, %{version: version, verbs: Protocol.verbs(), vsn: vsn()}},
         %{conn | version: version}}

      :error ->
        {{:error, {:unsupported_versions, Protocol.versions()}}, conn}
    end
  end

  defp hello(_args, conn), do: {{:error, :bad_request}, conn}

  defp apply_config(config) when is_list(config) do
    for {key, value} <- config, key in @config_keys, Keyword.keyword?(value) do
      merged = Keyword.merge(Application.get_env(:ex_sandbox, key, []), value)
      Application.put_env(:ex_sandbox, key, merged)
    end

    :ok
  end

  defp apply_config(_config), do: :ok

  defp vsn, do: to_string(Application.spec(:ex_sandbox, :vsn))

  @doc false
  def run(verb, args, conn) do
    dispatch(verb, args, conn)
  rescue
    error -> {:error, {:gateway_raised, Exception.message(error)}}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp dispatch(:start, {:provision, sandbox}, conn),
    do: ExSandbox.provision(conn.mechanism, sandbox)

  defp dispatch(:start, {:start, sandbox}, conn),
    do: ExSandbox.start(conn.mechanism, stored_allowlist(sandbox, conn))

  defp dispatch(:stop, {:stop, sandbox}, conn), do: ExSandbox.stop(conn.mechanism, sandbox)

  defp dispatch(:stop, {:destroy, sandbox}, conn) do
    with :ok <- ExSandbox.destroy(conn.mechanism, sandbox) do
      if is_binary(sandbox.id), do: AllowlistStore.delete(conn.store_dir, sandbox.id)
      :ok
    end
  end

  defp dispatch(:status, {:status, sandbox}, conn), do: ExSandbox.status(conn.mechanism, sandbox)
  defp dispatch(:status, {:address, sandbox}, conn), do: conn.mechanism.address(sandbox)

  defp dispatch(:status, {:address, sandbox, port}, conn),
    do: conn.mechanism.address(sandbox, port)

  defp dispatch(:status, {:host_pid, sandbox}, conn), do: conn.mechanism.host_pid(sandbox)

  defp dispatch(:status, {:failure_reason, sandbox}, conn),
    do: conn.mechanism.provision_failure_reason(sandbox)

  defp dispatch(:list, _args, conn), do: ExSandbox.list_running(conn.mechanism)

  defp dispatch(:call, {:call, sandbox, m, f, a, timeout}, conn),
    do: conn.mechanism.call(sandbox, m, f, a, timeout)

  defp dispatch(:call, {:cast, sandbox, m, f, a}, conn), do: conn.mechanism.cast(sandbox, m, f, a)

  defp dispatch(:call, {:execute, sandbox, command, opts}, conn),
    do: ExSandbox.execute(conn.mechanism, sandbox, command, opts)

  defp dispatch(:allowlist, {sandbox, allowed}, conn) when is_list(allowed) do
    with :ok <- AllowlistStore.put(conn.store_dir, sandbox.id, allowed) do
      conn.mechanism.update_egress(sandbox, allowed)
    end
  end

  defp dispatch(:sample, {:usage, sandbox}, conn), do: ExSandbox.usage(conn.mechanism, sandbox)
  defp dispatch(verb, _args, _conn), do: {:error, {:unknown_verb, verb}}

  defp stored_allowlist(%{id: id} = sandbox, conn) when is_binary(id) do
    case AllowlistStore.get(conn.store_dir, id) do
      {:ok, allowed} ->
        %{sandbox | context: Map.put(sandbox.context || %{}, :network_allowlist, allowed)}

      :error ->
        sandbox
    end
  end

  defp stored_allowlist(sandbox, _conn), do: sandbox
end
