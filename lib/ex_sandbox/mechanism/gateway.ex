defmodule ExSandbox.Mechanism.Gateway do
  @moduledoc """
  The `ExSandbox.Mechanism` that asks an `ExSandbox.Gateway` over its socket
  (D4 of `let-sandboxes-outlive-a-deploy`, `sandbox/FR-294`).

  One client process holds the connection, reconnects when it drops, and
  sends `hello` before anything else. A request made while no gateway is
  connected waits up to `:connect_wait_ms` (default 30 s) for one, then
  answers `{:error, :host_unreachable}`.

  The consumer starts the client in its own tree (`{ExSandbox.Mechanism.Gateway,
  socket_path: path}`), after whatever `:on_hello` needs. `:on_hello` is `{module, function, args}`, run in a
  task after each successful `hello` with the gateway's answer prepended to
  `args`. `:config_keys` lists the `:ex_sandbox` keys sent with `hello`
  (default `[:beam, :egress]`), so the gateway runs sandboxes as this
  consumer configured them.
  """
  @behaviour ExSandbox.Mechanism

  use GenServer

  require Logger

  alias ExSandbox.Gateway.ContextFuns
  alias ExSandbox.Gateway.Protocol
  alias ExSandbox.Sandbox

  @connect_wait_ms 30_000
  @reconnect_ms 500
  @op_timeout_ms 180_000

  # ---- the mechanism ----

  @impl ExSandbox.Mechanism
  def required_capabilities, do: []

  @impl ExSandbox.Mechanism
  def constructed_capabilities, do: []

  @impl ExSandbox.Mechanism
  def provision(%Sandbox{} = sandbox), do: request(:start, {:provision, sandbox})

  @impl ExSandbox.Mechanism
  def start(%Sandbox{} = sandbox), do: request(:start, {:start, sandbox})

  @impl ExSandbox.Mechanism
  def stop(%Sandbox{} = sandbox), do: request(:stop, {:stop, sandbox})

  @impl ExSandbox.Mechanism
  def destroy(%Sandbox{} = sandbox), do: request(:stop, {:destroy, sandbox})

  @impl ExSandbox.Mechanism
  def status(%Sandbox{} = sandbox), do: request(:status, {:status, sandbox})

  @impl ExSandbox.Mechanism
  def list_running, do: request(:list, nil)

  @impl ExSandbox.Mechanism
  def usage(%Sandbox{} = sandbox), do: request(:sample, {:usage, sandbox})

  @impl ExSandbox.Mechanism
  def execute(%Sandbox{} = sandbox, command, opts \\ []) do
    timeout = Keyword.get(opts, :timeout_ms, @op_timeout_ms) + 5_000
    request(:call, {:execute, sandbox, command, opts}, timeout)
  end

  @impl ExSandbox.Mechanism
  def address(%Sandbox{} = sandbox), do: request(:status, {:address, sandbox})

  @impl ExSandbox.Mechanism
  def address(%Sandbox{} = sandbox, port), do: request(:status, {:address, sandbox, port})

  @impl ExSandbox.Mechanism
  def update_egress(%Sandbox{} = sandbox, allowed) when is_list(allowed),
    do: request(:allowlist, {sandbox, allowed})

  @doc "Evaluates `{module, function, args}` in the sandbox, as `ExSandbox.Mechanism.Beam.call/5`."
  @spec call(Sandbox.t(), module(), atom(), [term()], timeout()) ::
          {:ok, term()} | {:error, term()}
  def call(%Sandbox{} = sandbox, module, function, args, timeout \\ 10_000),
    do:
      Protocol.unwrap(
        request(
          :call,
          {:call, sandbox, Protocol.opaque({module, function, args}), timeout},
          timeout + 5_000
        )
      )

  @doc "As `ExSandbox.Mechanism.Beam.cast/4`."
  @spec cast(Sandbox.t(), module(), atom(), [term()]) :: :ok | {:error, term()}
  def cast(%Sandbox{} = sandbox, module, function, args),
    do:
      Protocol.unwrap(request(:call, {:cast, sandbox, Protocol.opaque({module, function, args})}))

  @doc "As `ExSandbox.Mechanism.Beam.host_pid/1`."
  @spec host_pid(Sandbox.t()) :: {:ok, pos_integer()} | {:error, term()}
  def host_pid(%Sandbox{} = sandbox), do: request(:status, {:host_pid, sandbox})

  @doc "As `ExSandbox.Mechanism.Beam.provision_failure_reason/1`."
  @spec provision_failure_reason(Sandbox.t()) :: {:error, atom()} | :ok
  def provision_failure_reason(%Sandbox{} = sandbox),
    do: request(:status, {:failure_reason, sandbox})

  @doc "Whether a gateway socket exists at `path` (default: the configured one)."
  @spec available?(String.t() | nil) :: boolean()
  def available?(path \\ nil) do
    path = path || Keyword.get(config(), :socket_path)
    is_binary(path) and match?({:ok, %{type: :other}}, File.lstat(path))
  end

  # ---- the client ----

  @doc false
  def child_spec(opts), do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}}

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  @doc "Sends one request and waits for its reply."
  @spec request(Protocol.verb(), term(), timeout()) :: term()
  def request(verb, args, timeout \\ @op_timeout_ms) do
    case GenServer.whereis(__MODULE__) do
      nil ->
        {:error, :host_unreachable}

      client ->
        wait = Keyword.get(config(), :connect_wait_ms, @connect_wait_ms)

        try do
          client
          |> GenServer.call({:request, verb, outbound(args), wait}, wait + timeout)
          |> ContextFuns.import(&request(:call, &1))
        catch
          :exit, {:timeout, _} -> {:error, :timeout}
          :exit, _ -> {:error, :host_unreachable}
        end
    end
  end

  defp outbound(args) when is_tuple(args) do
    args |> Tuple.to_list() |> Enum.map(&ContextFuns.strip/1) |> List.to_tuple()
  end

  defp outbound(args), do: args

  defp config, do: Application.get_env(:ex_sandbox, :gateway_client, [])

  @impl GenServer
  def init(opts) do
    state = %{
      path: Keyword.fetch!(opts, :socket_path),
      on_hello: Keyword.get(opts, :on_hello),
      config_keys: Keyword.get(opts, :config_keys, [:beam, :egress]),
      socket: nil,
      ready?: false,
      next_id: 1,
      pending: %{},
      waiting: []
    }

    {:ok, state, {:continue, :connect}}
  end

  @impl GenServer
  def handle_continue(:connect, state), do: {:noreply, connect(state)}

  @impl GenServer
  def handle_call({:request, verb, args, _wait}, from, %{ready?: true} = state) do
    {:noreply, send_request(state, verb, args, from)}
  end

  def handle_call({:request, verb, args, wait}, from, state) do
    timer = Process.send_after(self(), {:give_up, from}, wait)
    {:noreply, %{state | waiting: state.waiting ++ [{from, verb, args, timer}]}}
  end

  @impl GenServer
  def handle_info(:connect, state), do: {:noreply, connect(state)}

  def handle_info({:give_up, from}, state) do
    {gone, kept} = Enum.split_with(state.waiting, fn {f, _, _, _} -> f == from end)
    for {f, _, _, _} <- gone, do: GenServer.reply(f, {:error, :host_unreachable})
    {:noreply, %{state | waiting: kept}}
  end

  def handle_info({:tcp, socket, frame}, %{socket: socket} = state) do
    :ok = :inet.setopts(socket, active: :once)

    case Protocol.decode(frame) do
      {:ok, {:reply, id, result}} -> {:noreply, answer(state, id, result)}
      _other -> {:noreply, state}
    end
  end

  def handle_info({:tcp_closed, socket}, %{socket: socket} = state) do
    {:noreply, disconnected(state)}
  end

  def handle_info({:tcp_error, socket, _reason}, %{socket: socket} = state),
    do: {:noreply, disconnected(state)}

  def handle_info(_message, state), do: {:noreply, state}

  defp connect(%{socket: nil} = state) do
    case :gen_tcp.connect({:local, state.path}, 0, [:binary, packet: 4, active: :once], 5_000) do
      {:ok, socket} ->
        hello = %{
          versions: Protocol.versions(),
          config:
            for key <- state.config_keys do
              entries = Application.get_env(:ex_sandbox, key, [])
              {key, Enum.map(entries, &Protocol.encode/1)}
            end
        }

        id = state.next_id
        :ok = :gen_tcp.send(socket, Protocol.encode({:request, id, :hello, hello}))
        %{state | socket: socket, next_id: id + 1, pending: Map.put(state.pending, id, :hello)}

      {:error, _reason} ->
        Process.send_after(self(), :connect, @reconnect_ms)
        state
    end
  end

  defp connect(state), do: state

  defp disconnected(state) do
    for {_id, from} <- state.pending,
        from != :hello,
        do: GenServer.reply(from, {:error, :host_unreachable})

    Process.send_after(self(), :connect, @reconnect_ms)
    %{state | socket: nil, ready?: false, pending: %{}}
  end

  defp answer(state, id, result) do
    case Map.pop(state.pending, id) do
      {:hello, pending} ->
        hello_answered(%{state | pending: pending}, result)

      {nil, _pending} ->
        state

      {from, pending} ->
        GenServer.reply(from, result)
        %{state | pending: pending}
    end
  end

  defp hello_answered(state, {:ok, info}) do
    run_on_hello(state.on_hello, info)
    state = %{state | ready?: true}

    Enum.reduce(state.waiting, %{state | waiting: []}, fn {from, verb, args, timer}, acc ->
      Process.cancel_timer(timer)
      send_request(acc, verb, args, from)
    end)
  end

  defp hello_answered(state, refused) do
    Logger.error("ex_sandbox gateway refused hello: #{inspect(refused)}")
    :gen_tcp.close(state.socket)
    disconnected(state)
  end

  defp run_on_hello({module, function, args}, info) do
    Task.start(fn -> apply(module, function, [info | args]) end)
  end

  defp run_on_hello(_none, _info), do: :ok

  defp send_request(state, verb, args, from) do
    id = state.next_id

    case :gen_tcp.send(state.socket, Protocol.encode({:request, id, verb, args})) do
      :ok ->
        %{state | next_id: id + 1, pending: Map.put(state.pending, id, from)}

      {:error, _reason} ->
        GenServer.reply(from, {:error, :host_unreachable})
        %{state | next_id: id + 1}
    end
  end
end
