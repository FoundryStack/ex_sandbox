defmodule ExSandbox.Gateway do
  @moduledoc """
  The per-host owner of a host's sandboxes: it runs a mechanism (by default
  `ExSandbox.Mechanism.Beam`) in its own VM and serves it over a unix socket,
  so sandboxes outlive the platform release that asked for them (D2, D3 of
  `let-sandboxes-outlive-a-deploy`, `sandbox/FR-294`).

  `ExSandbox.Mechanism.Gateway` is the client. The protocol is
  `ExSandbox.Gateway.Protocol`; a request runs in its own task, so a call
  whose client disconnects runs to completion and only its reply is dropped.

  Options: `:socket_path` (required), `:mechanism`, `:allowed_uids` (default:
  this VM's uid), `:store_dir` (the allowlist store), `:name`.
  """
  use Supervisor

  alias ExSandbox.Gateway.Server

  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts) do
    Supervisor.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl true
  def init(opts) do
    tasks = Module.concat(Keyword.get(opts, :name, __MODULE__), Tasks)

    children = [
      {Task.Supervisor, name: tasks},
      {Server, Keyword.put(opts, :tasks, tasks)}
    ]

    Supervisor.init(children, strategy: :rest_for_one)
  end

  @doc "The gateway's socket path on this host: `$XDG_RUNTIME_DIR/ex-sandbox/gateway.sock`."
  @spec default_socket_path() :: String.t() | nil
  def default_socket_path do
    case System.get_env("XDG_RUNTIME_DIR") do
      nil -> nil
      "" -> nil
      dir -> Path.join([dir, "ex-sandbox", "gateway.sock"])
    end
  end
end
