defmodule ExSandbox.DescriptorHog do
  @moduledoc """
  Fills a VM's descriptor table, then gives it back on request. Runs in a peer
  started under a low `ulimit -n`, never in the VM running the tests.
  """

  @doc "Loads what a release loads at boot. A lazy code load fails once the table is full."
  def preload do
    for app <- [:kernel, :stdlib, :elixir, :logger, :ex_sandbox] do
      _ = Application.load(app)
      {:ok, modules} = :application.get_key(app, :modules)
      :code.ensure_modules_loaded(modules)
    end

    :ok
  end

  @doc "Spawns a process that fills the table, holds it, and frees it on `:release`."
  def start do
    spawn(fn ->
      sockets = fill([])

      receive do
        :release -> Enum.each(sockets, &:gen_udp.close/1)
      end
    end)
  end

  defp fill(sockets) do
    case :gen_udp.open(0) do
      {:ok, socket} -> fill([socket | sockets])
      {:error, :emfile} -> sockets
    end
  end
end
