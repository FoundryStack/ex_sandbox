defmodule ExSandbox.Gateway.PeerCred do
  @moduledoc """
  The uid on the far end of a unix socket: `SO_PEERCRED` on Linux,
  `LOCAL_PEERCRED` on Darwin (D3 of `let-sandboxes-outlive-a-deploy`).
  """

  @doc "The connected peer's uid."
  @spec uid(:gen_tcp.socket()) :: {:ok, non_neg_integer()} | {:error, term()}
  def uid(socket) do
    case :os.type() do
      {:unix, :linux} ->
        read(socket, {1, 17, 12}, fn <<_pid::native-32, uid::native-32, _::binary>> -> uid end)

      {:unix, :darwin} ->
        read(socket, {0, 1, 76}, fn <<_v::native-32, uid::native-32, _::binary>> -> uid end)

      other ->
        {:error, {:unsupported_os, other}}
    end
  end

  defp read(socket, {level, option, size}, parse) do
    case :inet.getopts(socket, [{:raw, level, option, size}]) do
      {:ok, [{:raw, ^level, ^option, value}]} when byte_size(value) >= 8 -> {:ok, parse.(value)}
      {:ok, other} -> {:error, {:no_peer_credentials, other}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "The uid this VM runs as."
  @spec own_uid() :: non_neg_integer()
  def own_uid do
    {out, 0} = System.cmd("id", ["-u"])
    out |> String.trim() |> String.to_integer()
  end
end
