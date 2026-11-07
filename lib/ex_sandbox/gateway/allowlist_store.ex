defmodule ExSandbox.Gateway.AllowlistStore do
  @moduledoc """
  The last egress allowlist applied to each sandbox, on the gateway's disk,
  written before the gateway acks the change (D6 of
  `let-sandboxes-outlive-a-deploy`, `sandbox/FR-297`).
  """

  @doc "Records `allowed` for `id`, durably, before returning."
  @spec put(String.t() | nil, String.t(), list()) :: :ok | {:error, term()}
  def put(nil, _id, _allowed), do: :ok

  def put(dir, id, allowed) do
    path = path(dir, id)
    tmp = path <> ".tmp"

    with :ok <- File.mkdir_p(dir),
         :ok <- write_synced(tmp, :erlang.term_to_binary(allowed)) do
      File.rename(tmp, path)
    end
  end

  @doc "The recorded allowlist for `id`, or `:error`."
  @spec get(String.t() | nil, String.t()) :: {:ok, list()} | :error
  def get(nil, _id), do: :error

  def get(dir, id) do
    with {:ok, binary} <- File.read(path(dir, id)),
         {:ok, allowed} when is_list(allowed) <- ExSandbox.Gateway.Protocol.decode(binary) do
      {:ok, allowed}
    else
      _ -> :error
    end
  end

  @spec delete(String.t() | nil, String.t()) :: :ok
  def delete(nil, _id), do: :ok

  def delete(dir, id) do
    _ = File.rm(path(dir, id))
    :ok
  end

  defp write_synced(path, binary) do
    File.open(path, [:write, :binary, :raw], fn file ->
      :ok = :file.write(file, binary)
      :ok = :file.sync(file)
    end)
    |> case do
      {:ok, :ok} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp path(dir, id), do: Path.join(dir, Base.url_encode64(id, padding: false) <> ".allowlist")
end
