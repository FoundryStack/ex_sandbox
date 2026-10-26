defmodule ExSandbox.Gateway.Protocol do
  @moduledoc """
  The gateway's frames: external term format inside `{packet, 4}`, decoded
  with `[:safe]` on both sides (D3 of `let-sandboxes-outlive-a-deploy`).

  A request is `{:request, id, verb, args}` and its answer
  `{:reply, id, result}`. Replies may arrive in any order; the id pairs them.
  """

  @versions [1]
  @verbs [:hello, :start, :stop, :status, :list, :call, :allowlist, :sample]

  @type id :: non_neg_integer()
  @type verb :: :hello | :start | :stop | :status | :list | :call | :allowlist | :sample

  @doc "The protocol versions this side speaks, newest first."
  @spec versions() :: [pos_integer()]
  def versions, do: Enum.sort(@versions, :desc)

  @doc "The verbs a request may name."
  @spec verbs() :: [verb()]
  def verbs, do: @verbs

  @doc "The newest version both sides speak, or `:error`."
  @spec negotiate([term()]) :: {:ok, pos_integer()} | :error
  def negotiate(offered) when is_list(offered) do
    case Enum.filter(versions(), &(&1 in offered)) do
      [version | _] -> {:ok, version}
      [] -> :error
    end
  end

  def negotiate(_offered), do: :error

  @spec encode(term()) :: binary()
  def encode(term), do: :erlang.term_to_binary(term)

  @doc """
  A term the gateway forwards without reading -- a call's `{module,
  function, args}` and its result -- carried as its own binary, so a frame
  stays decodable when the term names atoms only the far side knows.
  """
  @spec opaque(term()) :: {:opaque, binary()}
  def opaque(term), do: {:opaque, encode(term)}

  @doc "The term inside `opaque/1`, its atoms created; anything else as it is."
  @spec unwrap(term()) :: term()
  def unwrap({:opaque, binary}) when is_binary(binary) do
    :erlang.binary_to_term(binary)
  rescue
    ArgumentError -> {:error, :bad_frame}
  end

  def unwrap(term), do: term

  @doc "Decodes one frame, refusing new atoms and external funs."
  @spec decode(binary()) :: {:ok, term()} | {:error, :bad_frame}
  def decode(binary) when is_binary(binary) do
    {:ok, :erlang.binary_to_term(binary, [:safe])}
  rescue
    ArgumentError -> {:error, :bad_frame}
  end
end
