defmodule ExSandbox.Gateway.ContextFuns do
  @moduledoc """
  Keeps a sandbox's context functions (`:exec`, `:connect`, `:udp_probe`) on
  the gateway and sends the client a marker for each, which the client turns
  back into a function that runs over the socket (D3 of
  `let-sandboxes-outlive-a-deploy`).
  """

  alias ExSandbox.Gateway.Protocol
  alias ExSandbox.Sandbox

  @doc "Stores `result`'s context functions in `table` and replaces them with markers."
  @spec export(term(), :ets.tid()) :: term()
  def export({:ok, %Sandbox{} = sandbox}, table), do: {:ok, export_sandbox(sandbox, table)}
  def export(result, _table), do: result

  @doc "Runs a stored context function."
  @spec apply_stored(:ets.tid(), String.t(), atom(), [term()]) :: term()
  def apply_stored(table, id, key, args) do
    case :ets.lookup(table, {id, key}) do
      [{_key, fun}] when is_function(fun, length(args)) -> apply(fun, args)
      _ -> {:error, :unknown_context_function}
    end
  end

  @doc "Forgets a sandbox's stored functions."
  @spec forget(:ets.tid(), String.t()) :: true
  def forget(table, id), do: :ets.match_delete(table, {{id, :_}, :_})

  @doc "Replaces markers in `result` with functions that call `request` with `{:context, id, key, args}`."
  @spec import(term(), (term() -> term())) :: term()
  def import({:ok, %Sandbox{context: context} = sandbox}, request) when is_map(context) do
    imported =
      Map.new(context, fn
        {key, {:gateway_context_function, key, arity}} ->
          call = &Protocol.unwrap(request.({:context, sandbox.id, key, Protocol.opaque(&1)}))
          {key, client_fun(arity, call)}

        pair ->
          pair
      end)

    {:ok, %{sandbox | context: imported}}
  end

  def import(result, _request), do: result

  @doc "Replaces context functions in a sandbox the client sends with markers."
  @spec strip(term()) :: term()
  def strip(%Sandbox{context: context} = sandbox) when is_map(context) do
    stripped =
      Map.new(context, fn
        {key, fun} when is_function(fun) ->
          {:arity, arity} = Function.info(fun, :arity)
          {key, {:gateway_context_function, key, arity}}

        pair ->
          pair
      end)

    %{sandbox | context: stripped}
  end

  def strip(other), do: other

  @doc "Puts the stored functions back in place of the markers in a request's sandboxes."
  @spec restore(term(), :ets.tid()) :: term()
  def restore(args, table) when is_tuple(args) do
    args |> Tuple.to_list() |> Enum.map(&restore_sandbox(&1, table)) |> List.to_tuple()
  end

  def restore(args, _table), do: args

  defp restore_sandbox(%Sandbox{context: context, id: id} = sandbox, table)
       when is_map(context) do
    restored =
      Enum.flat_map(context, fn
        {key, {:gateway_context_function, key, _arity}} ->
          case :ets.lookup(table, {id, key}) do
            [{_key, fun}] -> [{key, fun}]
            [] -> []
          end

        pair ->
          [pair]
      end)

    %{sandbox | context: Map.new(restored)}
  end

  defp restore_sandbox(other, _table), do: other

  defp export_sandbox(%Sandbox{context: context, id: id} = sandbox, table)
       when is_map(context) and is_binary(id) do
    exported =
      Map.new(context, fn
        {key, fun} when is_function(fun) ->
          :ets.insert(table, {{id, key}, fun})
          {:arity, arity} = Function.info(fun, :arity)
          {key, {:gateway_context_function, key, arity}}

        pair ->
          pair
      end)

    %{sandbox | context: exported}
  end

  defp export_sandbox(sandbox, _table), do: sandbox

  defp client_fun(0, call), do: fn -> call.([]) end
  defp client_fun(1, call), do: fn a -> call.([a]) end
  defp client_fun(2, call), do: fn a, b -> call.([a, b]) end
  defp client_fun(3, call), do: fn a, b, c -> call.([a, b, c]) end
end
