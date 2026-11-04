defmodule ExSandbox.Gateway.Wire do
  @moduledoc """
  A sandbox as it crosses the gateway socket from wire version 3 on
  (`hosting/FR-002`): a string-keyed map, one key per struct field, so a
  frame decoded with `[:safe]` names no atom the reader may lack. The reader
  ignores a key it does not know and gives a missing key the struct's
  default, so a field may be added without a new version when its default is
  what a peer without the field does.

  `context` is the one field that may hold any atom, so it travels as
  `ExSandbox.Gateway.Protocol.opaque/1`.
  """

  alias ExSandbox.Gateway.Protocol
  alias ExSandbox.Sandbox

  @version 3
  @required ["id", "owner_ref", "template_ref"]
  @fields Sandbox.__struct__() |> Map.from_struct() |> Map.keys()
  @by_name Map.new(@fields, &{Atom.to_string(&1), &1})

  # The struct as every version 2 peer knows it. Frozen: a field added from
  # here on travels only at version 3.
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

  @type wire :: %{required(String.t()) => term()}

  @doc "The wire form `from_wire/1` reads back."
  @spec to_wire(Sandbox.t()) :: wire()
  def to_wire(%Sandbox{} = sandbox) do
    sandbox
    |> Map.from_struct()
    |> Map.new(fn
      {:context, context} -> {"context", Protocol.opaque(context)}
      {key, value} -> {Atom.to_string(key), value}
    end)
    |> Map.put("v", @version)
  end

  @doc "The struct a wire map names, or the identity keys it lacks."
  @spec from_wire(wire()) :: {:ok, Sandbox.t()} | {:error, {:bad_sandbox, [String.t()]}}
  def from_wire(%{"v" => _} = wire) do
    case Enum.reject(@required, &Map.has_key?(wire, &1)) do
      [] ->
        fields =
          for {name, value} <- wire, key = @by_name[name], into: %{} do
            {key, if(key == :context, do: Protocol.unwrap(value), else: value)}
          end

        {:ok, struct(Sandbox, fields)}

      missing ->
        {:error, {:bad_sandbox, missing}}
    end
  end

  @doc """
  Every sandbox in a request's args or a reply's result as `version` carries
  it: the wire map at 3, at 2 the struct with the fields a version 2 peer
  knows.
  """
  @spec outbound(term(), pos_integer()) :: term()
  def outbound(term, 2), do: map_sandboxes(term, &Map.take(&1, [:__struct__ | @v2_fields]))
  def outbound(term, _version), do: map_sandboxes(term, &to_wire/1)

  @doc """
  Every sandbox in a request's args or a reply's result as this VM's struct,
  whichever form it arrived in. A version 2 peer's struct gets the fields it
  lacked at their defaults and loses the ones this VM lacks. Refuses on the
  first wire map without its identity.
  """
  @spec inbound(term()) :: {:ok, term()} | {:error, {:bad_sandbox, [String.t()]}}
  def inbound(term) do
    {:ok, map_sandboxes(term, &read!/1)}
  catch
    {:bad_sandbox, _keys} = refusal -> {:error, refusal}
  end

  defp read!(%{"v" => _} = wire) do
    case from_wire(wire) do
      {:ok, sandbox} -> sandbox
      {:error, refusal} -> throw(refusal)
    end
  end

  defp read!(%{__struct__: Sandbox} = sandbox), do: struct(Sandbox, Map.from_struct(sandbox))

  defp map_sandboxes(term, fun) when is_tuple(term) do
    term
    |> Tuple.to_list()
    |> Enum.map(fn
      %{__struct__: Sandbox} = sandbox -> fun.(sandbox)
      %{"v" => _} = wire -> fun.(wire)
      other -> other
    end)
    |> List.to_tuple()
  end

  defp map_sandboxes(other, _fun), do: other
end
