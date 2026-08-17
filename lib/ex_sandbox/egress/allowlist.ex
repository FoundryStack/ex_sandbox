defmodule ExSandbox.Egress.Allowlist do
  @moduledoc """
  Turns a tenant project's configured destinations into the form
  `ExSandbox.Egress.Policy` enforces (005 T060a2, `013-FR-014b`).

  ## Why this is a separate module from `Policy`

  `Policy` answers "is this destination permitted?" against a list already known
  to be well-formed. This module answers the earlier and more dangerous
  question: **what does an operator's configuration actually mean?** Those fail
  in opposite directions, and keeping them together would hide it.

  A wrong answer in `Policy` refuses something it should permit — visible
  immediately, because the permitted-destination check goes red. A wrong answer
  *here* can invent permission that the operator never granted, and nothing
  downstream can tell: `Policy` enforces whatever list it is handed, faithfully.

  ## Malformed input is refused, never dropped

  ⚠️ **The tempting implementation is `Enum.filter/2` + `Enum.map/2`, and it is
  the one that produces a silent breach.** Filtering skips entries that do not
  parse, so a project configured with

      ["api.example.com:443", "10.0.0.5"]

  — where the second entry is missing its port — yields a *shorter* allowlist
  that still looks correct and enforces the entries that did parse. The
  operator sees egress working, and never learns that one rule was discarded.
  The mirror case is worse: a config whose entries **all** fail to parse
  filters down to `[]`, which `Policy` treats as default-deny. That one at
  least fails closed, but it presents as "the allowlist is being enforced"
  rather than "your configuration was not understood".

  So `parse/1` returns `{:error, {:invalid_entries, [...]}}` naming every entry
  it could not read, and provisioning refuses. A sandbox is not provisioned
  with a *partial* interpretation of its network policy.

  ## An empty allowlist is legitimate, and distinct from an unreadable one

  `parse([])` is `{:ok, []}` — a project permitted to reach nothing, which is a
  coherent and useful configuration (`FR-011a`'s default-deny with nothing
  added). It must not be conflated with a configuration that failed to parse,
  which is why the error case is a tuple rather than an empty list.

  ## Accepted forms

  | form | meaning |
  |---|---|
  | `"host:443"` | that host on that port only |
  | `"host:*"` | that host on every port |
  | `{"host", 443}` | already-parsed, passes through |
  | `{"host", :any_port}` | already-parsed, passes through |

  ⚠️ There is deliberately **no bare `"host"` form**. It reads as "this host",
  but it has to resolve to either one port or all of them, and the safe reading
  (`:any_port`) is the permissive one. An operator who means every port must
  write `*` and see themselves write it.
  """

  alias ExSandbox.Egress.Policy

  @typedoc "An entry as a project's settings may express it."
  @type entry :: String.t() | Policy.destination()

  @typedoc "Why parsing refused, naming every entry that could not be read."
  @type error :: {:invalid_entries, [term()]}

  @doc """
  Parses a project's configured destinations into `Policy.destination()` values.

  Returns `{:error, {:invalid_entries, entries}}` if *any* entry is
  unreadable — see the moduledoc for why this is not a filter.
  """
  @spec parse([entry()] | nil) :: {:ok, [Policy.destination()]} | {:error, error()}
  def parse(nil), do: {:ok, []}

  def parse(entries) when is_list(entries) do
    {parsed, invalid} =
      Enum.reduce(entries, {[], []}, fn entry, {ok, bad} ->
        case parse_entry(entry) do
          {:ok, destination} -> {[destination | ok], bad}
          :error -> {ok, [entry | bad]}
        end
      end)

    case invalid do
      [] -> {:ok, Enum.reverse(parsed)}
      _ -> {:error, {:invalid_entries, Enum.reverse(invalid)}}
    end
  end

  # ⚠️ Anything that is not a list is refused rather than wrapped. A bare
  # `"api.example.com:443"` passed where a list was expected is a configuration
  # mistake, and silently treating it as a one-element allowlist would grant
  # exactly the access the mistake describes.
  def parse(other), do: {:error, {:invalid_entries, [other]}}

  defp parse_entry({host, :any_port} = destination) when is_binary(host) or is_tuple(host),
    do: {:ok, destination}

  defp parse_entry({host, port} = destination)
       when (is_binary(host) or is_tuple(host)) and is_integer(port) and port > 0 and
              port <= 65_535,
       do: {:ok, destination}

  defp parse_entry(entry) when is_binary(entry) do
    # ⚠️ Split from the *right*. An IPv6 literal contains colons, and splitting
    # from the left would cut one in half and produce a host that parses as
    # nothing while looking plausible in a log line.
    case String.split(entry, ":") |> Enum.reverse() do
      [port_part | host_parts] when host_parts != [] ->
        host = host_parts |> Enum.reverse() |> Enum.join(":")
        with {:ok, port} <- parse_port(port_part), do: build(host, port)

      _ ->
        :error
    end
  end

  defp parse_entry(_other), do: :error

  defp parse_port("*"), do: {:ok, :any_port}

  defp parse_port(part) do
    case Integer.parse(part) do
      # ⚠️ `rest == ""` matters: `Integer.parse("443x")` returns `{443, "x"}`,
      # so without this a typo'd entry would silently become port 443.
      {port, ""} when port > 0 and port <= 65_535 -> {:ok, port}
      _ -> :error
    end
  end

  defp build("", _port), do: :error
  defp build(host, port), do: {:ok, {host, port}}
end
