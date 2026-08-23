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

  ## The host's aliases arrive as **data** (029 T009a, `FR-015`, D103)

  `FR-015` requires excluding *every alias for the host*, and on the pasta
  mechanism the mapped gateway address is a second name for the host that is
  **not** the string `127.0.0.1`. But this module transfers whole to a future
  container mechanism precisely **because it names no mechanism**, so no pasta
  concept may live in it. Both hold only if the alias set is **handed in**:
  `parse/2` receives `host_aliases` and stays a pure policy function.

  ⚠️ **Two shapes were considered and ruled out.** A *capability query* — this
  module asking a mechanism what the host's addresses are — is exactly the
  re-coupling the transfer argument forbids. A *configured constant* drifts from
  the address actually in use, and that drift **is** the defect: the value would
  be right in the config file and wrong in the namespace, with every parse-time
  test green.

  So this module still knows nothing about pasta, Docker, or gateways. It knows
  that its caller may hand it a list of things that are the host, and it refuses
  entries naming any of them with `:host_alias` — a class of its own, so the
  refusal says *why* rather than "invalid".

  `parse/1` is `parse/2` with an empty alias list and behaves exactly as before.

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

  @typedoc """
  A thing that *is* the host, as a caller may express it.

  An address (`"10.0.0.1"`, `{10, 0, 0, 1}`) or a name
  (`"host.docker.internal"`). Ports are not part of an alias: a destination is
  the host, or it is not, and naming a port would permit every other one.
  """
  @type host_alias :: String.t() | :inet.ip_address()

  @typedoc """
  Why an entry was refused on policy grounds rather than for being unreadable.

  ⚠️ A refusal that says only "invalid" is indistinguishable from a typo, and
  `FR-014` requires an operator be able to act on it without reading code.
  """
  @type refusal_class :: :host_alias

  @typedoc "Why parsing refused, naming every entry it would not accept."
  @type error ::
          {:invalid_entries, [term()]}
          | {:refused_entries, [{term(), refusal_class()}]}

  @doc """
  Parses a project's configured destinations into `Policy.destination()` values.

  Returns `{:error, {:invalid_entries, entries}}` if *any* entry is
  unreadable — see the moduledoc for why this is not a filter — and
  `{:error, {:refused_entries, [{entry, class}]}}` if an entry is readable but
  names something policy forbids.

  `host_aliases` is the set of things that **are the host** on whatever
  mechanism the caller runs, handed in as data. See the moduledoc for why it is
  not queried for.
  """
  @spec parse([entry()] | nil, [host_alias()]) ::
          {:ok, [Policy.destination()]} | {:error, error()}
  def parse(entries, host_aliases \\ [])

  def parse(nil, _host_aliases), do: {:ok, []}

  def parse(entries, host_aliases) when is_list(entries) do
    aliases = normalise_aliases(host_aliases)

    {parsed, invalid, refused} =
      Enum.reduce(entries, {[], [], []}, fn entry, {ok, bad, no} ->
        with {:ok, destination} <- parse_entry(entry),
             nil <- refusal_class(destination, aliases) do
          {[destination | ok], bad, no}
        else
          :error -> {ok, [entry | bad], no}
          class when is_atom(class) -> {ok, bad, [{entry, class} | no]}
        end
      end)

    # ⚠️ Unreadable entries are reported **before** refused ones, and the order
    # is not arbitrary: an entry that could not be read was never classified, so
    # a `:refused_entries` list built alongside a non-empty `:invalid_entries`
    # list would be a report about a subset the operator has not been told
    # about. They fix what could not be read, parse again, and then see every
    # refusal.
    cond do
      invalid != [] -> {:error, {:invalid_entries, Enum.reverse(invalid)}}
      refused != [] -> {:error, {:refused_entries, Enum.reverse(refused)}}
      true -> {:ok, Enum.reverse(parsed)}
    end
  end

  # ⚠️ Anything that is not a list is refused rather than wrapped. A bare
  # `"api.example.com:443"` passed where a list was expected is a configuration
  # mistake, and silently treating it as a one-element allowlist would grant
  # exactly the access the mistake describes.
  def parse(other, _host_aliases), do: {:error, {:invalid_entries, [other]}}

  # The port is deliberately unread. A destination either is the host or is not;
  # a class that depended on the port would refuse `127.0.0.1:5432` and permit
  # `127.0.0.1:5433`.
  defp refusal_class({host, _port}, aliases), do: host_class(host, aliases)

  # ⚠️ **The alias comparison happens AFTER normalisation, and that placement is
  # the whole of `029 T009a`.** Compared as written, an alias `"10.0.0.1"` would
  # miss an entry spelled `"10.0.0.01"`, `{10, 0, 0, 1}` or `"0xa000001"` --
  # all of which `:inet.parse_address/1` reads as the same address (measured:
  # `:inet.parse_address(~c"127.1") == {:ok, {127, 0, 0, 1}}`). Normalising
  # first means aliases inherit that permissive parsing for free rather than
  # needing a spelling table nobody can keep complete.
  #
  # ⚠️ **029 T008's built-in classes belong in this function too**, in the two
  # marked seams below -- `:loopback`, `:rfc1918_private`, `:link_local`,
  # `:cloud_metadata`, `:unique_local`, `:unspecified` on the address branch and
  # the `localhost` family on the name branch. They are **absent from this
  # tree** (T008 is unchecked in `029/tasks.md` here and no such code exists),
  # so the seams are empty rather than reimplemented -- rebuilding them would
  # produce a second, divergent copy and a merge that could silently keep the
  # wrong one.
  defp host_class(host, aliases) do
    case normalise_host(host) do
      {:address, address} ->
        # SEAM (029 T008): built-in address classes go here, before the alias
        # check or after it -- they cannot both match, since no built-in class
        # and no caller alias name the same thing without agreeing.
        if MapSet.member?(aliases.addresses, address), do: :host_alias

      {:name, name} ->
        # SEAM (029 T008): the `localhost`/`ip6-localhost` family goes here.
        if MapSet.member?(aliases.names, name), do: :host_alias
    end
  end

  defp normalise_aliases(host_aliases) when is_list(host_aliases) do
    Enum.reduce(host_aliases, %{addresses: MapSet.new(), names: MapSet.new()}, fn
      host, acc ->
        case normalise_host(host) do
          {:address, address} -> %{acc | addresses: MapSet.put(acc.addresses, address)}
          {:name, name} -> %{acc | names: MapSet.put(acc.names, name)}
        end
    end)
  end

  # ⚠️ A non-list alias set is a caller bug and is raised rather than coerced.
  # Treating it as "no aliases" would silently drop the FR-015 exclusion, which
  # is the one failure this whole task exists to prevent.
  defp normalise_aliases(other),
    do: raise(ArgumentError, "host_aliases must be a list, got: #{inspect(other)}")

  defp normalise_host(host) when is_tuple(host), do: {:address, canonicalise(host)}

  defp normalise_host(host) when is_binary(host) do
    # ⚠️ Brackets are stripped first, and this is not cosmetic. `parse/1`
    # **keeps** them: `parse(["[::1]:5432"])` yields `{"[::1]", 5432}`
    # (measured), and `:inet.parse_address(~c"[::1]")` is `{:error, :einval}`.
    # So any classifier that hands the host straight to `parse_address/1` reads
    # every bracketed IPv6 literal as a *hostname* and lets it through.
    case :inet.parse_address(host |> strip_brackets() |> String.to_charlist()) do
      {:ok, address} -> {:address, canonicalise(address)}
      {:error, _} -> {:name, String.downcase(host)}
    end
  end

  # Anything else cannot be a host; `parse_entry/1` has already refused it.
  defp normalise_host(other), do: {:name, inspect(other)}

  defp strip_brackets("[" <> rest) do
    case String.split(rest, "]") do
      [inner | _] -> inner
      _ -> rest
    end
  end

  defp strip_brackets(host), do: host

  # An IPv4-mapped IPv6 address is the IPv4 address wearing a second spelling.
  # Collapsing it means one alias covers both forms.
  defp canonicalise({0, 0, 0, 0, 0, 0xFFFF, a, b}),
    do: {Bitwise.bsr(a, 8), Bitwise.band(a, 0xFF), Bitwise.bsr(b, 8), Bitwise.band(b, 0xFF)}

  defp canonicalise(address), do: address

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
