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

  ## Refused address classes (`029-FR-015`)

  An entry may be perfectly readable and still name somewhere a sandbox must
  never be handed. The allowlist is the tenant's *outward* reach; an entry
  naming the host the sandbox runs on, or the operator's own private network,
  is a hole in the isolation boundary rather than a destination.

  These are refused at parse time, before a sandbox exists:

  | class | what it covers |
  |---|---|
  | `:loopback` | `127.0.0.0/8`, IPv6 `::1`, and the reserved name `localhost` |
  | `:rfc1918_private` | `10/8`, `172.16/12`, `192.168/16` |
  | `:link_local` | `169.254.0.0/16`, IPv6 `fe80::/10` |
  | `:cloud_metadata` | `169.254.169.254` exactly |
  | `:unique_local` | IPv6 `fc00::/7` |
  | `:unspecified` | `0.0.0.0/8` and IPv6 `::` |

  ⚠️ **`:cloud_metadata` is a subset of `:link_local` and is named separately
  anyway.** Refusing it as "link-local" is *correct* and *useless*: an operator
  who wrote `169.254.169.254:80` was reaching for the instance credentials
  endpoint, and telling them the address is link-local does not tell them the
  system knows what they were reaching for. `FR-014` asks that a refusal be
  actionable, and the class is the only part of the message that carries what
  to do about it.

  ⚠️ **The refusal names the class, and that is the point of the whole guard.**
  `{:invalid_entries, ["127.0.0.1:80"]}` is indistinguishable from a typo: an
  operator reads "invalid", re-checks their spelling, finds it correct, and
  files a bug against the parser. `{:refused_entries, [{"127.0.0.1:80",
  :loopback}]}` says the entry was *understood* and *declined*. Those are
  different conversations, so they are different error terms.

  ## Why the refusal is a separate error from the unreadable one

  ⚠️ Unreadable entries are reported **first and alone**, and this is forced
  rather than chosen: classification needs a host, and an entry that did not
  parse has no host to classify. `"10.0.0.5"` (missing its port) is visibly
  RFC1918 to a human and is nonetheless reported as unreadable, because the
  parser reaches `:error` before any address is in hand. An operator with both
  kinds of problem fixes syntax first and sees the policy refusals on the next
  attempt. That is two round trips, and it is the cost of not guessing at the
  meaning of an entry that failed to parse.

  ## What this guard is *not*

  ⚠️ This is the **static** address classes only. `127.0.0.1` is not the host's
  only name — a mapped gateway address handed to the namespace is a second one,
  and it is not a constant this module could know. Nothing here consults a
  running mechanism, reads configuration, or resolves a hostname. An entry
  naming a hostname that *resolves* to `10.0.0.5` parses clean here; catching
  that is a connect-time question, not a parse-time one.
  """

  alias ExSandbox.Egress.Policy

  @typedoc "An entry as a project's settings may express it."
  @type entry :: String.t() | Policy.destination()

  @typedoc """
  The class an entry was refused for (`029-FR-015`).

  ⚠️ Carried in the error so the refusal is *actionable*. See the moduledoc
  table: a refusal that says only "invalid" cannot be told from a typo.
  """
  @type class ::
          :loopback
          | :rfc1918_private
          | :link_local
          | :cloud_metadata
          | :unique_local
          | :unspecified

  @typedoc """
  Why parsing refused.

  `:invalid_entries` names every entry that could not be **read**.
  `:refused_entries` names every entry that read cleanly and named an address
  class a sandbox may not be pointed at, each paired with the class it was
  refused for.
  """
  @type error :: {:invalid_entries, [term()]} | {:refused_entries, [{term(), class()}]}

  @doc """
  Parses a project's configured destinations into `Policy.destination()` values.

  Returns `{:error, {:invalid_entries, entries}}` if *any* entry is
  unreadable — see the moduledoc for why this is not a filter.

  Returns `{:error, {:refused_entries, [{entry, class}]}}` if every entry read
  cleanly but one or more names a refused address class (`029-FR-015`).
  """
  @spec parse([entry()] | nil) :: {:ok, [Policy.destination()]} | {:error, error()}
  def parse(nil), do: {:ok, []}

  def parse(entries) when is_list(entries) do
    {parsed, invalid, refused} =
      Enum.reduce(entries, {[], [], []}, fn entry, {ok, bad, no} ->
        case parse_entry(entry) do
          {:ok, destination} ->
            case refusal_class(destination) do
              nil -> {[destination | ok], bad, no}
              class -> {ok, bad, [{entry, class} | no]}
            end

          :error ->
            {ok, [entry | bad], no}
        end
      end)

    cond do
      # ⚠️ Unreadable before refused, and not by preference -- an entry that
      # did not parse has no address to classify. See the moduledoc.
      invalid != [] -> {:error, {:invalid_entries, Enum.reverse(invalid)}}
      refused != [] -> {:error, {:refused_entries, Enum.reverse(refused)}}
      true -> {:ok, Enum.reverse(parsed)}
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

  # --- 029-FR-015: refused address classes -----------------------------------

  # ⚠️ RFC 6761 reserves these names for loopback, so they are addresses
  # wearing a name rather than hostnames that happen to resolve inward.
  # Without them the entire guard is bypassed by writing `localhost:8080`,
  # which is the first thing anyone tries.
  @loopback_names ~w(localhost localhost.localdomain ip6-localhost ip6-loopback)

  @spec refusal_class(Policy.destination()) :: class() | nil
  defp refusal_class({host, _port}), do: host_class(host)

  defp host_class(host) when is_tuple(host), do: address_class(host)

  defp host_class(host) when is_binary(host) do
    # ⚠️ `:inet.parse_address/1` rejects the bracketed form that `parse_entry/1`
    # preserves for `Policy`, so `"[::1]"` would sail past unclassified.
    bare = host |> String.trim_leading("[") |> String.trim_trailing("]")

    case :inet.parse_address(String.to_charlist(bare)) do
      # ⚠️ Deliberately relies on `:inet.parse_address/1` being *permissive*.
      # Measured on OTP: `"127.1"`, `"2130706433"` and `"0x7f000001"` all parse
      # to `{127, 0, 0, 1}`. A dotted-quad-only regexp would have let all three
      # through as "hostnames", and glibc resolves every one of them to
      # loopback.
      {:ok, address} -> address_class(address)
      {:error, _} -> name_class(bare)
    end
  end

  defp name_class(host) do
    if String.downcase(host) in @loopback_names, do: :loopback, else: nil
  end

  # --- IPv4 ---

  @spec address_class(:inet.ip_address()) :: class() | nil
  defp address_class({127, _, _, _}), do: :loopback

  # ⚠️ `0.0.0.0` is not "nowhere". Linux `connect(2)` to it reaches
  # `127.0.0.1`, so it is a loopback spelling that does not contain `127`.
  defp address_class({0, _, _, _}), do: :unspecified

  defp address_class({10, _, _, _}), do: :rfc1918_private
  defp address_class({172, b, _, _}) when b >= 16 and b <= 31, do: :rfc1918_private
  defp address_class({192, 168, _, _}), do: :rfc1918_private

  # ⚠️ Before the general link-local clause, and the ordering is the message.
  # See the moduledoc: "link-local" is a true and useless thing to tell an
  # operator who typed the instance-credentials endpoint.
  defp address_class({169, 254, 169, 254}), do: :cloud_metadata
  defp address_class({169, 254, _, _}), do: :link_local

  defp address_class({a, b, c, d})
       when is_integer(a) and is_integer(b) and is_integer(c) and is_integer(d),
       do: nil

  # --- IPv6 ---

  defp address_class({0, 0, 0, 0, 0, 0, 0, 1}), do: :loopback
  defp address_class({0, 0, 0, 0, 0, 0, 0, 0}), do: :unspecified

  # ⚠️ IPv4-mapped (`::ffff:a.b.c.d`). `"::ffff:127.0.0.1"` parses to
  # `{0, 0, 0, 0, 0, 65535, 32512, 1}` -- no `127` anywhere in the tuple, and
  # every IPv4 clause above misses it. Re-ask the question of the embedded
  # address rather than adding an IPv6 spelling of each rule.
  defp address_class({0, 0, 0, 0, 0, 0xFFFF, ab, cd}) do
    address_class({
      Bitwise.bsr(ab, 8),
      Bitwise.band(ab, 0xFF),
      Bitwise.bsr(cd, 8),
      Bitwise.band(cd, 0xFF)
    })
  end

  # `fe80::/10` -- the top ten bits are `1111111010`.
  defp address_class({a, _, _, _, _, _, _, _}) when Bitwise.band(a, 0xFFC0) == 0xFE80,
    do: :link_local

  # `fc00::/7` -- the top seven bits are `1111110`, covering `fc00::`-`fdff::`.
  defp address_class({a, _, _, _, _, _, _, _}) when Bitwise.band(a, 0xFE00) == 0xFC00,
    do: :unique_local

  defp address_class(_address), do: nil
end
