defmodule ExSandbox.Egress.Refusal do
  @moduledoc """
  The address classes a sandbox may never be pointed at (`029-FR-015`), as one
  definition shared by every place that asks.

  Three places ask. `ExSandbox.Egress.Allowlist.parse/2` refuses a written
  entry that names one of these classes. `ExSandbox.Egress.Resolver` drops a DNS
  answer that points into one. And `ExSandbox.Egress.Policy` decides a
  `:public` entry per connection: it permits any dialled address outside every
  class here, on any port.

  ⚠️ **One module because the three must agree on the same address.** A second
  classifier drifts, and the drift shows up as one surface refusing what
  another permits: an entry refused at parse time that `:public` then reaches
  at connect time, with no test able to see both. The table of classes is in
  `ExSandbox.Egress.Allowlist`'s moduledoc, which is the public statement of it.

  ⚠️ **`refused?/2` takes an address, never a name.** A name can resolve
  anywhere, and the tenant chooses both the name and, for a zone it controls,
  the answer. The address the connection was actually dialled to is the only
  thing the decision may classify.
  """

  @typedoc "Why a host is refused. See `ExSandbox.Egress.Allowlist`'s table."
  @type class ::
          :loopback
          | :rfc1918_private
          | :link_local
          | :cloud_metadata
          | :unique_local
          | :unspecified
          | :host_alias

  @typedoc "A thing that *is* the host: an address or a name. See `ExSandbox.Egress.Allowlist`."
  @type host_alias :: String.t() | :inet.ip_address()

  @typedoc "Host aliases after `normalise_aliases/1`."
  @type aliases :: %{addresses: MapSet.t(:inet.ip_address()), names: MapSet.t(String.t())}

  @doc """
  True when `address` falls in any refused class, `host_aliases` included.

  `host_aliases` is a list as `ExSandbox.Egress.HostAliases.detect/0` returns
  it. Names in it cannot match an address and are ignored here.
  """
  @spec refused?(:inet.ip_address(), [host_alias()]) :: boolean()
  def refused?(address, host_aliases \\ []) when is_tuple(address),
    do: class(address, normalise_aliases(host_aliases)) != nil

  @doc """
  The addresses among `host_aliases`, canonicalised, for a caller that will ask
  `refused?/2` per connection and should not normalise the set each time.
  """
  @spec alias_addresses([host_alias()]) :: [:inet.ip_address()]
  def alias_addresses(host_aliases),
    do: host_aliases |> normalise_aliases() |> Map.fetch!(:addresses) |> MapSet.to_list()

  # ⚠️ **The alias comparison happens AFTER normalisation, and that placement is
  # the whole of `029 T009a`.** Compared as written, an alias `"10.0.0.1"` would
  # miss an entry spelled `"10.0.0.01"`, `{10, 0, 0, 1}` or `"0xa000001"` --
  # all of which `:inet.parse_address/1` reads as the same address (measured:
  # `:inet.parse_address(~c"127.1") == {:ok, {127, 0, 0, 1}}`). Normalising
  # first means aliases inherit that permissive parsing for free rather than
  # needing a spelling table nobody can keep complete.
  #
  # ⚠️ **029 T008's built-in classes are folded in below** -- `:loopback`,
  # `:rfc1918_private`, `:link_local`, `:cloud_metadata`, `:unique_local`,
  # `:unspecified` on the address branch and the `localhost` family on the name
  # branch. (An earlier revision of this comment said they were absent from the
  # tree; they were merged in the same fold and the note outlived its subject.)
  @doc """
  The class `host` is refused for, or `nil` if it names nowhere excluded.

  `host` is an address tuple or a string; `aliases` is what
  `normalise_aliases/1` returned.
  """
  @spec class(term(), aliases()) :: class() | nil
  def class(host, aliases) do
    case normalise_host(host) do
      {:address, address} ->
        # ⚠️ **`:host_alias` wins over a built-in class when both match, and the
        # first fold of these two functions had it the other way round.** The
        # agent's own tests caught it: a host alias is very often *also*
        # RFC1918 -- pasta's gateway and Docker Desktop's host address both are
        # -- so built-in-first makes `:host_alias` a class that almost never
        # fires. A refusal reason that cannot be reached is the same defect as
        # a check that cannot fail, in the error vocabulary instead of the
        # suite.
        #
        # It is also the more useful of the two true statements. "This is a
        # private address" and "this is the machine you are running on" are
        # both correct about `10.0.0.1`; only the second tells the operator
        # what `FR-015` is actually for. An operator who then tries a different
        # private address gets `:rfc1918_private` and learns the general rule
        # too.
        alias_class(aliases.addresses, address) || address_class(address)

      {:name, name} ->
        alias_class(aliases.names, name) || name_class(name)
    end
  end

  defp alias_class(set, value), do: if(MapSet.member?(set, value), do: :host_alias)

  @doc """
  Splits a caller's host aliases into canonical addresses and names, so each
  comparison in `class/2` is made after the same normalisation as the host.
  """
  @spec normalise_aliases([host_alias()]) :: aliases()
  def normalise_aliases(host_aliases) when is_list(host_aliases) do
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
  def normalise_aliases(other),
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

  # --- 029-FR-015: refused address classes -----------------------------------

  # ⚠️ RFC 6761 reserves these names for loopback, so they are addresses
  # wearing a name rather than hostnames that happen to resolve inward.
  # Without them the entire guard is bypassed by writing `localhost:8080`,
  # which is the first thing anyone tries.
  @loopback_names ~w(localhost localhost.localdomain ip6-localhost ip6-loopback)

  # ⚠️ The bracket-stripping and the reliance on `:inet.parse_address/1` being
  # *permissive* both moved into `normalise_host/1` above, where the alias set
  # goes through the same normalisation. That is the point of T009a: compared
  # as written, an alias `"10.0.0.1"` would miss an entry spelled `"10.0.0.01"`
  # or `"0xa000001"`, which `parse_address/1` reads as the same address.
  # Measured on OTP: `"127.1"`, `"2130706433"` and `"0x7f000001"` all parse to
  # `{127, 0, 0, 1}`, and glibc resolves every one of them to loopback. A
  # dotted-quad-only regexp would have let all three through as "hostnames".
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
