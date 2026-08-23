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
  table: a refusal that says only "invalid" cannot be told from a typo, and
  `FR-014` requires an operator be able to act on it without reading code.

  `:host_alias` is the odd one out and deliberately so. Every other class is a
  property of the address itself, knowable from the string. Whether an address
  *is the host* depends on the mechanism the caller runs, so it arrives as
  data (see `parse/2`) rather than being recognised here.
  """
  @type class ::
          :loopback
          | :rfc1918_private
          | :link_local
          | :cloud_metadata
          | :unique_local
          | :unspecified
          | :host_alias

  @typedoc """
  A thing that *is* the host, as a caller may express it.

  An address (`"10.0.0.1"`, `{10, 0, 0, 1}`) or a name
  (`"host.docker.internal"`). Ports are not part of an alias: a destination is
  the host, or it is not, and naming a port would permit every other one.
  """
  @type host_alias :: String.t() | :inet.ip_address()

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

  @doc """
  The class `host` would be refused for, or `nil` if it names nowhere excluded.

  ⚠️ **Public because `029-FR-015`'s exclusion applies to resolved answers as
  well as to written entries**, and the two must name the **same class for the
  same address**. `ExSandbox.Egress.Resolver` runs every answer it is about to
  record through this function, so a name whose zone points at `127.0.0.1`
  produces `:loopback` at connect time exactly as writing `127.0.0.1` produces
  `:loopback` at parse time. A second classifier would drift, and the drift
  would show up as one surface refusing what the other permits, with no test
  able to see both.

  `host` may be an address tuple or a string; `host_aliases` has the same
  meaning as in `parse/2`.
  """
  @spec classify(term(), [host_alias()]) :: class() | nil
  def classify(host, host_aliases \\ []),
    do: host_class(host, normalise_aliases(host_aliases))

  @doc """
  Why an entry of `class` was refused, as a clause a person can act on.

  ⚠️ **This is the half of `029-FR-015` that had no reader, and the class
  existed for it.** `parse/2` has named a class since `029` T008 and every
  caller propagated the tuple opaquely, so what reached an operator was
  "provisioning failed" — the exact sentence the class was added to replace.
  A class nobody renders is the same defect as a check that cannot fail.

  The sentence lives **here**, beside the classifier, rather than at whichever
  surface happens to show it. Two surfaces writing their own would be two
  vocabularies for one set of atoms, and the one nobody reads is the one that
  stops matching `address_class/1`.

  ⚠️ The atom is **not** in the sentence — `describe/1` puts it there. This is
  the prose half only, so a caller rendering somewhere the atom would be noise
  can leave it out.
  """
  @spec describe_class(class()) :: String.t()
  def describe_class(:loopback), do: "names loopback — the sandbox itself"

  def describe_class(:rfc1918_private),
    do: "names a private network, which is the operator's, not the tenant's"

  def describe_class(:link_local), do: "names a link-local address"

  def describe_class(:cloud_metadata),
    do: "names the cloud instance-metadata endpoint, which holds this host's credentials"

  def describe_class(:unique_local), do: "names an IPv6 unique-local address"

  def describe_class(:unspecified),
    do: "names the unspecified address, which connects to loopback"

  def describe_class(:host_alias), do: "is another name for the host this sandbox runs on"

  @doc """
  Renders a `parse/2` error as sentences naming **every** entry and its class.

  This is what `029-FR-014` asks for and what nothing produced: the answer to
  *"why was this refused?"* in a form that can be put in front of a person
  who is not going to read `address_class/1`.

  ⚠️ **The class atom is printed literally, alongside its prose.** Not
  decoration: `:cloud_metadata` is the string an operator greps for, pastes
  into a bug report, and matches against this module's own table. A sentence
  alone would be readable and unsearchable.

  ⚠️ **Every refused entry is listed, not the first.** The refusal is already
  the second round trip for an operator who also had unreadable entries (see
  the moduledoc); making them fix refusals one per provision would be a third,
  fourth and fifth.
  """
  @spec describe(error()) :: String.t()
  def describe({:refused_entries, entries}) do
    "The network allowlist was understood and declined: " <>
      Enum.map_join(entries, "; ", fn {entry, class} ->
        "#{format_entry(entry)} #{describe_class(class)} (#{inspect(class)})"
      end) <> "."
  end

  def describe({:invalid_entries, entries}) do
    "The network allowlist could not be read: " <>
      Enum.map_join(entries, "; ", &format_entry/1) <>
      ". An entry is written host:port, or host:* for every port."
  end

  # An entry is echoed **as the operator wrote it** wherever it is a string,
  # because the thing they have to go and edit is that string. Already-parsed
  # tuple forms have no written spelling to echo, so one is composed.
  defp format_entry(entry) when is_binary(entry), do: entry
  defp format_entry({host, :any_port}), do: "#{format_host(host)}:*"
  defp format_entry({host, port}) when is_integer(port), do: "#{format_host(host)}:#{port}"
  defp format_entry(other), do: inspect(other)

  defp format_host(host) when is_binary(host), do: host

  defp format_host(host) when is_tuple(host) do
    case :inet.ntoa(host) do
      {:error, _} -> inspect(host)
      charlist -> List.to_string(charlist)
    end
  end

  defp format_host(other), do: inspect(other)

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
  # ⚠️ **029 T008's built-in classes are folded in below** -- `:loopback`,
  # `:rfc1918_private`, `:link_local`, `:cloud_metadata`, `:unique_local`,
  # `:unspecified` on the address branch and the `localhost` family on the name
  # branch. (An earlier revision of this comment said they were absent from the
  # tree; they were merged in the same fold and the note outlived its subject.)
  @spec host_class(term(), %{addresses: MapSet.t(), names: MapSet.t()}) :: class() | nil
  defp host_class(host, aliases) do
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
