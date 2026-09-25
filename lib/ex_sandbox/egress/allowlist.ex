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
  | `"public"` or `:public` | every public address on every port; see below |

  ### `"public"`

  Parses to `{:public, alias_addresses}`: the host aliases this parse was
  given, carried as data so the per-connection decision can refuse them
  without asking the host again. `ExSandbox.Egress.Policy.permits?/3` permits a
  connection under it when the address the connection was **dialled to** is
  outside every refused class below. It never looks at a name, so a public
  name whose zone answers `10.0.0.5` is refused as `:rfc1918_private` on
  connect.

  ⚠️ **A word, not `*:*`.** `host:port` is a grammar for one host, and `*` in
  the host position would read as a wildcard that `"*:443"` could narrow. It
  cannot: this form has no port, and granting every public host on one port is
  not expressible. `"public"` has no colon, so it collides with no
  `host:port` entry, and with no host (a bare host is always unreadable).

  An already-parsed `{:public, _}` handed back in is rebuilt with **this**
  parse's aliases, never passed through with its own.

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
  alias ExSandbox.Egress.Refusal

  @typedoc "An entry as a project's settings may express it."
  @type entry :: String.t() | :public | Policy.destination()

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
  @type class :: ExSandbox.Egress.Refusal.class()

  @typedoc """
  A thing that *is* the host, as a caller may express it.

  An address (`"10.0.0.1"`, `{10, 0, 0, 1}`) or a name
  (`"host.docker.internal"`). Ports are not part of an alias: a destination is
  the host, or it is not, and naming a port would permit every other one.
  """
  @type host_alias :: ExSandbox.Egress.Refusal.host_alias()

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
    aliases = Refusal.normalise_aliases(host_aliases)
    public = {:public, aliases.addresses |> MapSet.to_list()}

    {parsed, invalid, refused} =
      Enum.reduce(entries, {[], [], []}, fn entry, {ok, bad, no} ->
        with {:ok, destination} <- parse_entry(entry, public),
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
    do: Refusal.class(host, Refusal.normalise_aliases(host_aliases))

  @doc """
  Why an entry of `class` was refused, as a clause a person can act on.

  ⚠️ **This is the half of `029-FR-015` that had no reader, and the class
  existed for it.** `parse/2` has named a class since `029` T008 and every
  caller propagated the tuple opaquely, so what reached an operator was
  "provisioning failed" — the exact sentence the class was added to replace.
  A class nobody renders is the same defect as a check that cannot fail.

  The sentence lives **here**, beside the table of classes, rather than at whichever
  surface happens to show it. Two surfaces writing their own would be two
  vocabularies for one set of atoms, and the one nobody reads is the one that
  stops matching `ExSandbox.Egress.Refusal`.

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
  who is not going to read `ExSandbox.Egress.Refusal`.

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

  # `:public` names no host, so there is nothing to refuse at parse time; the
  # classes are applied to each dialled address instead (`Policy.permits?/3`).
  defp refusal_class({:public, _alias_addresses}, _aliases), do: nil

  # The port is deliberately unread. A destination either is the host or is not;
  # a class that depended on the port would refuse `127.0.0.1:5432` and permit
  # `127.0.0.1:5433`.
  defp refusal_class({host, _port}, aliases), do: Refusal.class(host, aliases)

  # ⚠️ The alias addresses are this parse's, never the entry's. An already-parsed
  # `{:public, addresses}` handed back in is rebuilt rather than passed through,
  # so a caller cannot narrow the host's exclusion by editing the list it carries.
  defp parse_entry(entry, public) when entry in ["public", :public], do: {:ok, public}
  defp parse_entry({:public, addresses}, public) when is_list(addresses), do: {:ok, public}
  defp parse_entry(entry, _public), do: parse_entry(entry)

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
