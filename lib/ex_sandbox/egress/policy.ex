defmodule ExSandbox.Egress.Policy do
  @moduledoc """
  Which destinations one sandbox may reach, and how that sandbox is identified
  (005 T060a1/T060a2, `contracts/egress.md`, `005-FR-011a`–`FR-011e`).

  ## Identity is the source address, and it is unforgeable

  A sandbox's policy is keyed by the **source /30 its packets arrive from**.
  That address is the kernel's account of which network namespace a connection
  originated in — `:inet.peername/1` on the accepted socket, not anything the
  connecting party said.

  This matters more than it looks. Tenant code cannot claim another sandbox's
  allowlist, because it never asserts an identity at all: there is no token to
  steal, no header to spoof, and no name to collide with. The strongest form of
  an authorization check is one where the subject cannot participate in
  answering it.

  ⚠️ That property depends on **no sandbox having a route to any other**
  (`005-FR-011c`, `003-FR-002`). If two sandboxes shared a link, one could
  originate a connection from within the other's /30 and inherit its policy.
  This is why `ExSandbox.SharedRouteMechanism` exists as an adversary: it is
  conformant in every outward-facing respect and fails only that, so a check
  that trusts topology instead of attempting a crossing shows up as a false
  pass.

  ## Default deny

  `permits?/2` answers `false` for a /30 with no entry. A missing policy is not
  an absent restriction — it is the most restrictive one. `FR-011a` requires an
  allowlist *over* default-deny, and the ordering is the whole guarantee: a
  lookup miss must never be the path by which something becomes reachable.
  """

  @typedoc "An IPv4 address as `:inet` reports it."
  @type ip :: :inet.ip4_address()

  @typedoc """
  A permitted destination. `:any_port` admits a host on every port; a specific
  port admits only that one.
  """
  @type destination :: {ip() | String.t(), :inet.port_number() | :any_port}

  @typedoc "The /30 a sandbox's connections originate from, as `{a, b, c, d}`."
  @type source_key :: ip()

  @typedoc """
  What one sandbox resolved, per name (`029-FR-012`).

  ⚠️ Per **sandbox**, never global. A shared table would let one tenant's
  resolution of a name decide another tenant's verdict for it.
  """
  @type resolutions :: %{optional(String.t()) => MapSet.t(:inet.ip_address())}

  @doc """
  Reduces a source address to the /30 it belongs to.

  ⚠️ Masking is what makes the key stable. A sandbox's connections come from a
  *host* address inside its /30, and that address is not necessarily the network
  address — so keying on the raw source would miss. Masking to the /30 answers
  "which sandbox is this?" rather than "which address is this?".
  """
  @spec source_key(ip()) :: source_key()
  def source_key({a, b, c, d}), do: {a, b, c, d - rem(d, 4)}

  @doc """
  True only when `destination` is explicitly permitted for `source`.

  Returns `false` for an unknown source — see the default-deny note above.

  `resolutions` is what **this sandbox** resolved, as
  `ExSandbox.Egress.Registry.resolutions/2` returns it: `%{name => MapSet of
  addresses}`. It is what makes a hostname entry able to match at all
  (`029-FR-012`); omitted, it defaults to `%{}` and no hostname entry matches
  anything, which is the pre-`029` behaviour and is default-deny.
  """
  @spec permits?([destination()], {ip() | String.t(), :inet.port_number()}, resolutions()) ::
          boolean()
  def permits?(allowed, destination, resolutions \\ %{})

  def permits?(allowed, {host, port}, resolutions)
      when is_list(allowed) and is_map(resolutions) do
    normalised = normalise_host(host)

    Enum.any?(allowed, fn
      {allowed_host, allowed_port} when allowed_port == port or allowed_port == :any_port ->
        host_matches?(allowed_host, normalised, resolutions)

      _ ->
        false
    end)
  end

  def permits?(_allowed, _destination, _resolutions), do: false

  # ⚠️ **Two matches, and the second one is the whole of `FR-012`.**
  #
  # An entry that *is* an address matches by equality, as it always has. An
  # entry that is a **name** cannot: the acceptor reports `SO_ORIGINAL_DST`,
  # which is a dotted quad the kernel recovered from the redirect, post-DNS
  # (`nsacceptor.py:60`). Before `029` the two were compared directly, so
  # `"api.anthropic.com:443"` parsed cleanly, provisioned cleanly, and could
  # never match a connection -- a granted permission that silently denied.
  #
  # So a name entry is matched against **what this sandbox resolved that name
  # to**, recorded by `ExSandbox.Egress.Resolver` as it answered the query.
  # Nothing else is consulted: not the host's resolver, not a resolution
  # performed now on the platform's behalf. Resolving here would compare the
  # tenant's connection against an answer the tenant never received -- a
  # different name-to-address mapping than the one it acted on, so a rotation
  # or a split-horizon zone would refuse a connection the operator permitted.
  defp host_matches?(allowed_host, normalised_destination, resolutions) do
    case normalise_host(allowed_host) do
      host when is_tuple(host) ->
        host == normalised_destination

      # ⚠️ An unparseable host stays a **string** (see `normalise_host/1`), so
      # this branch is reached by exactly the entries that are names, and by the
      # malformed ones -- which resolve to nothing and therefore match nothing.
      name when is_binary(name) ->
        name_matches?(name, normalised_destination, resolutions)

      _ ->
        false
    end
  end

  # ⚠️ **Two ways for a name entry to match, and both are exact.**
  #
  # A destination presented as the *same name* matches by equality. In
  # production this branch is unreachable -- `nsacceptor.py` recovers
  # `SO_ORIGINAL_DST` and reports a dotted quad, always -- but the decision
  # function is also called with named destinations by callers that have a name
  # in hand, and refusing there would be refusing an entry against itself.
  #
  # A destination presented as an *address* matches only if this sandbox
  # resolved this name to that address. That is the production path and the
  # whole of `FR-012`.
  defp name_matches?(name, destination, _resolutions) when is_binary(destination),
    do: normalise_name(name) == normalise_name(destination)

  defp name_matches?(name, destination, resolutions) when is_tuple(destination),
    do: resolved_to?(resolutions, name, destination)

  defp name_matches?(_name, _destination, _resolutions), do: false

  # ⚠️ **Exact name equality, and the looseness this refuses is the point.**
  #
  # The tempting readings are all wider than what the operator wrote:
  # a suffix match makes `"github.com"` admit `evil.github.com.attacker.test`;
  # a `String.contains?` makes it admit anything with the substring; a
  # reverse index from address to "some name that resolved here" makes an entry
  # for one name admit **every other name on the same address**, which on any
  # shared CDN front is most of the internet. `policy_test.exs`'s own note on
  # the address seam already records the rule in the other direction: closing a
  # comparison must not become "compare loosely". `029-FR-012` says an entry
  # naming a hostname matches the connections *that hostname* resolves to, and
  # nothing here widens it past that one name.
  #
  # The two normalisations that ARE applied are spelling, not scope: DNS names
  # are case-insensitive (RFC 4343), and a trailing dot is the same name
  # absolutely qualified. Neither admits a name the operator did not write.
  defp resolved_to?(resolutions, name, address) do
    case Map.fetch(resolutions, normalise_name(name)) do
      {:ok, addresses} -> MapSet.member?(addresses, address)
      :error -> false
    end
  end

  @doc """
  The canonical form of a DNS name for comparison: lower-cased, with any
  trailing root dot removed.

  Public because the **recording** side and the **matching** side must agree
  exactly, and two copies of this would be two things that must stay equal
  forever. The symptom of them drifting is a permitted host that is silently
  refused, which reads as an unreachable network.
  """
  @spec normalise_name(String.t()) :: String.t()
  def normalise_name(name) when is_binary(name) do
    name |> String.downcase() |> String.trim_trailing(".")
  end

  # ⚠️ **The two sides of this comparison are written in different forms, and
  # nothing but this function makes them comparable.**
  #
  # `OriginalDst.decode/1` yields `{93, 184, 216, 34}` because that is what a
  # `sockaddr_in` contains. An allowlist resolved from a project's settings is
  # naturally written `"93.184.216.34"`. `permits?/2` matches the host by
  # equality, so without normalisation a tuple destination never matches a
  # string entry.
  #
  # That defect **fails closed**, which is exactly what makes it dangerous to
  # leave to review: nothing is breached, so no denial check goes red. Every
  # permitted destination is silently refused while the code reads as working
  # enforcement, and the only symptom is the "permitted destination is
  # reachable" check failing with no indication that a type mismatch caused it.
  #
  # Normalising to the tuple form rather than the string form is deliberate:
  # `:inet.parse_address/1` rejects what is not an address, so a malformed
  # entry stays unequal to everything instead of matching by string identity.
  defp normalise_host(host) when is_tuple(host), do: host

  defp normalise_host(host) when is_binary(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, address} -> address
      # Kept as the original string rather than coerced: an unparseable host is
      # not an address, and must not become equal to another unparseable one by
      # collapsing to a shared sentinel.
      {:error, _} -> host
    end
  end

  defp normalise_host(host), do: host
end
