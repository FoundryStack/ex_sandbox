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
  """
  @spec permits?([destination()], {ip() | String.t(), :inet.port_number()}) :: boolean()
  def permits?(allowed, {host, port}) when is_list(allowed) do
    Enum.any?(allowed, fn
      {^host, ^port} -> true
      {^host, :any_port} -> true
      _ -> false
    end)
  end

  def permits?(_allowed, _destination), do: false
end
