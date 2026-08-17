defmodule ExSandbox.Egress.Netns do
  @moduledoc """
  The commands that turn a bare network namespace into a sandbox's only path
  out (005 T060a3, `contracts/egress.md`).

  ## What has to exist inside the namespace

  Three things, and each was measured in the isolation image at
  `CapEff=0000000000000000` before being written here:

  1. an interface carrying the sandbox's `/30` address — this is the address
     `:inet.peername/1` reports at the pool, and therefore the **unforgeable
     identity** `ExSandbox.Egress.Policy.source_key/1` masks
  2. a **default route**, without which the kernel rejects an outbound connect
     with `enetunreach` *before* the nat hook runs
  3. a **nat output redirect** sending outbound TCP to the pool

  ⚠️ **Point 2 is not an optimisation, and it is the one a reader is most likely
  to drop as redundant.** The first end-to-end spike omitted the route and
  reported `redirect did NOT fire` — a true statement about the wrong thing,
  because the packet never reached the redirect. Without the route the sandbox
  is merely *isolated*, which is the state `--unshare-net` already gave and
  which passes every denial check while enforcing no policy at all.

  ## Why the redirect is `output` rather than `prerouting`

  The traffic originates *inside* this namespace, so it traverses the `output`
  hook. `prerouting` sees only packets arriving from elsewhere, and there is no
  elsewhere — the namespace has exactly one interface and it leads to `pasta`.
  A `prerouting` rule would install cleanly, list correctly, and match nothing.

  ## What this module deliberately does not do

  It builds commands; it does not run them. The launch path composes them into
  the sandbox's start, and the conformance suite establishes the boundary by
  *attempting connections* rather than by inspecting rules. A test asserting
  that the right `nft` string was produced proves the string, not the boundary —
  which is why these are unit-tested for shape here and verified for effect in
  the container.
  """

  alias ExSandbox.Egress.Policy

  @typedoc "The interface name inside a sandbox's namespace."
  @type interface :: String.t()

  @default_interface "sb0"

  @doc """
  The sandbox-side address of a `/30`, and the gateway address `pasta` answers
  on.

  A `/30` holds exactly four addresses: network, two hosts, broadcast. The
  first host is the gateway, the second is the sandbox — the same split the
  spike measured (`10.0.0.1` gateway, `10.0.0.2` sandbox).
  """
  @spec addresses(Policy.source_key()) :: %{gateway: String.t(), sandbox: String.t()}
  def addresses({a, b, c, d}) do
    %{
      gateway: "#{a}.#{b}.#{c}.#{d + 1}",
      sandbox: "#{a}.#{b}.#{c}.#{d + 2}"
    }
  end

  @doc """
  The shell commands establishing the namespace's interface, route, and
  redirect.

  Returned as a list of argv lists rather than a single string: a caller that
  joins them into a shell line is making an explicit choice to do so, whereas a
  string invites interpolation of a sandbox-controlled value into a command.
  """
  @spec setup_commands(Policy.source_key(), :inet.port_number(), keyword()) :: [[String.t()]]
  def setup_commands(source_key, pool_port, opts \\ []) do
    interface = Keyword.get(opts, :interface, @default_interface)
    %{gateway: gateway, sandbox: sandbox} = addresses(source_key)

    [
      ["ip", "link", "set", "lo", "up"],
      ["ip", "addr", "add", "#{sandbox}/30", "dev", interface],
      ["ip", "link", "set", interface, "up"],
      # ⚠️ The route the first spike omitted. Without it every outbound connect
      # fails `enetunreach` before the redirect is consulted.
      ["ip", "route", "add", "default", "via", gateway, "dev", interface],
      ["nft", "add", "table", "ip", "nat"],
      ["nft", "add", "chain", "ip", "nat", "output", "{ type nat hook output priority -100 ; }"],
      # ⚠️ Matches **all** outbound TCP, not a port list. The allowlist is
      # enforced at the pool, which is the only component that knows the
      # destination; filtering by port here would let an unlisted port bypass
      # the enforcement point entirely rather than be refused by it.
      #
      # ⚠️ `meta l4proto tcp`, not a bare `tcp`. The latter is not valid nft
      # grammar and every rule built from it was rejected at install time:
      #
      #     nft add rule ip nat output tcp redirect to :44697
      #     Error: syntax error, unexpected redirect
      #
      # Measured in the isolation container -- `meta l4proto tcp` and
      # `ip protocol tcp` are both accepted, as is `tcp dport 1-65535`. The
      # first is used because it matches all TCP with no port predicate, which
      # is the property the paragraph above depends on; `tcp dport 1-65535`
      # would install but reintroduces exactly the port match ruled out there.
      #
      # This was invisible for as long as it existed: these commands are built
      # here and run by `NodeLauncher`, and no sandbox in the conformance suite
      # carries an allowlist, so the policed branch never executed and the rule
      # was never handed to `nft`. See `egress-path-measurements.md`.
      ["nft", "add", "rule", "ip", "nat", "output", "meta", "l4proto", "tcp", "redirect", "to",
       ":#{pool_port}"]
    ]
  end

  @doc """
  The `pasta` invocation for a sandbox's namespace.

  ⚠️ `--config-net` is what makes this work without a host capability — measured
  at `CapEff=0000000000000000`. Its one real prerequisite is the `/dev/net/tun`
  **device**, not a capability, which is why `probe_network_policy/0` checks for
  the device and `compose.isolation.yml` declares it.
  """
  @spec pasta_command(pid_or_path :: String.t(), keyword()) :: [String.t()]
  def pasta_command(target, opts \\ []) do
    interface = Keyword.get(opts, :interface, @default_interface)

    [
      "pasta",
      "--config-net",
      "--interface",
      interface,
      target
    ]
  end
end
