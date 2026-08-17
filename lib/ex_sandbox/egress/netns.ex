defmodule ExSandbox.Egress.Netns do
  @moduledoc """
  The commands that turn a sandbox's network namespace into its only path out
  (005 T060a3, `contracts/egress.md`).

  ## The shape, measured end to end

  1. the host creates a named namespace and a **veth pair**, moves one end into
     it, addresses both ends from the sandbox's `/30`, and installs a default
     route,
  2. the tenant is launched **inside** that namespace, still `bwrap`-confined,
  3. the host installs the redirect; an acceptor listens inside the namespace.

  Measured working together: a `bwrap`-confined tenant connecting to
  `93.184.216.34:443` was redirected to an in-namespace acceptor that read
  `ORIGINAL_DST=93.184.216.34:443` from a peer at `10.77.0.2` — the sandbox's
  own `/30` address, which is what `ExSandbox.Egress.Policy.source_key/1`
  attributes by.

  ## ⚠️ Why not `pasta`

  An earlier version used `pasta --config-net`, which needs no host capability
  and looked ideal. **It cannot carry a confined tenant.**

  Measured: `pasta` starts its child as **uid 65534 with
  `CapEff=0000000000000000`**, inside a user namespace whose mappings it failed
  to write (`Couldn't write to /proc/self/uid_map`). From there the tenant
  cannot create any namespace, so `bwrap` — whose entire job is creating
  namespaces — fails with `No permissions to create new namespace`. `--runas 0`
  sets *pasta's* uid, not the tenant's.

  Inverting the nesting (`bwrap` outside, `pasta` inside) runs, but
  `--unshare-net` leaves `pasta` no interface to copy, so it falls back to
  **local mode** on a link-local address and an outbound connect returns
  `Connection refused`. That is a namespace with a default route and no path
  out — *isolated, not policed*, wearing a route, which is the shape most
  likely to be mistaken for success.

  A veth pair costs `CAP_NET_ADMIN` on the host, which `pasta` was chosen to
  avoid. That cost is real, and it is why the capability probe must gate this
  rather than assume it.

  ## ⚠️ The default route is load-bearing

  Without it the kernel rejects an outbound connect with `enetunreach` *before*
  the nat hook runs, so a missing route prints exactly like a refused redirect.
  Omitting it made the first spike report `redirect did NOT fire` — a true
  statement about the wrong thing. Without the route the sandbox is merely
  *isolated*: the state `--unshare-net` already gave, which passes every denial
  check while enforcing no policy at all.

  ## Why the redirect is `output` rather than `prerouting`

  The traffic originates *inside* this namespace, so it traverses the `output`
  hook. `prerouting` sees only packets arriving from elsewhere, and there is no
  elsewhere. A `prerouting` rule would install cleanly, list correctly, and
  match nothing.

  ## What this module deliberately does not do

  It builds commands; it does not run them. The launch path composes them, and
  the conformance suite establishes the boundary by *attempting connections*
  rather than by inspecting rules. A test asserting that the right `nft` string
  was produced proves the string, not the boundary.
  """

  alias ExSandbox.Egress.Policy

  @doc """
  The sandbox-side address of a `/30`, and the gateway address.

  A `/30` holds exactly four addresses: network, two hosts, broadcast. The
  first host is the gateway, the second is the sandbox.

  ⚠️ Retained because `Policy.source_key/1` masks the address the pool sees
  back to the key its allowlist is filed under — the join between a namespace
  and its policy. `pasta` assigns the namespace's address from the host
  interface it copies, so this is the *addressing scheme*, not a claim about
  what `pasta` will hand out.
  """
  @spec addresses(Policy.source_key()) :: %{gateway: String.t(), sandbox: String.t()}
  def addresses({a, b, c, d}) do
    %{
      gateway: "#{a}.#{b}.#{c}.#{d + 1}",
      sandbox: "#{a}.#{b}.#{c}.#{d + 2}"
    }
  end

  @doc """
  The commands that create and address the sandbox's namespace.

  Run on the **host**, before the tenant launches. Unlike the `pasta` shape
  this replaced, the namespace exists before anything runs in it, so the
  ordering is the plain one: configure, then launch.
  """
  @spec setup_commands(Policy.source_key(), :inet.port_number(), keyword()) :: [[String.t()]]
  def setup_commands(source_key, pool_port, opts \\ []) do
    name = Keyword.get(opts, :name, namespace_name(source_key))
    %{gateway: gateway, sandbox: sandbox} = addresses(source_key)
    {host_if, sandbox_if} = interface_names(source_key)

    [
      ["ip", "netns", "add", name],
      ["ip", "link", "add", host_if, "type", "veth", "peer", "name", sandbox_if],
      ["ip", "link", "set", sandbox_if, "netns", name],
      # The host end carries the gateway address the sandbox routes through.
      ["ip", "addr", "add", "#{gateway}/30", "dev", host_if],
      ["ip", "link", "set", host_if, "up"],
      in_ns(name, ["ip", "addr", "add", "#{sandbox}/30", "dev", sandbox_if]),
      in_ns(name, ["ip", "link", "set", sandbox_if, "up"]),
      in_ns(name, ["ip", "link", "set", "lo", "up"]),
      # ⚠️ See the moduledoc. Without this the connect fails `enetunreach`
      # before the nat hook runs, and the sandbox is isolated rather than
      # policed -- which passes every denial check.
      in_ns(name, ["ip", "route", "add", "default", "via", gateway])
    ] ++ redirect_commands(name, pool_port)
  end

  @doc """
  The commands that install the redirect into a namespace.
  """
  @spec redirect_commands(String.t(), :inet.port_number()) :: [[String.t()]]
  def redirect_commands(name, pool_port) when is_binary(name) do
    [
      in_ns(name, ["nft", "add", "table", "ip", "nat"]),
      in_ns(name, [
        "nft",
        "add",
        "chain",
        "ip",
        "nat",
        "output",
        "{ type nat hook output priority -100 ; }"
      ]),
      # ⚠️ Matches **all** outbound TCP, not a port list. The allowlist is
      # enforced at the acceptor, which is the only component that knows the
      # destination; filtering by port here would let an unlisted port bypass
      # the enforcement point entirely rather than be refused by it.
      #
      # ⚠️ `meta l4proto tcp`, not a bare `tcp`. The latter is not valid nft
      # grammar and every rule built from it was rejected at install time:
      #
      #     nft add rule ip nat output tcp redirect to :44697
      #     Error: syntax error, unexpected redirect
      #
      # Measured -- `meta l4proto tcp` and `ip protocol tcp` are both accepted,
      # as is `tcp dport 1-65535`. The first is used because it matches all TCP
      # with no port predicate, which is the property the paragraph above
      # depends on.
      in_ns(name, [
        "nft",
        "add",
        "rule",
        "ip",
        "nat",
        "output",
        "meta",
        "l4proto",
        "tcp",
        "redirect",
        "to",
        ":#{pool_port}"
      ])
    ]
  end

  @doc """
  The commands that give back a sandbox's namespace and its veth pair.

  ⚠️ Deleting the namespace destroys the sandbox-side veth with it, but the
  **host-side end survives** if the namespace was never created or the pair was
  built and the move failed. Both are removed, and both tolerate absence --
  destroy runs for sandboxes that failed to provision and runs twice for ones
  that did (`003-FR-013`).
  """
  @spec teardown_commands(Policy.source_key(), keyword()) :: [[String.t()]]
  def teardown_commands(source_key, opts \\ []) do
    name = Keyword.get(opts, :name, namespace_name(source_key))
    {host_if, _} = interface_names(source_key)

    [
      ["ip", "netns", "delete", name],
      ["ip", "link", "delete", host_if]
    ]
  end

  @doc """
  The namespace name for a sandbox's `/30`.

  Derived from the address rather than from the sandbox id: the `/30` is what
  the policy is keyed by, so a name derived from it cannot drift from the
  identity the acceptor enforces against.
  """
  @spec namespace_name(Policy.source_key()) :: String.t()
  def namespace_name({a, b, c, d}), do: "sb-#{a}-#{b}-#{c}-#{d}"

  @doc """
  The host-side and sandbox-side veth names for a `/30`.

  ⚠️ Both are derived from the `/30` and both must be unique **on the host** —
  the host end lives in the host's namespace alongside every other sandbox's.
  A fixed name would work for one sandbox and collide on the second, with
  `RTNETLINK answers: File exists`.

  ⚠️ Kernel interface names are capped at 15 characters. `10.255.255.252`
  yields `sbh-10-255-255-252`, which is 18 and would be rejected — so the last
  octet alone is used, which is unique because the allocator hands out
  non-overlapping `/30`s from one `/16`.
  """
  @spec interface_names(Policy.source_key()) :: {String.t(), String.t()}
  def interface_names({_a, _b, c, d}), do: {"sbh#{c}x#{d}", "sbs#{c}x#{d}"}

  @doc """
  The command that reads a namespace's routing table.

  Used to verify `pasta` installed a default route before the tenant is
  allowed to matter. See the moduledoc: without one, every connect fails
  `enetunreach` before the redirect is consulted, and the sandbox is isolated
  rather than policed — a state that passes every denial check.
  """
  @spec route_command(String.t()) :: [String.t()]
  def route_command(name) when is_binary(name), do: in_ns(name, ["ip", "-4", "route", "show"])

  @doc """
  Whether `ip route show` output carries a default route.
  """
  @spec default_route?(String.t()) :: boolean()
  def default_route?(output) when is_binary(output), do: String.contains?(output, "default via")

  @doc """
  Wraps a tenant command so it launches inside the sandbox's namespace.

  ⚠️ `--unshare-net` must already have been removed by the caller. Left in
  place, `bwrap` would put the tenant in a fresh **empty** namespace instead of
  the configured one -- the policy would be installed correctly, on a namespace
  nothing uses, and every denial check would still pass because an empty
  namespace denies everything too.
  """
  @spec in_namespace(Policy.source_key(), [String.t()], keyword()) :: [String.t()]
  def in_namespace(source_key, [_ | _] = tenant_command, opts \\ []) do
    name = Keyword.get(opts, :name, namespace_name(source_key))
    in_ns(name, tenant_command)
  end

  defp in_ns(name, command), do: ["ip", "netns", "exec", name] ++ command
end
