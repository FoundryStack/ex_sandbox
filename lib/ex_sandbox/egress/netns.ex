defmodule ExSandbox.Egress.Netns do
  @moduledoc """
  The commands that turn a sandbox's network namespace into its only path out
  (005 T060a3, `contracts/egress.md`).

  ## The shape, and why it is inverted from the obvious one

  The obvious design — create a named namespace, configure it, attach `pasta`,
  then have the tenant join it — **is not reachable**. Measured, in
  `egress-path-measurements.md`: `pasta` cannot join a namespace made by
  `ip netns add` here, failing with `Failed to join network namespace:
  Permission denied`. It works only when it *spawns* the namespace itself.

  So the order inverts:

  1. `pasta --config-net --runas 0 -P <pidfile> -- <tenant>` creates the
     namespace, configures its interface and default route, and starts the
     tenant inside it,
  2. the **host** then installs the redirect into that namespace with
     `nsenter -t <holder-pid> -n nft …`.

  ⚠️ Step 2 cannot be done from inside. `pasta`'s namespace is unprivileged, so
  the tenant has no `CAP_NET_ADMIN` and `nft` there fails with `Operation not
  permitted`. That is *desirable* — a tenant able to edit the ruleset would
  defeat `FR-011b` by reconfiguration rather than by connection — but it means
  the policy is installed from outside, by us, after the tenant is running.

  ## What `pasta` configures, and what this module therefore does not

  `pasta --config-net` brings up the interface, assigns the address, and
  installs the default route. An earlier version of this module emitted
  `ip addr add`, `ip link set`, and `ip route add` steps of its own; all three
  failed with `Cannot find device "sb0"`, because nothing had created the
  device and `pasta` had not yet run. They were not merely redundant — they ran
  *before* the thing that makes them possible.

  ⚠️ **The default route is still load-bearing, it is simply not ours to
  install.** Without it the kernel rejects an outbound connect with
  `enetunreach` *before* the nat hook runs, and the sandbox is merely
  *isolated* — the state `--unshare-net` already gave, which passes every
  denial check while enforcing no policy at all. `pasta` provides it; this
  module's job is to not get in the way, and `verify_route/1` exists so its
  absence is caught rather than assumed.

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
  The commands that install the redirect into a *running* tenant's namespace.

  `holder_pid` is the pid of the process **inside** the namespace.

  ⚠️ It is not `pasta`'s own pid, and the difference is a silent catastrophe
  rather than an error. `pasta -P` writes its **host-side** pid; the tenant
  runs in a child. Measured:

      pidfile pid = 10 -> ns net:[4026534462]   <- the HOST namespace
      tenant  pid = 11 -> ns net:[4026534599]   <- the sandbox namespace

  `nsenter -t 10 -n nft …` installs the sandbox's redirect **into the host
  namespace**: it succeeds, warns about nothing, and leaves the tenant
  unpoliced while the host acquires a stray NAT rule. `ExSandbox.Egress.Pasta`
  finds the holder by comparing namespace inodes for exactly this reason.
  """
  @spec redirect_commands(pos_integer(), :inet.port_number()) :: [[String.t()]]
  def redirect_commands(holder_pid, pool_port)
      when is_integer(holder_pid) and holder_pid > 0 do
    [
      nsenter(holder_pid, ["nft", "add", "table", "ip", "nat"]),
      nsenter(holder_pid, [
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
      # depends on; `tcp dport 1-65535` would install but reintroduces exactly
      # the port match ruled out there.
      nsenter(holder_pid, [
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
  The command that reads a namespace's routing table.

  Used to verify `pasta` installed a default route before the tenant is
  allowed to matter. See the moduledoc: without one, every connect fails
  `enetunreach` before the redirect is consulted, and the sandbox is isolated
  rather than policed — a state that passes every denial check.
  """
  @spec route_command(pos_integer()) :: [String.t()]
  def route_command(holder_pid), do: nsenter(holder_pid, ["ip", "-4", "route", "show"])

  @doc """
  Whether `ip route show` output carries a default route.
  """
  @spec default_route?(String.t()) :: boolean()
  def default_route?(output) when is_binary(output), do: String.contains?(output, "default via")

  @doc """
  The `pasta` invocation that creates a namespace and starts the tenant in it.

  ⚠️ `--runas 0` is required and is not a hardening choice. Without it `pasta`
  drops to `nobody`, then cannot re-enter the namespace it just made:

      Started as root, will change to nobody.
      Failed to join network namespace: Permission denied

  ⚠️ `--config-net` is what makes this work without a host capability. Its one
  real prerequisite is the `/dev/net/tun` **device**, not a capability, which is
  why `probe_network_policy/0` checks for the device and `compose.isolation.yml`
  declares it.

  ⚠️ There is deliberately no `--interface` flag. An earlier version passed
  `--interface sb0`, believing it named the namespace-side device; `-i` selects
  the **host** interface to copy addresses and routes *from*, and the
  namespace-side name is `-I/--ns-ifname`. Measured:
  `pasta --config-net --interface sb0 …` fails with `Invalid interface name
  sb0: No such device`. Neither is needed — `pasta` picks the host's default
  route interface, which is the one with a route out.
  """
  @spec pasta_command(String.t(), [String.t()]) :: [String.t()]
  def pasta_command(pidfile, [_ | _] = tenant_command) do
    ["pasta", "--config-net", "--runas", "0", "-P", pidfile, "--"] ++ tenant_command
  end

  # ⚠️ `-U --preserve-credentials` is load-bearing and `-n` alone is REFUSED
  # from the BEAM's vantage. Measured on `docker-isolation:latest` under plain
  # unprivileged `docker run --device /dev/net/tun`, both forms from both
  # vantage points in one run:
  #
  #     caller OUTSIDE the platform userns (this is where the BEAM stands):
  #       nsenter -t <holder> -n ip link                          -> REFUSED
  #       nsenter -t <holder> -n -U --preserve-credentials ip link -> OK
  #
  # The netns is a descendant of the platform's user namespace, so entering it
  # requires `CAP_SYS_ADMIN` *in that userns*. The BEAM is not in it --
  # `/proc/self/ns/user` reads `user:[4026531837]` while the holder's reads
  # `user:[4026534472]` -- so the netns must be joined together with the userns
  # that owns it. `--preserve-credentials` keeps the caller's uid rather than
  # remapping to the target's root.
  #
  # ⚠️ A shell probe run *inside* the platform userns measures the opposite
  # (bare `-n` OK, `-U` refused, because it is already in that userns) and that
  # is the reading this call site originally encoded. It is not the BEAM's
  # position. `ExSandbox.Capability.can_enter_foreign_netns?/0` probes the form
  # written here, so probe and mechanism cannot drift apart again silently.
  defp nsenter(pid, command),
    do: ["nsenter", "-t", "#{pid}", "-n", "-U", "--preserve-credentials"] ++ command
end
