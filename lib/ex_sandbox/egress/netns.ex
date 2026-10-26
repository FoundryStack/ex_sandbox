defmodule ExSandbox.Egress.Netns do
  @moduledoc """
  The commands that turn a sandbox's network namespace into its only path out
  (005 T060a3, `contracts/egress.md`).

  ## The shape (D6 of `let-sandboxes-outlive-a-deploy`)

  1. `bwrap --unshare-net` starts the tenant in a namespace holding only
     loopback,
  2. the **host** installs the redirect into it with
     `nsenter -t <holder-pid> -n nft …` (`redirect_commands/4`),
  3. then gives it a source address and a default route over `lo`
     (`route_commands/2`), last, so no connect leaves loopback unpoliced.

  The redirect sends every outbound TCP connect to the acceptor's listener
  inside the namespace; the acceptor reads `SO_ORIGINAL_DST`, judges it, and
  dials a permitted destination from the host. Nothing else carries traffic
  out: there is no interface but `lo`.

  ⚠️ Steps 2 and 3 cannot be done from inside. The tenant has no
  `CAP_NET_ADMIN` there, which is desirable — a tenant able to edit the ruleset
  would defeat `FR-011b` by reconfiguration rather than by connection.

  ⚠️ **The default route is load-bearing.** Without it the kernel rejects an
  outbound connect with `enetunreach` *before* the nat hook runs, and the
  sandbox is merely *isolated*, which passes every denial check while
  enforcing no policy at all. A bare `default dev lo` gives the tenant source
  `0.0.0.0`; the `/32` on `lo` and `src` give it the address its policy is
  filed under.

  ## Why the redirect is `output` rather than `prerouting`

  The traffic originates *inside* this namespace, so it traverses the `output`
  hook. `prerouting` sees only packets arriving from elsewhere, and there is no
  elsewhere. A `prerouting` rule would install cleanly, list correctly, and
  match nothing.

  ## Why the UDP drop is a `filter` chain and not another `nat` rule

  The TCP redirect lives in `nat`/`output` because it *translates* a destination.
  The UDP rule does not translate anything — it **refuses** — and a `drop` does
  not belong in a `nat` chain merely because that is where the neighbouring rule
  was. `nat` chains are consulted by conntrack for the **first packet of a flow
  only**; a filtering verdict placed there is evaluated on a schedule that has
  nothing to do with how often the traffic it is refusing occurs. So the drop
  gets its own base chain of `type filter`, and the two hooks stay honest about
  what each is for.

  ⚠️ **The chain's policy is `accept`, and that is not a widening.** A `drop`
  policy on an `output` filter chain refuses *everything*, TCP included, and the
  TCP path — which is policed by the redirect, not by this chain — would go with
  it. Default-deny for UDP is expressed by the terminal `meta l4proto udp drop`
  below, which nothing after it can reach past.

  ⚠️ **Family `inet`, not `ip`.** The redirect's table is `ip` (IPv4 only), which
  is defensible for a translation whose target is an IPv4 acceptor. A *refusal*
  scoped to IPv4 would leave the identical IPv6 datagram to walk out, which is
  the shape `FR-015` calls "a control that reads as the guarantee it is not".
  `inet` covers both in one chain. It also fails closed if a kernel will not
  build it: `run_steps/1` halts on a non-zero `nft` exit and
  `police_or_terminate/3` terminates the tenant, so an unsupported table stops
  the launch rather than passing it unpoliced.

  ## Measured, on `docker-isolation:latest` (nftables v1.1.3), 2026-08-23

  Every command below installs (`rc=0`), and `nft` folds the redundant
  `meta l4proto udp` into the `udp dport` match when it lists the exemption
  back:

      table inet filter {
        chain output {
          type filter hook output priority filter; policy accept;
          ip daddr 10.0.0.53 udp dport 53 accept
          meta l4proto udp drop
        }
      }

  ⚠️ **And the rule was measured by attempting the operation, not by reading
  the ruleset** (`FR-016`). In a namespace with a real default route — without
  one every result is `ENETUNREACH` before the hook runs, and *isolated* reads
  exactly like *policed*:

      BEFORE            udp 8.8.8.8:53      -> SENT        <- the hole
                        udp 10.0.0.1:53     -> SENT
      no resolver       udp 8.8.8.8:53      -> EPERM
                        udp 10.0.0.1:53     -> EPERM
                        udp 127.0.0.1:53    -> EPERM
      resolver 10.0.0.53:53
                        udp 10.0.0.53:53    -> SENT        <- the sole destination
                        udp 10.0.0.53:5353  -> EPERM
                        udp 8.8.8.8:53      -> EPERM
      TCP control       tcp 10.0.0.1:80     -> timeout, NOT EPERM

  ⚠️ The TCP line is the one that makes the rest non-vacuous: a chain whose
  *policy* were `drop` would refuse TCP too, and every UDP line above would look
  identical. A timeout there is the correct non-policy outcome for a route with
  nothing behind it.

  ⚠️ **This was a hand-built namespace, not `pasta`'s, and the commands were run
  directly rather than through `LaunchPlan`.** It establishes the grammar and
  the kernel's behaviour; it does **not** establish that the policed launch path
  installs them. That is `029 T014`'s checkpoint.

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
  and its policy. `route_commands/2` puts the sandbox address on the
  namespace's `lo` as the tenant's source.
  """
  @spec addresses(Policy.source_key()) :: %{gateway: String.t(), sandbox: String.t()}
  def addresses({a, b, c, d}) do
    %{
      gateway: "#{a}.#{b}.#{c}.#{d + 1}",
      sandbox: "#{a}.#{b}.#{c}.#{d + 2}"
    }
  end

  @doc "Normalises every accepted `forward()` shape to a list of pairs, primary first."
  @spec forward_pairs(forward()) :: [forward_pair()]
  def forward_pairs(nil), do: []
  def forward_pairs({_host_port, _ns_port} = pair), do: [pair]
  def forward_pairs(pairs) when is_list(pairs), do: pairs

  @doc """
  The commands that install the redirect into a *running* tenant's namespace.

  `holder_pid` is the pid of the process **inside** the namespace.

  ⚠️ A pid in the **host** namespace is a silent catastrophe rather than an
  error: `nsenter -t <host pid> -n nft …` installs the sandbox's redirect into
  the host namespace, succeeds, and leaves the tenant unpoliced.
  `NodeLauncher.police/2` refuses a holder whose namespace is its own.
  """
  # Marks the acceptor's own upstream sockets so the redirect can skip them.
  # Any non-zero value works; this one is arbitrary and stable.
  @acceptor_mark 42

  @typedoc """
  The one UDP destination a sandbox may reach, or `nil` for none.

  ⚠️ An **address**, never a hostname — an `nft` rule cannot resolve a name, and
  the thing that would resolve it is the resolver this names.
  """
  @type resolver :: {String.t() | :inet.ip_address(), :inet.port_number()} | nil

  @typedoc "One inbound TCP port published on host loopback, `{host_port, ns_port}`."
  @type forward_pair :: {:inet.port_number(), :inet.port_number()}

  @typedoc """
  The inbound TCP ports published on host loopback, primary first.

  ⚠️ A bare `forward_pair()` and `nil` are accepted too, and not for
  convenience: a launched row persisted before a sandbox could publish more
  than one port carries the single tuple, and `forward_pairs/1` is where every
  shape becomes the list.
  """
  @type forward :: [forward_pair()] | forward_pair() | nil

  @spec redirect_commands(pos_integer(), :inet.port_number(), resolver(), forward()) ::
          [[String.t()]]
  def redirect_commands(holder_pid, pool_port, resolver \\ nil, forward \\ nil)
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
      # ⚠️ The acceptor's OWN upstream must be exempted, and this rule must come
      # FIRST -- `nft` evaluates in order, so a `return` placed after the
      # redirect never runs.
      #
      # Without it the acceptor's own connect to the permitted destination is
      # re-caught by the very redirect it exists to serve, and it talks to
      # itself. Measured with a TCP upstream, with and without the exemption:
      #
      #   without: conn#1 ORIGINAL_DST=93.184.216.34:443
      #            conn#2 ORIGINAL_DST=127.0.0.1:9100   <- its own upstream
      #            conn#3 ... conn#4 ...  LOOP DETECTED
      #   with:    conn#1 ORIGINAL_DST=93.184.216.34:443
      #            upstream said b'ORIGIN-REPLY'  -> TENANT: got b'DONE'
      #
      # ⚠️ The symptom of the loop is a PERMITTED destination timing out, which
      # reads as an unreachable network rather than as a broken enforcement
      # point -- and every denial check still passes, because denial is
      # unaffected. It survived the first end-to-end run for exactly that
      # reason: the deny case looked perfect.
      #
      # ⚠️ `meta mark`, not `meta skuid`. `skuid` is the more obvious choice and
      # is unusable here: the platform user namespace maps a single uid
      # (`uid_map: 0 0 1`, and `/etc/subuid` has no entry), so there is no second
      # identity to name. The mark is set by the acceptor on its own upstream
      # socket via `SO_MARK`; tenant code cannot set it on the platform's behalf
      # because it never touches that socket.
      nsenter(holder_pid, [
        "nft",
        "add",
        "rule",
        "ip",
        "nat",
        "output",
        "meta",
        "mark",
        "#{@acceptor_mark}",
        "return"
      ]),
      # Namespace loopback stays in the namespace, so `127.0.0.0/8` here
      # reaches nothing but the sandbox. Redirecting it made the acceptor refuse the tenant's own
      # servers -- a test endpoint on `127.0.0.1:<ephemeral>` -- as egress.
      # OBSERVED 2026-09-25 on staging: refusals for 127.0.0.1:55205 and
      # 127.0.0.1:58963 from an application's own test run.
      nsenter(holder_pid, [
        "nft",
        "add",
        "rule",
        "ip",
        "nat",
        "output",
        "ip",
        "daddr",
        "127.0.0.0/8",
        "return"
      ])
    ] ++
      forward_exemption(holder_pid, forward) ++
      [
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
      ] ++ udp_commands(holder_pid, resolver)
  end

  # The acceptor delivers an inbound connection by connecting to
  # 127.0.0.1:<ns_port> from INSIDE the namespace; were the redirect to catch
  # it, the acceptor would refuse it as egress (OBSERVED 2026-09-21 on
  # production). Only the forwarded ports are exempt, one rule each.
  defp forward_exemption(holder_pid, forward) do
    for {_host_port, ns_port} <- forward_pairs(forward) do
      nsenter(holder_pid, [
        "nft",
        "add",
        "rule",
        "ip",
        "nat",
        "output",
        "ip",
        "daddr",
        "127.0.0.1",
        "tcp",
        "dport",
        "#{ns_port}",
        "return"
      ])
    end
  end

  # ⚠️ **This closes a measured hole, not a theoretical one.** Phase 0's
  # conformance run recorded that "a UDP datagram sent from inside the sandbox to
  # 8.8.8.8:53 was ANSWERED — it left the namespace unpoliced and the reply came
  # back". The **same allowlist refuses that destination over TCP**, so until
  # this rule exists a tenant bypasses the entire enforcement point by choosing a
  # transport, over the textbook exfiltration port.
  #
  # ⚠️ **Resolver-as-sole-destination, ruled, not chosen here.** `FR-013` (as
  # amended by D34 defect 5) permits either policing UDP the way TCP is policed
  # or permitting UDP to a platform resolver as its *sole* destination and
  # dropping the rest. The project owner ruled the second (029 T011). It is
  # default-deny; the allowlist is **hostname**-based while UDP is
  # address-based, so "allowlist match for UDP" is not a well-defined question;
  # and DNS is the only legitimate UDP need of a build sandbox.
  #
  # ⚠️ **`nil` drops *all* UDP, and that is the point.** Default-deny includes
  # the unconfigured case. The resolver itself is Phase 2's first deliverable
  # (029 T015); until something supplies its address the correct behaviour is
  # that no UDP leaves, not that UDP is waved through until the resolver
  # arrives. The address arrives as **data** for the same reason the host-alias
  # list does — this module must not acquire an opinion about who runs the
  # resolver.
  #
  # ⚠️ **The resolver's address MAY be a host-side one, and that does not
  # contradict `FR-015`.** It will read as a contradiction, because `FR-015`
  # forbids reaching the host and the platform's resolver plausibly runs there.
  # D34 (defect 4) settles it by naming the surfaces: **`FR-015` governs
  # allowlist entries** — what an operator or tenant may write down, and what a
  # resolver may answer — while nftables rules the platform itself constructs,
  # which a tenant cannot author, are governed by `FR-032`. A
  # platform-constructed rule naming a host-side address is not an allowlist
  # entry naming one. So no host-alias check belongs here; the exclusion lives
  # in `ExSandbox.Egress.Allowlist`, where the tenant-authored surface is.
  defp udp_commands(holder_pid, resolver) do
    [
      nsenter(holder_pid, ["nft", "add", "table", "inet", "filter"]),
      nsenter(holder_pid, [
        "nft",
        "add",
        "chain",
        "inet",
        "filter",
        "output",
        "{ type filter hook output priority 0 ; policy accept ; }"
      ])
    ] ++
      resolver_exemption(holder_pid, resolver) ++
      [
        # ⚠️ LAST, and terminal. `nft` evaluates in order, so this must come
        # after the resolver exemption or the exemption never runs -- the same
        # ordering trap the acceptor's `meta mark ... return` documents above.
        #
        # ⚠️ `meta l4proto udp`, not a bare `udp`, for the reason measured for
        # the TCP redirect above: a bare protocol name is not valid `nft`
        # grammar and the rule is rejected at install time. And no port
        # predicate -- this refuses UDP as such, so a tenant cannot pick an
        # unlisted port and walk past it.
        nsenter(holder_pid, [
          "nft",
          "add",
          "rule",
          "inet",
          "filter",
          "output",
          "meta",
          "l4proto",
          "udp",
          "drop"
        ])
      ]
  end

  @doc """
  Returns `resolver` unchanged, or raises if it is not a usable one.

  ⚠️ **Exists so the refusal lands at plan-build time rather than at
  rule-install time.** `resolver_exemption/2` also raises, but it runs *after*
  the tenant has started, so a bad address there terminates a running
  sandbox instead of refusing a launch. Both raise; this one raises early, and
  the two share `parse_resolver_address/1` so they cannot disagree about what
  is readable.

  `nil` is valid and means **no UDP destination at all** — see `udp_commands/2`
  on why that is default-deny rather than a degradation.
  """
  @spec validate_resolver!(resolver()) :: resolver()
  def validate_resolver!(nil), do: nil

  def validate_resolver!({address, port} = resolver)
      when is_integer(port) and port > 0 and port <= 65_535 do
    case parse_resolver_address(address) do
      {:ok, _parsed} ->
        resolver

      :error ->
        raise ArgumentError, "resolver address is not an IP address: #{inspect(address)}"
    end
  end

  def validate_resolver!(other),
    do: raise(ArgumentError, "resolver must be `{address, port}` or nil, got: #{inspect(other)}")

  defp resolver_exemption(_holder_pid, nil), do: []

  defp resolver_exemption(holder_pid, {address, port})
       when is_integer(port) and port > 0 and port <= 65_535 do
    # ⚠️ Refused loudly rather than degraded to "no exemption". A resolver whose
    # address cannot be read is a misconfiguration, and silently emitting only
    # the drop would produce a sandbox with no DNS whose rules all installed
    # cleanly -- indistinguishable from one that was never given a resolver.
    # Raising halts the launch, and `police_or_terminate/3` terminates a tenant
    # that could not be policed.
    {daddr_keyword, literal} =
      case parse_resolver_address(address) do
        {:ok, {_, _, _, _} = parsed} ->
          {"ip", to_string(:inet.ntoa(parsed))}

        {:ok, parsed} ->
          {"ip6", to_string(:inet.ntoa(parsed))}

        :error ->
          raise ArgumentError, "resolver address is not an IP address: #{inspect(address)}"
      end

    # ⚠️ **TWO rules, because a DNS exchange is a round trip and this chain
    # filters BOTH halves of it.** The answer leaves the resolver's socket and
    # is therefore also `output` traffic -- with the resolver as its *source*
    # and the tenant's ephemeral port as its destination, so the query rule
    # cannot match it and the terminal drop does.
    #
    # MEASURED inside `unshare -n` with a stub nameserver on `127.0.0.1:53`,
    # under exactly the rules this function emitted before the second one was
    # added:
    #
    #     query rule only    -> query SENT, stub's reply EPERM, client timed out
    #     + this second rule -> reply sent, "ANSWER RECEIVED (6 bytes)"
    #     control, port 5353 -> query EPERM, still refused
    #
    # ⚠️ The first line is why "the datagram left" is not evidence that name
    # resolution works. An earlier probe here asserted only `SENT` and read as
    # a pass, while every lookup inside a sandbox was in fact timing out --
    # which surfaces as `FR-012` denying a hostname the operator did permit.
    #
    # ⚠️ Narrow on purpose: source address AND source port, not `ct state
    # established`. Conntrack would also readmit whatever else the namespace
    # happened to have talked to, and the exemption's whole value is that it
    # names one endpoint.
    #
    # ⚠️ It permits a SOURCE, so it is worth stating what a tenant could do with
    # it: bind the resolver's address and port itself and send from there. With
    # the default resolver that address is loopback, so such a datagram cannot
    # leave the namespace and reaches only the acceptor. A deployment that moves
    # the resolver to a routable address gives the tenant a way to send UDP from
    # that source to any destination, and should weigh that against whatever it
    # gained by moving it.
    [
      nsenter(holder_pid, [
        "nft",
        "add",
        "rule",
        "inet",
        "filter",
        "output",
        "meta",
        "l4proto",
        "udp",
        daddr_keyword,
        "daddr",
        literal,
        "udp",
        "dport",
        "#{port}",
        "accept"
      ]),
      nsenter(holder_pid, [
        "nft",
        "add",
        "rule",
        "inet",
        "filter",
        "output",
        "meta",
        "l4proto",
        "udp",
        daddr_keyword,
        "saddr",
        literal,
        "udp",
        "sport",
        "#{port}",
        "accept"
      ])
    ]
  end

  defp resolver_exemption(_holder_pid, other),
    do: raise(ArgumentError, "resolver must be `{address, port}` or nil, got: #{inspect(other)}")

  defp parse_resolver_address(address) when is_tuple(address) do
    case :inet.ntoa(address) do
      {:error, _} -> :error
      _ -> {:ok, address}
    end
  end

  defp parse_resolver_address(address) when is_binary(address) do
    case :inet.parse_address(String.to_charlist(address)) do
      {:ok, parsed} -> {:ok, parsed}
      {:error, _} -> :error
    end
  end

  defp parse_resolver_address(_), do: :error

  @doc """
  The `SO_MARK` value the acceptor sets on its own upstream connections.

  Exists so the redirect can skip them: without the exemption the acceptor's
  connect to a permitted destination is caught by its own redirect and it talks
  to itself, which surfaces as a permitted destination timing out.
  """
  @spec acceptor_mark() :: pos_integer()
  def acceptor_mark, do: @acceptor_mark

  @doc """
  The commands that give the loopback-only namespace a source address and a
  default route, so an outbound connect reaches the `nat` hook instead of
  failing `enetunreach` (D6 of `let-sandboxes-outlive-a-deploy`).

  ⚠️ Run **after** `redirect_commands/4`: from the moment the route exists a
  connect leaves loopback, and before the redirect is in place nothing would
  judge it.
  """
  @spec route_commands(pos_integer(), String.t()) :: [[String.t()]]
  def route_commands(holder_pid, address) do
    [
      nsenter(holder_pid, ["ip", "addr", "add", "#{address}/32", "dev", "lo"]),
      nsenter(holder_pid, ["ip", "route", "add", "default", "dev", "lo", "src", address])
    ]
  end

  # ⚠️ `-n` alone, never `-U` (D6 of `let-sandboxes-outlive-a-deploy`). The
  # holder's user namespace is bwrap's, created after `setpriv`, and maps only
  # the sandbox uid. Measured against such a holder from a root caller:
  #
  #     nsenter -t <holder> -n nft add table ip nat                         -> OK
  #     nsenter -t <holder> -n -U nft ...       -> setgid() failed: Invalid argument
  #     nsenter -t <holder> -n -U --preserve-credentials [--keep-caps] nft ... -> EPERM
  #
  # Entering takes `CAP_SYS_ADMIN` and `CAP_NET_ADMIN` over the netns, which
  # the caller holds from the initial user namespace, as `Egress.NetnsSocket`'s
  # `setns` does.
  defp nsenter(pid, command),
    do: ["nsenter", "-t", "#{pid}", "-n"] ++ command
end
