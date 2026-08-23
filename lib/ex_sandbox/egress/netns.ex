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
  # Marks the acceptor's own upstream sockets so the redirect can skip them.
  # Any non-zero value works; this one is arbitrary and stable.
  @acceptor_mark 42

  # Where `pasta` lives on the target base image (verified at `/usr/bin/pasta`).
  # Used only when `PATH` lookup fails, so a misconfigured host fails naming a
  # path it looked for. See `pasta_path/0`.
  @pasta_fallback "/usr/bin/pasta"

  @typedoc """
  The one UDP destination a sandbox may reach, or `nil` for none.

  ⚠️ An **address**, never a hostname — an `nft` rule cannot resolve a name, and
  the thing that would resolve it is the resolver this names.
  """
  @type resolver :: {String.t() | :inet.ip_address(), :inet.port_number()} | nil

  @spec redirect_commands(pos_integer(), :inet.port_number(), resolver()) :: [[String.t()]]
  def redirect_commands(holder_pid, pool_port, resolver \\ nil)
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
  `pasta` has started the tenant, so a bad address there terminates a running
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

  ## The four flags that close the host off (`029-FR-015`, `029-FR-018`)

  `pasta`'s defaults are built for convenience — it *wants* the namespace to
  reach the host and the host to reach the namespace. Every one of the flags
  below turns a default off, and none of them is a hardening extra.

  | flag | what the default does |
  |---|---|
  | `--no-map-gw` | maps the namespace's default gateway to the **host**, so the host is reachable at the gateway address |
  | `-t none` | `-t auto` forwards **inbound TCP**: a tenant binding `0.0.0.0:8080` binds `0.0.0.0:8080` *on the host* (`FR-018`) |
  | `-T none` | the same for TCP in the outbound-to-host direction |
  | `-u none` | `-u auto` forwards inbound **UDP** |
  | `-U none` | the same for UDP in the outbound-to-host direction |

  ⚠️ **`--no-map-gw` alone closes half the doors and reads as complete.** The
  namespace reaches host `127.0.0.1` by **two independent paths**, and that flag
  closes one of them: the gateway-address mapping. The other is the port
  forwarding that `-t/-T/-u/-U` default to `auto`. A build that passes
  `--no-map-gw` and stops has a *narrower* hole rather than no hole, and it
  presents identically to one that has none — `curl` to the gateway address
  gets nothing, which is exactly what a correct configuration looks like.

  ⚠️ **`-t none` deliberately disables the inbound forwarding Phase 3 wants.**
  That is not an oversight to be repaired when Phase 3 lands. Phase 3 replaces
  it with an explicit `-t <hostport>:<nsport>`, which is a **narrowing** of
  `auto` — one named port instead of every port the tenant chooses to bind —
  and not a re-widening back to the default.

  ⚠️ This function builds a command. That the flags are **passed** is all a
  command-string assertion can show; that they **close the doors** is a
  different claim needing a live namespace, and it belongs to `T012`/`T014`'s
  probe set, not here.
  """
  @spec pasta_command(String.t(), [String.t()], String.t()) :: [String.t()]
  def pasta_command(pidfile, [_ | _] = tenant_command, runas \\ "0") do
    [
      pasta_path(),
      "--config-net",
      "--runas",
      runas,
      "--no-map-gw",
      "-t",
      "none",
      "-T",
      "none",
      "-u",
      "none",
      "-U",
      "none",
      "-P",
      pidfile,
      "--"
    ] ++ tenant_command
  end

  @doc """
  The `--runas` value for a uid, as `pasta` spells it.

  ⚠️ `--runas 0` is correct only when `pasta` runs **as root**. Under the split
  ordering (`LaunchPlan.build/4`) it runs after `setpriv` has already dropped to
  the sandbox uid, and there `--runas 0` fails outright:

      Can't set GID to 0: Operation not permitted

  and `--runas 0:0` **hangs** rather than erroring, which is worse -- a launch
  that never returns rather than one that fails. A matching non-zero
  `uid:gid` pair is the only value measured to work after the drop, and it
  produces `uid_map = 0 <uid> 1` (see `egress-path-measurements.md`).
  """
  @spec runas_for_uid(non_neg_integer()) :: String.t()
  def runas_for_uid(0), do: "0"
  def runas_for_uid(uid) when is_integer(uid) and uid > 0, do: "#{uid}:#{uid}"

  # ⚠️ An **absolute path**, and the bare name `"pasta"` was a real defect
  # (005 T060a).
  #
  # This list becomes the head of `LaunchPlan.tenant_command`, which
  # `NodeLauncher` hands to `:peer` as the program to spawn. `:peer` uses
  # `:erlang.open_port({:spawn_executable, prog}, ...)`, and
  # **`spawn_executable` does no `PATH` lookup** -- it wants a path to a file.
  # With a bare name every policed launch died with:
  #
  #     ** (ErlangError) Erlang error: :enoent:
  #        * 1st argument: invalid port name
  #        :erlang.open_port({:spawn_executable, ~c"pasta"}, ...)
  #
  # ⚠️ Why every probe missed it. `docker/wired-egress-e2e.sh`,
  # `netns-first-e2e.sh` and the rest run the emitted commands **through a
  # shell**, and a shell resolves `PATH`. So the mechanism's own commands were
  # correct everywhere they had been measured, and wrong on the one path that
  # actually launches a tenant. It surfaced only when the conformance suite
  # gained an allowlist and started taking the policed branch -- the permit
  # direction again, which is where every defect in this feature has hidden.
  #
  # `Hardening.Linux.systemd_run_path/0` already resolves its program this way
  # for the same reason; the pasta prefix was added later and missed the rule.
  # The fallback keeps the failure naming a path that was looked for rather than
  # a bare name that says nothing about where it was sought.
  defp pasta_path, do: System.find_executable("pasta") || @pasta_fallback

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
  # ⚠️ **`--preserve-credentials` was REMOVED, and the measurement above is not
  # wrong -- its subject moved.** That measurement was taken against a holder
  # whose user namespace was **root-owned**, which is what `pasta` produced while
  # it wrapped the whole command and therefore ran as root. Under the split
  # ordering (T060a4e) `pasta` runs after `setpriv`, so the namespace it creates
  # is owned by the **sandbox uid**, and carrying our own credentials in lands us
  # there with no capabilities at all:
  #
  #     holder uid: 112526, holder userns: user:[4026534623]
  #     nsenter -t <holder> -n -U --preserve-credentials nft add table ip nat
  #       -> Error: Could not process rule: Operation not permitted   rc=1
  #     nsenter -t <holder> -n -U nft add table ip nat
  #       -> rc=0
  #
  # Without the flag we are remapped to root *inside the target userns*, which is
  # where the `CAP_NET_ADMIN` for `nft` has to come from. The `-U` itself is
  # still load-bearing for the original reason: the netns is a descendant of that
  # userns, so it cannot be joined without joining its owner.
  #
  # ⚠️ **This form is measured to fail from a non-root caller**
  # (`nsenter: setgroups failed: Operation not permitted`), and that matters for
  # `013-FR-006b`, which requires an unprivileged execution plane. It is recorded
  # rather than papered over: the privileged container this runs in today would
  # certify a fix that the unprivileged deployment cannot use, so the remaining
  # gap is a known one with a measurement attached rather than a surprise later.
  defp nsenter(pid, command),
    do: ["nsenter", "-t", "#{pid}", "-n", "-U"] ++ command
end
