defmodule ExSandbox.Conformance.Network do
  @moduledoc """
  Conformance group: network confinement (005 T060b, T060d; `003-FR-002`,
  `005-FR-003`, `005-FR-011a`–`FR-011d`).

  ## Why this group did not exist, and what its absence cost

  `003-FR-002` says no sandbox may observe or connect to another. Until this
  group, the published contract did not check it. The only network assertion in
  the repository lived in `test/mechanism/beam/isolation_cluster_test.exs` — a
  **mechanism-private** test, shipped with `ex_sandbox`'s own suite rather than
  with the contract a third party runs.

  So a third-party mechanism could implement `ExSandbox.Mechanism`, pass the
  entire published suite, and provide no network isolation whatsoever.
  `012-FR-010`'s promise that the suite is "usable by any mechanism
  implementation" was true of the code and not of the guarantee.

  ## Both directions, because denial alone is not a policy

  The first version of this group would have checked one thing: that a sandbox
  cannot reach what it must not. That check is passed perfectly by a mechanism
  that permits **nothing** — no DNS, no API calls, no webhooks out — which is
  what `--unshare-net` gives today and is not what a tenant application can run
  under (`005-FR-011a`).

  A denial-only suite therefore rewards the wrong mechanism: it scores a
  sandbox that cannot work at all above one that implements a real allowlist,
  because the second has to get the permitted half right and the first has no
  permitted half to get wrong. `FR-011d` requires both directions for this
  reason, and the checks below come in pairs.

  ⚠️ The permitted-direction check reports **capability unavailable**, not
  failure, when the mechanism declares no allowlist. A mechanism that denies
  everything is at an earlier point on the road, not in violation — but it must
  not be able to collect a green tick for the half it never implemented.

  ## The transport must not be the subject

  Every check reaches into the sandbox through `context.exec`, never through
  distribution. Asking "can this sandbox reach the platform?" over `:erpc`
  cannot answer: a refused connection and an unreachable sandbox are both
  `:noconnection`, so the suite cannot tell the boundary holding from the test
  never running.

  This is not hypothetical tidiness. It is the measured failure that
  `isolation_cluster_test.exs` documents at length, and it is why that file
  reaches its sandbox over stdio.
  """

  # Seconds. Long enough that a permitted destination on a loaded host still
  # answers, short enough that three denied destinations do not read as a hang.
  @probe_timeout_s 3

  # Milliseconds. Bounds the whole exec, including a `context.exec` that never
  # returns. Comfortably above @probe_timeout_s so a probe that *does* honour
  # its own bound reports its own result rather than being killed first.
  @exec_timeout_ms 15_000

  # ⚠️ The denied destination used to be RFC 5737 TEST-NET-1 (`203.0.113.1`),
  # chosen because it is documentation-reserved and nominally routable, so a
  # refusal would be evidence of policy. **It was removed, not merely
  # defaulted-over.**
  #
  # `attempt_reach_denied_host/2` gates on a host control probe against the same
  # address, and no operator actually routes TEST-NET-1 -- so the control says
  # `:no` on every host, and the check reported the third outcome permanently.
  # An address that can never demonstrate `FR-011c` anywhere is not a
  # conservative default; it is a check that is guaranteed never to run, which
  # is how it sat passing against `PorousMechanism` for as long as it did.
  #
  # ⚠️ The permit/deny pair, and the two must be **the same kind of address**.
  #
  # `FR-011d` is a claim about the allowlist deciding, so the checks are only
  # meaningful when the sole difference between the permitted and the denied
  # destination is the policy. A permitted address on the open internet paired
  # with a denied address nobody routes compares a live host against a black
  # hole, and the denial is explained by the routing table rather than by the
  # boundary -- which is exactly how this check came to pass against
  # `PorousMechanism`.
  #
  # Both default to addresses measured reachable from the isolation container
  # (`1.1.1.1:443` and `8.8.8.8:53`; `93.184.216.34:443` was measured
  # UNREACHABLE there and would have made the permitted half fail against a
  # correct mechanism). They are overridable because reachability is a fact
  # about a deployment, not about conformance -- a host behind an egress proxy
  # names its own pair rather than reporting a boundary defect.
  @default_permitted {"1.1.1.1", 443}
  @default_denied {"8.8.8.8", 53}

  # ⚠️ The permitted set carries a **hostname as well as an IP literal**, and
  # the second entry is what makes `029-FR-012` visible to this suite at all
  # (029 T004).
  #
  # Until it existed every permitted destination the suite named was a dotted
  # quad, so **name matching was never exercised by construction**: the acceptor
  # reports `SO_ORIGINAL_DST` as an address, `Egress.Policy.permits?/2` compares
  # by equality, and a hostname entry can therefore never match a connection --
  # a defect the whole group ran green over, because no check ever asked a
  # sandbox to reach a destination it knew by name.
  #
  # ⚠️ It must resolve to something **not otherwise in the allowlist**, and this
  # is the trap the first draft fell into. `one.one.one.one` is the obvious
  # hostname for `1.1.1.1` and is exactly wrong: the connection it produces is
  # permitted by the IP entry already present, so the check goes green against a
  # mechanism that never matched a name. `require_permitted_name_reachable/2`
  # reports the third outcome rather than a pass if the name and the literal
  # ever converge -- see the overlap guard there.
  @default_permitted_name {"cloudflare-dns.com", 443}

  # The UDP legs, and the port is 53 for a reason rather than by habit
  # (029 T005, `FR-013`, `SC-003`).
  #
  # `@default_denied` is a DNS server probed over **TCP**, so the group's
  # flagship denial check proves DNS-over-TCP is refused to precisely the host
  # DNS-over-UDP walks out to. The redirect is `meta l4proto tcp` and there is no
  # UDP handling anywhere, so the transport the resolver actually uses has never
  # been attempted from inside a sandbox.
  @udp_loopback {"127.0.0.1", 53}
  @udp_port 53

  # ⚠️ Cached like `@control_key`, and for the same reason: the answer cannot
  # change within a run, and an unanswered datagram costs a full timeout every
  # time it is asked.
  @udp_control_key {__MODULE__, :denied_address_udp_control}

  @doc """
  The destination this run treats as permitted, and the one it treats as denied.

  ⚠️ Both are **configuration, not constants**, because a check gated on
  reachability cannot hardcode what is reachable. `attempt_reach_denied_host/2`
  reports the third outcome wherever the host cannot reach the denied address
  itself, so a deployment whose egress differs from the defaults supplies its
  own pair rather than recording a permanent gap:

      config :ex_sandbox, :conformance,
        permitted_destination: {"example.internal", 443},
        denied_destination: {"blocked.internal", 443}

  They must not overlap, and `denied_address/0` refuses if they do -- an
  allowlist containing the denied destination would make `FR-011c` fail against
  a mechanism doing exactly what it was told.
  """
  @spec permitted_address() :: {String.t(), pos_integer()}
  def permitted_address do
    conformance_config()
    |> Keyword.get(:permitted_destination, @default_permitted)
  end

  @spec denied_address() :: {String.t(), pos_integer()}
  def denied_address do
    denied = Keyword.get(conformance_config(), :denied_destination, @default_denied)

    if denied == permitted_address() do
      raise ArgumentError, """
      the conformance suite's permitted and denied destinations are the same
      address (#{inspect(denied)}).

      `FR-011c` asks that a destination OUTSIDE the allowlist be refused. With
      the two equal, the sandbox is asked to refuse a destination its own
      allowlist permits -- so the check fails against a mechanism enforcing the
      policy correctly, and passes only against one that ignores it.
      """
    end

    denied
  end

  @doc """
  The destination this run treats as permitted **and names by hostname**
  (`029-FR-012`, 029 T004).

  Configurable for the same reason `permitted_address/0` is -- a deployment
  behind an egress proxy names a host it can actually resolve and reach:

      config :ex_sandbox, :conformance,
        permitted_name_destination: {"api.internal", 443}
  """
  @spec permitted_name_address() :: {String.t(), pos_integer()}
  def permitted_name_address do
    conformance_config()
    |> Keyword.get(:permitted_name_destination, @default_permitted_name)
  end

  defp conformance_config, do: Application.get_env(:ex_sandbox, :conformance, [])

  @doc """
  The `context` the group's sandboxes are built with.

  ⚠️ **Opt-in, and the opt-in is a measured admission rather than caution.**

  Carrying a `network_allowlist` is what makes the four checks in this group
  real: `:permitted` is *derived* from it, so without one
  `require_permitted_reachable/2` has nothing to dial and every check reports
  the third outcome. The allowlist is therefore the whole point — and it is off
  by default because on the BEAM mechanism it does not yet work.

  **Measured** (isolation run `2026-08-18T09:37Z-97`, with the allowlist
  unconditionally on): all five checks FAILED with
  `could not provision: {:error, :mechanism_error}`, because a populated
  allowlist makes `NodeLauncher` take the policed branch, and that branch cannot
  currently boot a tenant:

      Couldn't write to /proc/self/uid_map: Operation not permitted
      setpriv: setresuid failed: Invalid argument
      [error] sandbox node failed to boot: {:boot_failed, {:exit_status, 127}}

  `pasta` in spawn mode creates a user namespace it cannot map, so every process
  inside is uid 65534 and `setpriv --reuid` fails for **any** uid. See
  `egress-path-measurements.md`.

  ⚠️ **Why this was a flag and not a silent revert.** The failures above were
  *honest* — the mechanism genuinely could not build the boundary, and the suite
  was right to refuse to report one. But they aborted the credentials phase
  before the isolation phase ran at all, so leaving them on cost every other
  measurement in the census and gave nothing back. The flag kept the capability
  one line away and kept the reason written down, rather than deleting the work
  and rediscovering it.

  ## The default is now ON (T060a4e resolved)

  The blocker above is fixed: `LaunchPlan.build/4` inserts `pasta` **after** the
  privilege drop rather than wrapping the command in it, so `setpriv` runs in
  the host's fully mapped namespace and the tenant boots. Both halves of that
  ordering were measured, not argued (`docker/launch-ordering-probe.sh`): pasta
  composes after the drop (`uid_map = 0 <uid> 1`), and the scope's `MemoryMax`
  still SIGKILLs a 192MB allocation at a 64M cap across **two** intervening
  execs.

  With the launch bootable, the trade reverses. Off is now the setting that
  costs measurement: the checks report the third outcome forever, and the permit
  direction — the only half that can distinguish an allowlist from blanket
  denial — is never exercised. The flag remains, because turning it off is how
  a host that genuinely cannot police egress keeps the rest of the census.

  ⚠️ **It is deliberately NOT an exclusion** (`012-FR-011`). Off, the checks
  report `capability_unavailable` — visible in the census, counted against the
  baseline, and impossible to mistake for a pass. A mechanism gets no credit for
  the checks it does not run.

      config :ex_sandbox, :conformance, allowlist_enabled: false
  """
  @spec suite_context() :: map()
  def suite_context do
    if Keyword.get(conformance_config(), :allowlist_enabled, true) do
      # ⚠️ Two entries, and the hostname is not decoration (029 T004). The IP
      # literal is what `put_permitted`-style derivation picks up for the
      # existing permit check; the hostname is the only reason `FR-012`'s name
      # matching is reachable from this suite at all.
      %{network_allowlist: [permitted_address(), permitted_name_address()]}
    else
      %{}
    end
  end

  # Bounds the host control probe. Deliberately short: it is a discrimination
  # question, not a latency measurement, and it is paid once per run.
  @control_timeout_ms 2_000

  @control_key {__MODULE__, :denied_address_control}

  @doc "Emits the network checks into the calling test module."
  defmacro tests do
    quote do
      require ExSandbox.Conformance.Group
      import ExSandbox.Conformance.Group, only: [check: 2]

      describe "network confinement (003-FR-002, 005-FR-011a-d)" do
        @describetag conformance: :network

        ExSandbox.Conformance.Group.guarded_setup do
          # ⚠️ The suite's sandbox carries a **real allowlist**, and until it did
          # every check in this group reported the third outcome (005 T060a4).
          #
          # `build_sandbox()` set no `context` at all, so no mechanism could
          # publish `:permitted` -- it is derived from the tenant's allowlist --
          # and `require_permitted_reachable/2` had nothing to dial. The
          # derivation was correct and inert: the census read "this mechanism
          # declares no permitted destinations" for a mechanism whose allowlist
          # handling was finished.
          #
          # ⚠️ Ordering matters and is the reason this did not land earlier. A
          # populated allowlist makes `require_permitted_reachable/2` DIAL from
          # inside the sandbox, and a sandbox under `--unshare-net` has no
          # interfaces, so the dial is refused and scores
          # `guarantee_failure("005-FR-011a")` -- "confinement that denies the
          # permitted half is not confinement, it is an outage". Populated
          # before the netns install, this turns an honest
          # `capability_unavailable` into a hard `failed` while the mechanism is
          # unchanged. The suite is right to fail there; the ordering would have
          # been wrong. It is correct now only because the policed launch path
          # exists.
          sandbox = build_sandbox(context: ExSandbox.Conformance.Network.suite_context())

          case ExSandbox.provision(@mechanism, sandbox) do
            {:ok, provisioned} ->
              {:ok, started} = ExSandbox.start(@mechanism, provisioned)
              on_exit(fn -> ExSandbox.destroy(@mechanism, started) end)
              %{sandbox: started}

            {:error, {:capability_unavailable, [missing | _]}} ->
              capability_unavailable(missing.name, missing.detail)

            other ->
              guarantee_failure("003-FR-010", "could not provision: #{inspect(other)}")
          end
        end

        # -- The denied direction ------------------------------------------

        check "reaching another sandbox over the network is refused" do
          other = build_sandbox()
          other = provision_or_report(@mechanism, other)
          {:ok, other} = ExSandbox.start(@mechanism, other)
          on_exit(fn -> ExSandbox.destroy(@mechanism, other) end)

          require_refused("003-FR-002", fn ->
            ExSandbox.Conformance.Network.attempt_reach_sandbox(
              @mechanism,
              var!(context).sandbox,
              other
            )
          end)
        end

        check "every published handle of another sandbox is refused from inside" do
          # `029-FR-017`, 029 T034a. The rule that replaces the structural
          # guarantee, and it is deliberately NOT the check above.
          #
          # The check above asks one question: is `context.address` refused? That
          # is a question about the single handle this suite happens to know. The
          # requirement is about **every** handle the platform publishes for a
          # sandbox -- and 029 Phase 3 is where a sandbox acquires a second one
          # (a host-side tuple, T033) and a third (a public name, T040a) while
          # `context.address` keeps naming the first. A check that probes one
          # handle goes green with the others wide open, which is the shape this
          # phase has already found twice (T012a's unpoliced IPv6, T040a's
          # gateway path).
          #
          # ⚠️ And it is gated on the handle being **live**. The check above
          # currently PASSES against `ExSandbox.EditablePolicyMechanism` because
          # nothing listens at the address it publishes -- `:refused` scored as
          # the boundary holding, which is the hazard T034 names, sitting in the
          # suite today rather than arriving with Phase 3. A refusal means
          # something only where the platform itself reaches the handle.
          other = build_sandbox()
          other = provision_or_report(@mechanism, other)
          {:ok, other} = ExSandbox.start(@mechanism, other)
          on_exit(fn -> ExSandbox.destroy(@mechanism, other) end)

          ExSandbox.Conformance.Network.require_every_peer_handle_refused(
            @mechanism,
            var!(context).sandbox,
            other
          )
        end

        check "reaching the platform's own listening port is refused" do
          # The platform is the highest-value target on the host: it holds the
          # credentials every sandbox is denied, and it is reachable by address
          # without discovery. A sandbox that can open a socket to it has
          # defeated the boundary regardless of what it does next.
          require_refused("003-FR-002", fn ->
            ExSandbox.Conformance.Network.attempt_reach_platform(
              @mechanism,
              var!(context).sandbox
            )
          end)
        end

        check "a destination outside the environment's allowlist is refused" do
          # ⚠️ The address is chosen to be routable-but-denied, not
          # unroutable. Probing a black-hole address passes against a mechanism
          # with no policy at all, because the connection fails for reasons
          # having nothing to do with confinement -- the same shape as asserting
          # a leak was not observed by never looking.
          require_refused("005-FR-011c", fn ->
            ExSandbox.Conformance.Network.attempt_reach_denied_host(
              @mechanism,
              var!(context).sandbox
            )
          end)
        end

        # -- The permitted direction ---------------------------------------

        check "a destination inside the environment's allowlist is reachable" do
          # The half a denial-only mechanism cannot pass, and must not be able
          # to skip quietly. `FR-011a`: a sandbox that cannot reach its
          # permitted destinations cannot run a tenant application, so a
          # mechanism confining by denying everything has not finished.
          ExSandbox.Conformance.Network.require_permitted_reachable(
            @mechanism,
            var!(context).sandbox
          )
        end

        check "a permitted destination named by HOSTNAME is reachable" do
          # `029-FR-012`, 029 T004. The half of the allowlist that no check in
          # this group could see before: every permitted destination the suite
          # named was a dotted quad, so a mechanism that cannot match a name
          # collected a full green group.
          #
          # ⚠️ A **pass** here is the outcome to be suspicious of, not a
          # failure. The measured state of the BEAM mechanism is that
          # `SO_ORIGINAL_DST` arrives as an address and the policy compares by
          # equality, so a name entry cannot match; this check going green means
          # either that matching landed or -- the thing to look at first -- that
          # the connection was permitted by some *other* entry and the name was
          # never consulted.
          ExSandbox.Conformance.Network.require_permitted_name_reachable(
            @mechanism,
            var!(context).sandbox
          )
        end

        check "UDP egress is confined the same as TCP" do
          # `029-FR-013`, `SC-003`, 029 T005. Every other probe in this group is
          # `:gen_tcp`, and the policy this group measures is `meta l4proto tcp`
          # -- so an allowlist a tenant can bypass by choosing a transport has
          # never been attempted here.
          #
          # ⚠️ A datagram coming *back* is the only thing scored as a crossing.
          # Silence is scored as a refusal, which is the conservative direction
          # and a known weakness: a UDP probe that is dropped and a UDP probe
          # nothing was listening for look identical from inside.
          #
          # ⚠️ **The name changed once, and the measurement is why.** This check
          # was `"the host is not reachable over UDP from inside the sandbox"`
          # and attempted exactly the two legs `SC-003` names -- the host's
          # loopback and the namespace gateway. Measured in the isolation
          # harness (run `2026-08-23T05:12:57Z-85`): both legs silent, check
          # GREEN, and the green established nothing at all. Neither address had
          # anything obliged to answer, so "the datagram was dropped" and "the
          # datagram arrived somewhere with no listener" produced the identical
          # result, and the check reported a boundary it had not observed.
          #
          # The denied leg added alongside them is the one with force: it is a
          # real resolver, the environment's allowlist does NOT permit it, and
          # it is gated on the host itself getting an answer from it. So the
          # only outcomes left are a leak (red) and a host that cannot
          # demonstrate either way (the third outcome) -- a green by silence is
          # no longer reachable.
          require_refused("029-FR-013", fn ->
            ExSandbox.Conformance.Network.attempt_udp_egress(
              @mechanism,
              var!(context).sandbox
            )
          end)
        end

        check "the allowlist cannot be widened from inside the sandbox" do
          # `FR-011b`. An allowlist a sandbox can edit is not an allowlist, and
          # this is the check that distinguishes a policy enforced *around* the
          # sandbox from one merely configured *in* it. A mechanism that stores
          # its policy inside the confined filesystem passes every other check
          # in this group and fails this one.
          require_refused("005-FR-011b", fn ->
            ExSandbox.Conformance.Network.attempt_widen_allowlist(
              @mechanism,
              var!(context).sandbox
            )
          end)
        end
      end
    end
  end

  # -- Attempts ---------------------------------------------------------------
  #
  # Each returns `{:refused, evidence}` or `{:succeeded, evidence}`, the shape
  # `require_refused/2` reads. Anything else routes to its inconclusive clause,
  # which fails -- never to a pass.

  @doc """
  Attempts to open a TCP connection from one sandbox to another.

  ⚠️ Addressed by **IP and port**, not by node name. An undistributed sandbox
  has no node name, so a name-based attempt fails for a reason that has nothing
  to do with the network boundary and reports a pass either way.
  """
  def attempt_reach_sandbox(mechanism, sandbox, other) do
    case sandbox_address(mechanism, other) do
      {:ok, {host, port}} ->
        probe_connect(mechanism, sandbox, host, port, "sandbox #{other.id}")

      :unknown ->
        # ⚠️ The third outcome, NOT a contract violation -- and the container run
        # is what made the difference visible.
        #
        # Not a pass, for the reason below: a mechanism that exposes no address
        # would otherwise clear this check by being unaddressable, which is
        # indistinguishable from having no boundary at all.
        #
        # But not a breach either. `FR-011e` makes the handle a declaration a
        # mechanism owes the suite, and an undeclared handle means "this
        # mechanism has not built the boundary yet", which is a different fact
        # from "this mechanism's boundary leaked". Reporting it as a violation
        # sent a reader to look for a defect that is not there -- the BEAM
        # mechanism runs under `--unshare-net` and genuinely has no address to
        # publish until `T060a` gives it one.
        #
        # The census is where this matters: `failed=` gates an exit code and
        # demands investigation, `unavailable=` records a known gap.
        ExSandbox.Conformance.Helpers.capability_unavailable(
          :network_restriction,
          "this mechanism's sandbox `context` carries no `:address` -- " <>
            "`{host, port}` the sandbox listens on -- so one sandbox cannot " <>
            "attempt to reach another and `003-FR-002` cannot be established " <>
            "by declining to try.\n\n" <>
            "This is not a pass: an unaddressable sandbox is indistinguishable " <>
            "from one with no boundary. Populate `context.address` (`FR-011e`)."
        )
    end
  end

  @doc """
  Every handle by which the platform makes `sandbox` reachable from outside it
  (`029-FR-017`, 029 T034a).

  ⚠️ **A declaration the mechanism owes the suite, not something the suite can
  discover.** `FR-011e` already established that shape for `context.address`,
  and the reason is stronger here: the suite cannot enumerate a mechanism's
  publishing surfaces. It cannot know that a container runtime also answers on a
  bridge address and a service name, or that this platform will shortly publish
  a host-side tuple *and* a public hostname for the same sandbox. So the set is
  declared, and a handle the platform publishes but the mechanism does not
  declare is ungoverned by construction.

  Read from `context.peer_handles` — a list of `{host, port}` — falling back to
  `[context.address]` when that is already a dialable tuple, so a mechanism that
  publishes exactly one handle declares nothing extra.

  ⚠️ **Mechanism-neutral on purpose** (D27). Nothing here names a namespace, a
  port forward, a table, or a bridge. A container mechanism declares its
  published port and its runtime-resolvable name; this one declares its netns
  tuple and, after 029 T033, its host-side tuple. The rule survives the transfer
  that D27 says T031 and T032 do not.
  """
  @spec peer_handles(ExSandbox.Sandbox.t() | map()) :: [term()]
  def peer_handles(%{context: context}) when is_map(context) do
    case Map.get(context, :peer_handles) do
      declared when is_list(declared) ->
        declared

      _ ->
        # ⚠️ Only a tuple falls back. The BEAM mechanism publishes
        # `"peer:" <> id` (`beam.ex:582`), deliberately, and turning a string
        # into a handle here would hand `:gen_tcp.connect/4` something it cannot
        # resolve and score the failure as the boundary holding -- the false
        # pass `BeamContextTest` pins out.
        case Map.get(context, :address) do
          {host, port} when is_binary(host) and is_integer(port) -> [{host, port}]
          _ -> []
        end
    end
  end

  def peer_handles(_sandbox), do: []

  @doc """
  Requires that **every** declared handle of `other` is refused from inside
  `sandbox`, and that at least one of them was actually exercised
  (`029-FR-017`).

  ## The three outcomes, and why the middle one is not a pass

  Per handle:

    * the platform cannot reach it → **not exercised**. A refusal from inside is
      not evidence when the destination answers nobody: `EditablePolicyMechanism`
      publishes an address with no listener behind it, and the existing
      peer check passes against it for that reason alone.
    * the platform reaches it and the sandbox does not → **refused**, which is
      the only thing that counts as evidence.
    * the sandbox reaches it → **crossed**, which fails outright.

  Aggregated: any crossing fails; otherwise any refusal passes; otherwise the
  third outcome, naming every handle and why each was not exercised.

  ⚠️ The order is chosen. "Any crossing fails" beats "any refusal passes" so a
  mechanism cannot buy a green tick for one handle while leaking through
  another — which is the entire difference between this check and the one that
  probes `context.address` alone.

  ⚠️ **A mechanism declaring no handle reports the third outcome, never a
  pass.** That is the state today: `FR-017` holds because a sandbox's address is
  unnameable, so there is nothing to attempt, and "the boundary was not
  exercised" is the true statement about it. Scoring it green would be
  `FR-015`'s *control that reads as the guarantee it is not*.
  """
  @spec require_every_peer_handle_refused(module(), ExSandbox.Sandbox.t(), ExSandbox.Sandbox.t()) ::
          :ok
  def require_every_peer_handle_refused(mechanism, sandbox, other) do
    case peer_handles(other) do
      [] ->
        ExSandbox.Conformance.Helpers.capability_unavailable(
          :network_restriction,
          no_peer_handles_detail(other)
        )

      handles ->
        handles
        |> Enum.map(&peer_handle_verdict(mechanism, sandbox, other, &1))
        |> decide_peer_handles(other)
    end
  end

  defp no_peer_handles_detail(other) do
    published =
      case other.context do
        context when is_map(context) -> inspect(Map.get(context, :address))
        _ -> "nothing (the sandbox carries no `context` map)"
      end

    """
    this mechanism declares no dialable handle for a sandbox, so no attempt to
    reach one from another sandbox was made and `029-FR-017` was not exercised.

    `context.peer_handles` is absent and `context.address` is #{published},
    which is not a `{host, port}` this suite can dial.

    This is the third outcome and it is the honest one. `FR-017` is satisfied
    **structurally** while a sandbox's address is unnameable -- nothing enforces
    it, so nothing can fail to -- and a green tick here would report an
    enforcement point that has never refused anything. That is exactly
    `029-FR-015`'s "a control that reads as the guarantee it is not".

    To turn this into a pass, declare `context.peer_handles` as the complete
    list of `{host, port}` the platform publishes for a sandbox, each one
    reachable from the platform itself.
    """
  end

  defp peer_handle_verdict(mechanism, sandbox, other, {host, port} = handle)
       when is_binary(host) and is_integer(port) and port > 0 do
    if platform_reaches?(host, port) do
      case probe_connect(mechanism, sandbox, host, port, "sandbox #{other.id}") do
        {:succeeded, evidence} ->
          {:crossed, handle, evidence}

        {:refused, evidence} ->
          {:refused, handle, evidence}

        other_result ->
          {:not_exercised, handle,
           "the attempt neither crossed nor was refused: #{inspect(other_result)}"}
      end
    else
      {:not_exercised, handle,
       "the platform itself could not open a connection to #{host}:#{port} within " <>
         "#{@control_timeout_ms}ms, so a refusal from inside a sandbox distinguishes " <>
         "nothing -- a dead handle is refused for everyone"}
    end
  end

  defp peer_handle_verdict(_mechanism, _sandbox, _other, handle) do
    {:not_exercised, handle,
     "declared as #{inspect(handle)}, which is not a `{host, port}` with a binary " <>
       "host and a positive integer port, so it cannot be dialled"}
  end

  defp decide_peer_handles(verdicts, other) do
    crossed = for {:crossed, handle, evidence} <- verdicts, do: {handle, evidence}
    refused = for {:refused, handle, _evidence} <- verdicts, do: handle

    cond do
      crossed != [] ->
        tally = "#{length(crossed)} of #{length(verdicts)} published handle(s)"

        ExSandbox.Conformance.Helpers.guarantee_failure("029-FR-017", """
        A sandbox REACHED another sandbox at #{tally}.

        #{Enum.map_join(crossed, "\n", fn {handle, evidence} -> "  #{inspect(handle)}: #{inspect(evidence)}" end)}

        `FR-017` is a rule about every handle the platform publishes, not about
        the one a suite happens to probe. A mechanism that refuses the others
        still fails here, and that is the point: the second handle is how this
        guarantee is lost.
        """)

      refused != [] ->
        :ok

      true ->
        ExSandbox.Conformance.Helpers.capability_unavailable(
          :network_restriction,
          """
          #{length(verdicts)} handle(s) were declared for sandbox #{other.id} and
          not one of them was exercised, so `029-FR-017` was not demonstrated:

          #{Enum.map_join(verdicts, "\n", fn {:not_exercised, handle, why} -> "  #{inspect(handle)}: #{why}" end)}

          This is the third outcome and not a pass. A handle nothing answers on
          is refused for every caller, inside a sandbox or out, so a refusal
          attributes to nothing. `FR-033` requires the same thing from the other
          side: an address is not published until forwarding is proven to work.
          """
        )
    end
  end

  # ⚠️ The control probes the handle from the **platform**, which is the vantage
  # `FR-017` entitles: the gateway has to reach a sandbox, a sibling must not.
  # Same argument as `host_reaches_denied_address?/0` one address over.
  #
  # ⚠️ Deliberately **not cached**, unlike the denied-address control. That one
  # asks about a single fixed address whose answer cannot change within a run;
  # this one asks about a handle belonging to a sandbox that was created for
  # this check and destroyed after it, and ports are recycled. A cache keyed on
  # `{host, port}` would answer about a previous sandbox's listener -- which is
  # `FR-034`'s stale-route defect, reproduced inside the check meant to catch
  # its neighbour.
  defp platform_reaches?(host, port) do
    case :gen_tcp.connect(
           to_charlist(host),
           port,
           [:binary, active: false],
           @control_timeout_ms
         ) do
      {:ok, socket} ->
        :gen_tcp.close(socket)
        true

      {:error, _reason} ->
        false
    end
  end

  @doc "Attempts to reach the platform node's own listening socket."
  def attempt_reach_platform(mechanism, sandbox) do
    case platform_listener() do
      {:ok, {host, port}} ->
        probe_connect(mechanism, sandbox, host, port, "the platform")

      :unknown ->
        {:no_listener,
         "the platform has no listening socket to attempt, so this check " <>
           "cannot establish 003-FR-002 on this host"}
    end
  end

  @doc """
  Attempts to reach a destination the environment does not permit
  (`005-FR-011c`).

  ⚠️ Gated on a **host control probe against this same address**, and the shape
  of that control is the whole correctness of this check.

  The address is documentation-reserved (RFC 5737 TEST-NET-1), chosen because it
  is nominally routable rather than a black hole, so that a refusal would be
  evidence of policy. That reasoning does not survive contact with the internet.

  Measured on a macOS dev host: `nc -z -w 3 203.0.113.1 443` **ignored its own
  bound and blocked for 75 seconds**, so the suite's outer `timeout 3` fired
  first and produced exit 124. Exit 124 is `TIMEDOUT`, which this group
  deliberately scores as a refusal — a probe that ran and saw no answer within
  its bound is exactly what a `DROP` policy looks like from inside.

  Every step is right in isolation, and together they made this check pass
  against `ExSandbox.PorousMechanism`: a mechanism that runs every command in
  the host's own unconfined shell and has no policy whatsoever.

  The first fix attempted here was a general reachability baseline — can the
  host reach the open internet at all? It measured **yes** on this host, and the
  check went on passing. That refuted the diagnosis: TEST-NET-1 is *nominally*
  routable but **nobody actually routes it**, so it is silent for everyone
  regardless of host health. A liveness question about the host cannot detect
  that, because the host is fine.

  So the control probes **this exact address, from the host, outside any
  sandbox**. If the host — subject to no sandbox policy — also sees silence,
  then silence from inside the sandbox distinguishes nothing, and the check
  reports the third outcome. It has force only where the host reaches the
  address and the sandbox does not: the one configuration where the difference
  is attributable to the boundary.

  `012-FR-016a` exists for precisely this: a check that cannot be demonstrated
  here is not a check that passed.
  """
  def attempt_reach_denied_host(mechanism, sandbox) do
    {denied_host, denied_port} = denied_address()

    case host_reaches_denied_address?() do
      :yes ->
        probe_connect(mechanism, sandbox, denied_host, denied_port, "a denied destination")

      :no ->
        ExSandbox.Conformance.Helpers.capability_unavailable(
          :network_restriction,
          """
          this host cannot itself reach #{denied_host}:#{denied_port}, so a
          refused connection from inside the sandbox is not evidence of an egress
          policy.

          A refusal means something only if the same attempt SUCCEEDS from
          outside the sandbox -- otherwise both sides are silent and the boundary
          explains nothing.

          Measured: RFC 5737 TEST-NET-1 is documentation-reserved and nominally
          routable, but in practice no operator routes it, so the probe times out
          for the host too. The suite scores an unanswered probe as a drop, which
          made this check PASS against a mechanism with no network confinement at
          all.

          This is the third outcome and not a pass. Closing it needs a denied
          destination genuinely reachable from the host and denied by policy --
          which the egress work (005 T060a) creates by construction, since the
          allowlist will then be real.
          """
        )
    end
  end

  # ⚠️ The control probes the SAME address the check does, from the host.
  #
  # Two weaker questions were considered and are wrong:
  #
  #   * "Can the host reach the open internet?" -- measured `:yes` on a host
  #     where this check was still passing vacuously. The host was healthy; the
  #     address was unrouted. It answers a question nobody was asking.
  #
  #   * Asking this of a correctly-confined production host -- there the honest
  #     answer may be no, because the host itself sits behind the same egress
  #     policy, and the control would disable the check exactly where it works.
  #     That is a real limitation and it is the right trade: a check that goes
  #     quiet when it cannot discriminate is strictly better than one reporting
  #     a pass it did not earn.
  #
  # `:gen_tcp` rather than a shell: this runs on the host, where the suite has a
  # BEAM and needs no `nc`, and `connect/4`'s timeout is actually honoured --
  # unlike `nc -w`, whose disregard for its own bound is the original defect.
  defp host_reaches_denied_address? do
    case :persistent_term.get(@control_key, :unknown) do
      :unknown ->
        result = measure_control()
        # Cached: the answer cannot change within a run, and an unrouted address
        # costs a full timeout every time it is asked.
        :persistent_term.put(@control_key, result)
        result

      cached ->
        cached
    end
  end

  defp measure_control do
    {denied_host, denied_port} = denied_address()

    case :gen_tcp.connect(
           to_charlist(denied_host),
           denied_port,
           [:binary, active: false],
           @control_timeout_ms
         ) do
      {:ok, socket} ->
        :gen_tcp.close(socket)
        :yes

      {:error, _reason} ->
        :no
    end
  end

  @doc """
  Requires that a permitted destination is actually reachable (`FR-011a`,
  `FR-011d`).

  ⚠️ Reports **capability unavailable** rather than failure when the mechanism
  declares no allowlist. A mechanism that denies everything has not violated
  `FR-011a` so much as not reached it — but the distinction has to be visible,
  because a silent skip here is what lets a deny-everything mechanism collect a
  full green suite while being unable to run any tenant application.
  """
  def require_permitted_reachable(mechanism, sandbox) do
    case permitted_destination(mechanism, sandbox) do
      {:ok, {host, port}} ->
        case probe_connect(mechanism, sandbox, host, port, "a permitted destination") do
          {:succeeded, _evidence} ->
            :ok

          {:refused, evidence} ->
            ExSandbox.Conformance.Helpers.guarantee_failure("005-FR-011a", """
            A destination the environment PERMITS was not reachable from inside
            the sandbox.

            Evidence: #{inspect(evidence)}

            Confinement that denies the permitted half is not confinement, it is
            an outage. `FR-011a` requires the allowlist to be an allowlist: a
            sandbox must be able to reach what its environment declares, or it
            cannot serve a webhook, call an API, or resolve a name.
            """)

          other ->
            ExSandbox.Conformance.Helpers.guarantee_failure("005-FR-011a", """
            Reaching a permitted destination neither succeeded nor was refused:
            #{inspect(other)}
            """)
        end

      :no_allowlist ->
        ExSandbox.Conformance.Helpers.capability_unavailable(
          :network_restriction,
          """
          this mechanism declares no permitted destinations, so the permitted
          half of `FR-011d` cannot be demonstrated.

          This is the third outcome and not a pass. A mechanism that denies all
          egress passes every denial check in this group trivially -- it has no
          permitted half to get wrong -- and a suite that stayed silent here
          would rank it above a mechanism implementing a real allowlist.

          Populate `context.permitted` with `{host, port}` the environment
          permits (005-FR-011a).
          """
        )
    end
  end

  @doc """
  Requires that a permitted destination **named by hostname** is reachable
  (`029-FR-012`).

  ⚠️ Three gates before the probe runs, and each of them exists because the
  obvious version of this check reports something it did not measure:

    1. **The mechanism must declare an allowlist at all.** Without one there is
       no policy for a name to be matched against, and dialling anyway would
       score a mechanism that denies everything.
    2. **The host must itself resolve and reach the name.** Same control as
       `attempt_reach_denied_host/2`: if the host is silent too, silence from
       inside distinguishes nothing.
    3. **The name must not resolve to an address the allowlist already carries
       as a literal.** This is the one that is specific to name matching. If the
       hostname's address is the IP entry the suite also permits, then a
       successful connection is explained by the literal and the name was never
       consulted -- a green tick for a capability that does not exist.
  """
  def require_permitted_name_reachable(mechanism, sandbox) do
    {name, port} = permitted_name_address()

    with :ok <- require_declared_allowlist(mechanism, sandbox),
         :ok <- require_name_distinct_from_literals(name),
         :ok <- require_host_reaches_name(name, port) do
      case probe_connect(mechanism, sandbox, name, port, "a permitted destination named #{name}") do
        {:succeeded, _evidence} ->
          :ok

        {:refused, evidence} ->
          ExSandbox.Conformance.Helpers.guarantee_failure("029-FR-012", """
          A destination the environment PERMITS **by name** was not reachable
          from inside the sandbox, while the host reaches it and the same
          environment reaches a permitted destination named by address.

          Evidence: #{inspect(evidence)}

          `029-FR-012` requires an allowlist entry naming a hostname to match the
          connections that hostname resolves to. Silently denying a permission an
          operator believes they granted is the worst available failure for an
          audit surface -- an entry that cannot work must not be accepted.

          ⚠️ Two distinguishable causes produce this, and both are `FR-012`:
          the name did not resolve **inside** the sandbox (`FR-013` calls a
          working DNS story a precondition for `FR-012` rather than a separate
          nicety), or it resolved and the enforcement point compared the
          resulting address against a string. The evidence above says which:
          a refusal reported by the mechanism's own probe means it got as far
          as connecting.
          """)

        other ->
          ExSandbox.Conformance.Helpers.guarantee_failure("029-FR-012", """
          Reaching a permitted destination by name neither succeeded nor was
          refused: #{inspect(other)}
          """)
      end
    end
  end

  defp require_declared_allowlist(mechanism, sandbox) do
    case permitted_destination(mechanism, sandbox) do
      {:ok, _} ->
        :ok

      :no_allowlist ->
        ExSandbox.Conformance.Helpers.capability_unavailable(
          :network_restriction,
          """
          this mechanism declares no permitted destinations, so there is no
          policy for a hostname entry to be matched against and `029-FR-012`
          cannot be demonstrated.

          This is the third outcome and not a pass.
          """
        )
    end
  end

  # ⚠️ The guard that keeps a green tick honest. Measured reasoning rather than
  # caution: `1.1.1.1` and `one.one.one.one` are the same destination, so a
  # suite permitting both would see the name-based connection permitted by the
  # literal and report name matching as working on a mechanism that compares
  # addresses by equality.
  defp require_name_distinct_from_literals(name) do
    literals =
      [permitted_address(), denied_address()]
      |> Enum.map(fn {host, _port} -> host end)
      |> Enum.flat_map(&resolve_all/1)
      |> MapSet.new()

    resolved = resolve_all(name)

    cond do
      resolved == [] ->
        ExSandbox.Conformance.Helpers.capability_unavailable(
          :network_restriction,
          """
          #{name} does not resolve from this host, so a refusal from inside the
          sandbox says nothing about whether the allowlist matched the name.

          This is the third outcome and not a pass. Name a destination this
          deployment can resolve:

              config :ex_sandbox, :conformance,
                permitted_name_destination: {"api.internal", 443}
          """
        )

      Enum.any?(resolved, &MapSet.member?(literals, &1)) ->
        ExSandbox.Conformance.Helpers.capability_unavailable(
          :network_restriction,
          """
          #{name} resolves to #{inspect(resolved)}, which the suite also names as
          a literal in `permitted_destination` or `denied_destination`.

          A connection to the name would then be decided by the literal entry and
          the name would never be consulted, so a pass here would report name
          matching against a mechanism that only compares addresses. This is the
          third outcome and not a pass -- choose a `permitted_name_destination`
          whose addresses are disjoint from the literals.
          """
        )

      true ->
        :ok
    end
  end

  defp require_host_reaches_name(name, port) do
    case :gen_tcp.connect(
           to_charlist(name),
           port,
           [:binary, active: false],
           @control_timeout_ms
         ) do
      {:ok, socket} ->
        :gen_tcp.close(socket)
        :ok

      {:error, reason} ->
        ExSandbox.Conformance.Helpers.capability_unavailable(
          :network_restriction,
          """
          this host cannot itself reach #{name}:#{port} (#{inspect(reason)}), so a
          refusal from inside the sandbox is not evidence that the allowlist
          failed to match the name -- both sides would be silent and the boundary
          would explain nothing.

          This is the third outcome and not a pass.
          """
        )
    end
  end

  defp resolve_all(host) do
    charlist = to_charlist(host)

    case :inet.parse_address(charlist) do
      {:ok, address} ->
        [address]

      {:error, _} ->
        case :inet.getaddrs(charlist, :inet) do
          {:ok, addresses} -> addresses
          {:error, _} -> []
        end
    end
  end

  @doc """
  Attempts to send UDP datagrams out of the sandbox's namespace
  (`029-FR-013`, `SC-003`, 029 T005).

  Two legs, both named by `SC-003`: the host's loopback as the sandbox sees it,
  and the namespace's gateway. The gateway leg is the one with force -- under
  `pasta` that address is the namespace's own resolver, so an answer from it is
  a datagram that left and came back, which no TCP probe in this group can
  observe because the redirect is `meta l4proto tcp`.

  ⚠️ Requires the mechanism to declare `context.udp_probe`. Without it this
  reports the third outcome rather than guessing, for the same reason
  `attempt_widen_allowlist/2` does: there is no host-neutral way to send a
  datagram from inside someone else's namespace, and a shell probe that could
  not run would score "we did not try" as "the boundary held".
  """
  def attempt_udp_egress(mechanism, sandbox) do
    with {:ok, probe} <- udp_probe(mechanism, sandbox),
         :ok <- require_host_answers_udp(),
         :ok <- require_resolver_answers(probe, sandbox) do
      run_udp_legs(probe, sandbox)
    end
  end

  # ⚠️ The permitted-path control for this check, and it is not optional
  # (029 T015, `FR-013`, `FR-016`).
  #
  # Every remaining leg scores silence as the boundary holding. A namespace
  # with no working network at all is silent on all of them, so without a
  # datagram that IS supposed to come back, this check passes hardest exactly
  # where the sandbox is most broken.
  #
  # The resolver is that datagram: `FR-013` requires one UDP destination a
  # sandbox can reach, so an answer from it is the positive half and silence
  # from it means the negative half establishes nothing.
  #
  # Mechanisms that declare no `:resolver` get the old behaviour rather than a
  # failure -- a sandbox with no name resolution is a legitimate configuration,
  # and its UDP legs are then all denials with no control, which is stated
  # rather than hidden.
  defp require_resolver_answers(probe, sandbox) do
    case declared_resolver(sandbox) do
      {host, port} ->
        case probe.(host, port) do
          :answered ->
            :ok

          other ->
            ExSandbox.Conformance.Helpers.capability_unavailable(
              :network_restriction,
              """
              the sandbox's own resolver at #{host}:#{port} did not answer
              (#{inspect(other)}), so the silence of every other UDP leg
              establishes nothing: a namespace with no working network is
              silent on all of them and would pass this check.

              This is the third outcome and not a pass. `029-FR-013` requires
              exactly one reachable UDP destination, and this check needs it
              back before it can read any other leg's silence as a refusal.
              """
            )
        end

      nil ->
        :ok
    end
  end

  defp declared_resolver(%{context: %{resolver: {host, port}}})
       when is_binary(host) and is_integer(port),
       do: {host, port}

  defp declared_resolver(_sandbox), do: nil

  # ⚠️ The control that stops this check reporting a boundary it never saw, and
  # it is the same control `attempt_reach_denied_host/2` applies to TCP: if the
  # HOST cannot get an answer from the denied resolver either, then silence from
  # inside the sandbox distinguishes nothing and the honest report is the third
  # outcome.
  #
  # Without it the check is green on any host with no route to the internet --
  # which is a plausible CI runner, and exactly the host where a reader would
  # most want to be told that nothing was established.
  defp require_host_answers_udp do
    if host_answers_udp_denied?() == :yes do
      :ok
    else
      {denied_host, denied_port} = denied_address()

      ExSandbox.Conformance.Helpers.capability_unavailable(
        :network_restriction,
        """
        this host gets no UDP answer from #{denied_host}:#{denied_port} either,
        so silence from inside the sandbox says nothing about whether the egress
        policy covers UDP.

        This is the third outcome and not a pass. `029-FR-013` needs a
        destination that answers datagrams on the host and is outside the
        environment's allowlist; without one, the only remaining legs are
        addresses nothing is obliged to answer and their silence is not
        evidence.
        """
      )
    end
  end

  defp host_answers_udp_denied? do
    case :persistent_term.get(@udp_control_key, :unknown) do
      :unknown ->
        result = measure_udp_control()
        :persistent_term.put(@udp_control_key, result)
        result

      cached ->
        cached
    end
  end

  defp measure_udp_control do
    {denied_host, denied_port} = denied_address()

    case :gen_udp.open(0, [:binary, active: false]) do
      {:ok, socket} ->
        verdict = udp_exchange(socket, denied_host, denied_port)
        :gen_udp.close(socket)
        verdict

      {:error, _} ->
        :no
    end
  end

  defp udp_exchange(socket, host, port) do
    with :ok <- :gen_udp.send(socket, to_charlist(host), port, dns_query()),
         {:ok, _} <- :gen_udp.recv(socket, 0, @control_timeout_ms) do
      :yes
    else
      _ -> :no
    end
  end

  # The same `example.com IN A` query the sandbox-side probe sends, and it has
  # to be the same one: a resolver discards a malformed datagram in silence, so
  # a control built from junk bytes would report "this host cannot demonstrate
  # UDP" against a resolver answering perfectly well.
  defp dns_query do
    <<0xAB, 0xCD, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, "example", 3, "com", 0, 0, 1, 0, 1>>
  end

  defp run_udp_legs(probe, sandbox) do
    sandbox
    |> udp_legs()
    |> Enum.reduce_while({:refused, {:no_datagram_returned, :udp}}, fn {host, port}, acc ->
      case probe.(host, port) do
        :answered ->
          {:halt,
           {:succeeded,
            "a UDP datagram sent from inside the sandbox to #{host}:#{port} was " <>
              "ANSWERED -- it left the namespace unpoliced and the reply came back, " <>
              "so the egress policy covers TCP only (029-FR-013)"}}

        :unanswered ->
          {:cont, acc}

        {:sandbox_unreachable, reason} ->
          {:halt,
           {:sandbox_unreachable,
            "the sandbox became unreachable while probing #{host}:#{port} over UDP " <>
              "(#{inspect(reason)}), so nothing was established about the boundary"}}

        other ->
          {:halt,
           {:no_probe,
            "this mechanism's `context.udp_probe` returned #{inspect(other)}, which is " <>
              "not one of :answered | :unanswered, so nothing was established"}}
      end
    end)
  end

  defp udp_probe(_mechanism, %{context: %{udp_probe: probe}}) when is_function(probe, 2),
    do: {:ok, probe}

  defp udp_probe(_mechanism, _sandbox) do
    ExSandbox.Conformance.Helpers.capability_unavailable(
      :network_restriction,
      "this mechanism's sandbox `context` carries no `:udp_probe` -- a " <>
        "2-arity function sending a datagram from inside the sandbox and " <>
        "answering `:answered` or `:unanswered` -- so `029-FR-013` cannot be " <>
        "checked.\n\n" <>
        "It is not enough for the group's TCP probes to be refused: the " <>
        "policy this group measures is `meta l4proto tcp`, so an allowlist a " <>
        "tenant can bypass by choosing a transport would pass every check " <>
        "here. Populate `context.udp_probe` (`FR-011e`)."
    )
  end

  # The loopback leg is host-independent; the gateway leg is only attempted when
  # the mechanism says what its gateway is. Guessing one would dial an address
  # that belongs to nothing and score its silence as a boundary.
  #
  # ⚠️ The denied destination is LAST and it is the only leg that can produce a
  # red. The first two are the addresses `SC-003` names and they are kept
  # because a leak to either would be worth catching -- but neither is obliged
  # to answer, so on their own they can only ever produce silence. See the
  # check's own note for the run that measured exactly that.
  # ⚠️ The sandbox's own resolver is REMOVED from the legs, and leaving it in
  # is a false failure rather than a false pass (029 T015).
  #
  # `@udp_loopback` was written when nothing served `127.0.0.1:53` inside a
  # namespace, so an answer there could only mean the datagram escaped to the
  # host's resolver. Since `FR-013` that address is served on a socket bound
  # inside the namespace by `ExSandbox.Egress.Acceptor`, and an answer means the
  # exemption works.
  # Measured in the isolation image: this leg reported "it left the namespace
  # unpoliced" against a sandbox whose UDP drop was installed and enforcing.
  #
  # It does not vanish from the run -- `require_resolver_answers/2` probes it
  # first, as the control that makes the remaining legs' silence readable.
  defp udp_legs(sandbox) do
    resolver = declared_resolver(sandbox)

    sandbox
    |> all_udp_legs()
    |> Enum.reject(&(&1 == resolver))
  end

  defp all_udp_legs(%{context: %{gateway: gateway}}) when is_binary(gateway),
    do: [@udp_loopback, {gateway, @udp_port}, denied_address()]

  defp all_udp_legs(_sandbox), do: [@udp_loopback, denied_address()]

  @doc """
  Attempts to widen the environment's own allowlist from inside the sandbox
  (`FR-011b`).

  The hostile act is reconfiguration, not connection: tenant code that can edit
  the policy does not need to defeat it.

  Requires the mechanism to declare `context.policy_handle`. Without it the
  check reports the third outcome rather than guessing — see the implementation
  for the two guesses that passed against a mechanism with no policy at all.
  """
  def attempt_widen_allowlist(mechanism, sandbox) do
    # ⚠️ This check asks the mechanism where its policy lives, and reports the
    # third outcome when it does not say. Two earlier versions guessed, and both
    # **passed against `PorousMechanism`** -- a mechanism that runs every command
    # in the host's own unconfined shell and has no policy at all:
    #
    #   1. Reading `/proc/self/net/route` and treating an empty result as "no
    #      egress path to redirect". On macOS the file does not exist, `wc -l`
    #      printed 0, and the absence of a Linux procfs entry scored as a
    #      boundary holding.
    #   2. Running `ip`/`iptables`/`route` and treating a non-zero exit as a
    #      denial. On macOS `route add` exists and fails for lack of root, so a
    #      **permission error** scored as a boundary holding.
    #
    # Both are the same mistake in different clothes: inferring confinement from
    # a failure that confinement did not cause. There is no host-neutral way to
    # tell "the policy is out of reach" from "this shell could not run the tool"
    # without knowing what the policy *is*, so the suite stops guessing and asks.
    #
    # A mechanism that answers gets a real check. One that does not gets the
    # third outcome -- honest, visible in the census, and impossible to mistake
    # for a demonstrated guarantee.
    case policy_handle(mechanism, sandbox) do
      {:ok, handle} ->
        attempt_policy_write(mechanism, sandbox, handle)

      :undeclared ->
        # Third outcome, for the same reason as `:address` above: an undeclared
        # handle is an unfinished mechanism, not a violated guarantee.
        ExSandbox.Conformance.Helpers.capability_unavailable(
          :network_restriction,
          "this mechanism's sandbox `context` carries no `:policy_handle` -- a " <>
            "path naming where the egress allowlist is enforced -- so `FR-011b` " <>
            "cannot be checked.\n\n" <>
            "It is not enough for the widening attempt to fail: on a host " <>
            "without root every attempt fails for reasons having nothing to do " <>
            "with the boundary, and a check that accepted that would pass " <>
            "against a mechanism with no policy at all. Populate " <>
            "`context.policy_handle` (`FR-011e`)."
        )
    end
  end

  defp policy_handle(_mechanism, %{context: %{policy_handle: handle}}) when is_binary(handle),
    do: {:ok, handle}

  defp policy_handle(_mechanism, _sandbox), do: :undeclared

  # The act: append to the mechanism's own policy from inside the sandbox. A
  # policy enforced *around* the sandbox is not writable from within it; one
  # merely configured *in* it is.
  #
  # ⚠️ `test -e` first, and its absence is a **refusal** here rather than
  # inconclusive -- unlike the guesses above, this is the mechanism's own
  # declared path, so "not present inside the sandbox" is a real answer about a
  # real thing rather than an inference from a missing host file.
  defp attempt_policy_write(mechanism, sandbox, handle) do
    command = """
    if [ ! -e '#{handle}' ]; then
      echo ABSENT
    elif echo '203.0.113.0/24' >> '#{handle}' 2>/dev/null; then
      echo WIDENED
    else
      echo DENIED
    fi
    """

    case bounded_exec(mechanism, sandbox, command) do
      {:no_runner, _} = no_runner ->
        no_runner

      :probe_timeout ->
        {:probe_timed_out, "the allowlist-widening attempt did not finish in time"}

      {:ok, output} ->
        cond do
          String.contains?(output, "WIDENED") ->
            {:succeeded,
             "tenant code appended to #{handle} from inside the sandbox; " <>
               "the egress policy is editable by its subject"}

          String.contains?(output, "ABSENT") ->
            {:refused, {:policy_not_visible, handle}}

          String.contains?(output, "DENIED") ->
            {:refused, {:policy_not_writable, handle}}

          true ->
            {:no_probe, "the widening attempt produced no verdict: #{inspect(output)}"}
        end

      {:error, reason} ->
        {:refused, reason}
    end
  end

  # -- Probing ----------------------------------------------------------------

  # ⚠️ The probe runs **inside** the sandbox and reports its own result, rather
  # than the host observing a connection. A host-side observation cannot
  # distinguish "the sandbox was stopped" from "the sandbox never tried".
  #
  # Plain shell, no interpreter assumed: a mechanism's sandbox may carry no
  # Erlang, no Python, and no `nc`.
  #
  # ⚠️ Three verdicts, not two, and `TIMEDOUT` is the one that took two attempts
  # to get right.
  #
  # `nc -z -w N` bounds the *read*, not the connect: against a filtered address
  # on macOS it blocks indefinitely and takes `System.cmd/3` with it. Measured --
  # one denied-destination check ran past ExUnit's 60s test timeout and the whole
  # suite read as a deadlock. So the attempt is wrapped in `timeout` wherever
  # that exists, and exit 124 -- its documented timed-out status -- is reported
  # as `TIMEDOUT` rather than collapsed into `REFUSED`.
  #
  # That distinction is what lets a **drop** count as a refusal (the probe ran
  # and observed no answer within its own bound) while a **hang** stays
  # inconclusive (nothing was observed at all). Without it the suite rewards a
  # `REJECT` policy, which advertises the boundary's existence, over a `DROP`
  # policy, which does not.
  defp probe_connect(mechanism, sandbox, host, port, description) do
    # ⚠️ A mechanism may supply its own connect probe, and for the BEAM
    # mechanism it must. Measured in the isolation container: a BEAM sandbox
    # has a shell but the image carries neither `netcat` nor `iproute2`, and
    # Debian's `/bin/sh` is `dash`, which has no `/dev/tcp` -- that is a bash
    # builtin. Every shell-based probe therefore reported `{:no_probe, _}` and
    # all three denial checks failed as inconclusive.
    #
    # That was the correct verdict for the question asked ("did a connection
    # attempt happen?" -- no) and the wrong question to be asking. A BEAM
    # sandbox can open a socket perfectly well; it just cannot do it through a
    # shell. So the mechanism gets to answer in its own terms, and the shell is
    # the fallback for mechanisms that have no native way to try.
    case native_connect(mechanism, sandbox, host, port, description) do
      :no_native_probe -> shell_connect(mechanism, sandbox, host, port, description)
      result -> result
    end
  end

  # `context.connect` is a 2-arity function taking `{host, port}` and returning
  # `:connected`, `:refused`, or `:timeout` -- the same three verdicts the shell
  # probe produces, for the same reason (`FR-011f`).
  defp native_connect(_mechanism, %{context: %{connect: connect}}, host, port, description)
       when is_function(connect, 2) do
    case connect.(host, port) do
      :connected ->
        {:succeeded, "the sandbox opened a connection to #{description} (#{host}:#{port})"}

      :refused ->
        {:refused, {description, host, port}}

      :timeout ->
        {:refused, {:no_answer_within_bound, description, host, port}}

      # ⚠️ NOT `{:refused, _}`. The sandbox becoming unreachable says nothing
      # about the destination -- and a sandbox that died mid-probe is exactly
      # what a breached resource cap looks like. Scoring it as a refusal would
      # let a crashing mechanism pass every denial check.
      {:sandbox_unreachable, reason} ->
        {:sandbox_unreachable,
         "the sandbox itself became unreachable while probing #{description} " <>
           "(#{inspect(reason)}), so nothing was established about the boundary"}

      other ->
        {:no_probe,
         "this mechanism's `context.connect` returned #{inspect(other)}, which is " <>
           "not one of :connected | :refused | :timeout, so nothing was established"}
    end
  end

  defp native_connect(_mechanism, _sandbox, _host, _port, _description), do: :no_native_probe

  defp shell_connect(mechanism, sandbox, host, port, description) do
    attempt =
      "if command -v nc >/dev/null 2>&1; then " <>
        "nc -z -w #{@probe_timeout_s} #{host} #{port}; " <>
        "else exec 3<>/dev/tcp/#{host}/#{port}; fi"

    command = """
    if ! command -v nc >/dev/null 2>&1 && [ -z "$BASH_VERSION" ]; then
      echo NOPROBE
    else
      if command -v timeout >/dev/null 2>&1; then
        timeout #{@probe_timeout_s} sh -c '#{attempt}' >/dev/null 2>&1
      else
        sh -c '#{attempt}' >/dev/null 2>&1
      fi
      case "$?" in
        0)   echo CONNECTED ;;
        124) echo TIMEDOUT ;;
        *)   echo REFUSED ;;
      esac
    fi
    """

    case bounded_exec(mechanism, sandbox, command) do
      {:no_runner, _} = no_runner ->
        no_runner

      :probe_timeout ->
        # ⚠️ The outer bound means the probe never reported at all, which is
        # different from the probe reporting that it timed out. Reaching here,
        # nothing about the boundary was observed -- inconclusive, which
        # `require_refused/2` fails.
        {:probe_timed_out,
         "the connection attempt to #{description} (#{host}:#{port}) produced no " <>
           "result within #{@exec_timeout_ms}ms -- not even a timeout verdict from " <>
           "the probe itself, so nothing about the boundary was observed."}

      {:ok, output} ->
        cond do
          String.contains?(output, "CONNECTED") ->
            {:succeeded, "the sandbox opened a connection to #{description} (#{host}:#{port})"}

          String.contains?(output, "REFUSED") ->
            {:refused, {description, host, port}}

          # A probe that ran and got no answer within its own bound: what a DROP
          # policy looks like from inside.
          String.contains?(output, "TIMEDOUT") ->
            {:refused, {:no_answer_within_bound, description, host, port}}

          true ->
            # ⚠️ Deliberately neither. A sandbox with no way to attempt a
            # connection has demonstrated nothing, and returning `{:refused, _}`
            # here would score "we could not try" as "the boundary held" -- the
            # precise substitution `require_refused/2` exists to prevent.
            {:no_probe,
             "no connection probe is available inside this sandbox " <>
               "(neither `nc` nor a shell with /dev/tcp), so reaching " <>
               "#{description} was never attempted"}
        end

      {:error, reason} ->
        {:refused, reason}
    end
  end

  # -- What the mechanism has to tell us --------------------------------------

  defp sandbox_address(_mechanism, %{context: %{address: {host, port}}}), do: {:ok, {host, port}}
  defp sandbox_address(_mechanism, _sandbox), do: :unknown

  defp permitted_destination(_mechanism, %{context: %{permitted: {host, port}}}),
    do: {:ok, {host, port}}

  defp permitted_destination(_mechanism, _sandbox), do: :no_allowlist

  # The platform's own listener, if it has one. Read from the running system
  # rather than assumed: a hardcoded port answers about a socket that may not
  # exist, and a failed connection to nothing looks exactly like a boundary.
  defp platform_listener do
    case :inet.getaddr(~c"127.0.0.1", :inet) do
      {:ok, _} ->
        case :erlang.ports() |> Enum.find_value(&listening_port/1) do
          nil -> :unknown
          port -> {:ok, {"127.0.0.1", port}}
        end

      _ ->
        :unknown
    end
  end

  defp listening_port(port) do
    case :inet.port(port) do
      {:ok, n} when is_integer(n) and n > 0 -> n
      _ -> nil
    end
  rescue
    _ -> nil
  catch
    _, _ -> nil
  end

  # ⚠️ The timeout lives **here**, not in the shell command, and the first
  # version of this got that wrong.
  #
  # `nc -z -w 3` bounds the *read* phase, not the connect: against a filtered
  # address on macOS it blocks indefinitely, and `System.cmd/3` blocks with it.
  # Measured -- a single denied-destination check ran past ExUnit's 60s test
  # timeout and the whole suite read as a deadlock.
  #
  # A mechanism's `context.exec` is supplied by the mechanism and carries no
  # timeout guarantee, so the suite cannot delegate the bound to it. Running it
  # in a task the suite can abandon is the only place the bound holds for every
  # mechanism.
  defp bounded_exec(mechanism, sandbox, command) do
    task = Task.async(fn -> exec(mechanism, sandbox, command) end)

    case Task.yield(task, @exec_timeout_ms) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> result
      _ -> :probe_timeout
    end
  end

  # Same contract as the isolation group's: a mechanism reaches its sandbox
  # through `context.exec`, and having none is inconclusive rather than a pass.
  defp exec(_mechanism, %{context: %{exec: exec}}, command) when is_function(exec, 1) do
    exec.(command)
  end

  defp exec(_mechanism, _sandbox, _command) do
    {:no_runner,
     "this mechanism's sandbox `context` carries no `:exec` function, so no " <>
       "network act can be attempted from inside the sandbox -- and a network " <>
       "boundary is established by attempting to cross it, never by declining " <>
       "to. Populate `context.exec` with a 1-arity function running a shell " <>
       "command inside the sandbox and returning `{:ok, output}` or " <>
       "`{:error, reason}`."}
  end
end
