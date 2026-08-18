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

  defp conformance_config, do: Application.get_env(:ex_sandbox, :conformance, [])

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
          sandbox =
            build_sandbox(
              context: %{
                network_allowlist: [ExSandbox.Conformance.Network.permitted_address()]
              }
            )

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
