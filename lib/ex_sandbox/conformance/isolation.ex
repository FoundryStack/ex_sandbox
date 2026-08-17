defmodule ExSandbox.Conformance.Isolation do
  @moduledoc """
  Conformance group: isolation (012 T031; `003` quickstart Scenario 1).

  ## Every check here performs the hostile act

  This is the group's defining constraint, and the one that makes it worth
  writing at all. The natural way to write an isolation test is to run something
  ordinary and assert nothing leaked:

      {:ok, out} = run(sandbox, "echo hello")
      refute out =~ "DATABASE_URL"

  That passes against a mechanism with **no isolation whatsoever**, because
  nothing ever went looking for `DATABASE_URL`. It is not a weak test; it is not
  a test. Constitution *Isolation Review* is explicit that an isolation claim is
  established by attempting the breach.

  So each check below reaches for something it must not be able to have —
  platform credentials, another sandbox's filesystem, the host's process table,
  its own supervisor — and requires that the attempt was **refused**.

  ## The inconclusive case is a failure here, not a skip

  Unlike `ExSandbox.Conformance.ResourceLimits`, there is no host capability that
  could legitimately prevent *attempting* these acts. A mechanism that cannot
  run the hostile act at all cannot show that it isolates, so
  `require_refused/2` treats "neither refused nor succeeded" as a failure.
  """

  @doc "Emits the isolation checks into the calling test module."
  defmacro tests do
    quote do
      require ExSandbox.Conformance.Group
      import ExSandbox.Conformance.Group, only: [check: 2]

      describe "isolation (003 quickstart Scenario 1, Constitution Isolation Review)" do
        # Selects this group for `mix test --only conformance:isolation`, the
        # invocation quickstart documents. Without it that command matches
        # nothing and reports success.
        @describetag conformance: :isolation

        # ⚠️ `guarded_setup`, not a bare `setup` (T043a). `check/2`'s rescue wraps
        # the test body only, so a capability gap raised while provisioning here
        # escaped without the "third outcome" framing -- reported as a plain
        # exception, indistinguishable at a glance from a mechanism defect.
        ExSandbox.Conformance.Group.guarded_setup do
          sandbox = build_sandbox()

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

        check "reading the platform's own credentials from inside is refused" do
          # The specific secret matters: it is one the *host* holds and the
          # sandbox must never see. Naming it makes the act hostile rather than
          # incidental.
          require_refused("003-FR-006", fn ->
            ExSandbox.Conformance.Isolation.attempt_read_platform_secret(
              @mechanism,
              var!(context).sandbox
            )
          end)
        end

        check "reading another sandbox's filesystem is refused" do
          other = build_sandbox()
          other = provision_or_report(@mechanism, other)
          {:ok, other} = ExSandbox.start(@mechanism, other)
          on_exit(fn -> ExSandbox.destroy(@mechanism, other) end)

          require_refused("003-FR-006", fn ->
            ExSandbox.Conformance.Isolation.attempt_cross_sandbox_read(
              @mechanism,
              var!(context).sandbox,
              other
            )
          end)
        end

        check "halting the host from inside the sandbox is refused" do
          # ⚠️ Probes deliverability rather than delivering. Actually killing
          # the platform would prove the point and destroy the report that
          # makes the point useful.
          require_refused("003-FR-006", fn ->
            ExSandbox.Conformance.Isolation.attempt_self_halt(@mechanism, var!(context).sandbox)
          end)
        end

        check "enumerating host processes from inside is refused" do
          require_refused("003-FR-006", fn ->
            ExSandbox.Conformance.Isolation.attempt_host_process_list(
              @mechanism,
              var!(context).sandbox
            )
          end)
        end

        check "an opaque owner_ref survives the round trip unparsed" do
          # FR-007: the mechanism stores and propagates owner_ref, never parses
          # it. A value with structure the mechanism might be tempted to read.
          hostile = "tenant:../../etc/passwd\0 ' OR 1=1"
          sandbox = build_sandbox(owner_ref: hostile)

          provisioned = provision_or_report(@mechanism, sandbox)
          on_exit(fn -> ExSandbox.destroy(@mechanism, provisioned) end)

          assert_guarantee(
            provisioned.owner_ref == hostile,
            "003-FR-006",
            "the mechanism altered `owner_ref` from #{inspect(hostile)} to " <>
              inspect(provisioned.owner_ref) <>
              ". It is opaque: stored, " <>
              "compared, propagated -- never parsed (012 FR-007)."
          )
        end
      end
    end
  end

  @doc """
  Attempts to read a secret only the host holds.

  Returns `{:succeeded, value}` if the sandbox got it — an isolation failure —
  or `{:refused, reason}` if it could not.
  """
  def attempt_read_platform_secret(mechanism, sandbox) do
    secret = "axonn-conformance-secret-" <> Integer.to_string(System.unique_integer([:positive]))
    System.put_env("AXONN_CONFORMANCE_SECRET", secret)

    try do
      case exec(mechanism, sandbox, "printenv AXONN_CONFORMANCE_SECRET") do
        {:no_runner, _} = no_runner ->
          no_runner

        {:ok, output} ->
          if String.contains?(output, secret) do
            {:succeeded, "the host's AXONN_CONFORMANCE_SECRET was readable inside the sandbox"}
          else
            {:refused, :not_visible}
          end

        {:error, reason} ->
          {:refused, reason}
      end
    after
      System.delete_env("AXONN_CONFORMANCE_SECRET")
    end
  end

  @doc "Attempts to read a file belonging to a different sandbox."
  def attempt_cross_sandbox_read(mechanism, sandbox, other) do
    marker = "cross-sandbox-" <> other.id

    with {:ok, _} <- exec(mechanism, other, "echo #{marker} > /tmp/marker"),
         {:ok, output} <- exec(mechanism, sandbox, "cat /tmp/marker") do
      if String.contains?(output, marker) do
        {:succeeded, "sandbox #{sandbox.id} read sandbox #{other.id}'s /tmp/marker"}
      else
        {:refused, :not_visible}
      end
    else
      {:no_runner, _} = no_runner -> no_runner
      {:error, reason} -> {:refused, reason}
    end
  end

  @doc """
  Attempts to bring down the host from inside the sandbox.

  ⚠️ The verdict is the **signal's** outcome, not whether this process is still
  running. See the implementation: the obvious liveness check cannot fail.
  """
  def attempt_self_halt(mechanism, sandbox) do
    # ⚠️ The target is the **platform's own OS process**, not pid 1, and both
    # earlier targets were wrong in ways that made this check unable to fail.
    #
    #   1. Original: `kill -9 1`, then `host_alive?()` defined as
    #      `Process.alive?(self())`. A process cannot observe its own death, so
    #      that expression is `true` by construction and the check returned
    #      `{:refused, :host_survived}` on every path.
    #   2. Second attempt: `kill -9 1` judged by its exit status. Better, but
    #      pid 1 is unsignallable by an unprivileged user on any host, so it is
    #      refused by the OS for everyone -- `PorousMechanism`, which runs
    #      unconfined in the host's own shell, was refused exactly as a confined
    #      sandbox would be. The check passed against a mechanism that isolates
    #      nothing.
    #
    # Both hid behind the broken `SuiteRunner`, which never ran the group's
    # `setup` -- every check died on `KeyError` first, and the meta-test read
    # that crash as the failure it was looking for.
    #
    # The platform's own OS pid is the target that separates the two cases. An
    # unconfined process on the same host **can** signal it: same uid, same pid
    # namespace. A confined sandbox cannot -- it is in a different pid namespace
    # where that number is meaningless or absent, and under a different uid.
    #
    # `kill -0` probes deliverability without sending anything. The distinction
    # this check exists to draw is whether the sandbox *could* reach the
    # platform, and actually killing the test runner to prove it would take the
    # report down with it.
    platform_pid = System.pid()

    case exec(mechanism, sandbox, "kill -0 #{platform_pid} 2>&1; echo rc=$?") do
      {:no_runner, _} = no_runner ->
        no_runner

      {:ok, output} ->
        if String.contains?(output, "rc=0") do
          {:succeeded,
           "the sandbox can signal the platform's own OS process (pid " <>
             "#{platform_pid}). `kill -0` succeeding means a real signal would " <>
             "be delivered: the sandbox shares the platform's pid namespace and " <>
             "uid, and can terminate the process supervising it."}
        else
          {:refused, {:signal_undeliverable, String.trim(output)}}
        end

      {:error, reason} ->
        {:refused, reason}
    end
  end

  @doc "Attempts to enumerate the host's process table from inside."
  def attempt_host_process_list(mechanism, sandbox) do
    case exec(mechanism, sandbox, "ps -e -o comm=") do
      {:no_runner, _} = no_runner ->
        no_runner

      {:ok, output} ->
        lines = output |> String.split("\n", trim: true) |> length()

        # A confined pid namespace shows a handful of processes; a host's table
        # shows dozens. The threshold is coarse because the distinction is.
        if lines > 30 do
          {:succeeded, "#{lines} processes visible -- this is the host's process table"}
        else
          {:refused, {:confined_process_table, lines}}
        end

      {:error, reason} ->
        {:refused, reason}
    end
  end

  # A mechanism exposes no `exec` callback -- running code inside a sandbox is
  # 009-stack-adapters' concern. The suite reaches it through the sandbox's
  # `context`, which a mechanism may populate with a runner for exactly this.
  # Absent one, the hostile act cannot be attempted, and require_refused/2
  # treats that as a failure rather than a pass.
  defp exec(_mechanism, %{context: %{exec: exec}}, command) when is_function(exec, 1) do
    exec.(command)
  end

  defp exec(_mechanism, _sandbox, _command) do
    # NOT `{:error, _}`. `require_refused/2` reads `{:refused, reason}` as a
    # pass, and every `{:error, reason}` below becomes one -- so a mechanism
    # with no runner at all would pass every isolation check by never
    # attempting anything. This distinct shape falls through to the
    # inconclusive clause, which fails.
    {:no_runner,
     "this mechanism's sandbox `context` carries no `:exec` function, so the " <>
       "hostile act cannot be attempted -- and an isolation claim is established " <>
       "by attempting the breach, never by declining to. Populate `context.exec` " <>
       "with a 1-arity function running a shell command inside the sandbox and " <>
       "returning `{:ok, output}` or `{:error, reason}`."}
  end
end
