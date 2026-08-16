defmodule ExSandbox.Conformance.Credentials do
  @moduledoc """
  Conformance group: a sandbox's credential reaches its own store and nothing
  else (003 T030–T033, `FR-018` – `FR-021`, quickstart Scenario 4).

  ## The load-bearing check is that the credential is *refused* elsewhere

  `013-FR-008` and `013-FR-009` are the claims that make the credential model
  worth having, and both are negative: the credential must fail against another
  sandbox's store and against the platform's. Everything else here is
  supporting.

  A check that merely confirms the role exists, or that the sandbox can reach
  its own database, passes against a credential with **superuser** privileges.
  The grants have to be shown to *restrict*, and the only way to show that is to
  point the credential somewhere it should not reach and watch it be turned
  away. That is why every check below performs the attempt rather than
  inspecting a grant table: a grant that reads correctly and does not apply is
  exactly the defect this group was written after finding.

  ## Reading your own credential is expected to SUCCEED

  Step 1 of Scenario 4, and the check that most often gets written backwards.
  Tenant code can always read its own credential — the application inside the
  sandbox needs it to reach its own database. Containment comes from the
  credential **granting nothing elsewhere**, not from hiding it.

  A suite asserting the read fails is testing concealment, which is not the
  guarantee and cannot be one: any process that can open the connection can
  recover the credential from its own configuration.

  ## The host supplies the probe, because this library has no database concept

  `ex_sandbox` depends on Elixir/OTP and nothing else (`012-FR-001`) — no
  Postgrex, no repo, no notion of a data store at all. So it cannot itself
  attempt a connection, and these checks take a **probe** from the host:

      use ExSandbox.Conformance,
        mechanism: MyMechanism,
        credential_probe: MyApp.CredentialProbe

  The probe implements `ExSandbox.Conformance.Credentials.Probe`. A host that
  supplies none reports `host capability unavailable` for this group — the third
  outcome, distinct from pass and fail (`012-FR-016`). That is **not** an
  exclusion under `012-FR-011`: the consumer cannot request it to skip a check
  it would otherwise fail, it follows from the host genuinely having no data
  store, and it is reported rather than hidden.

  A mechanism with no data store at all is the case this covers honestly. One
  that has a data store and no probe gets a loud "unavailable" rather than a
  quiet pass, which is the distinction that matters.
  """

  defmodule Probe do
    @moduledoc """
    What a host supplies so the credentials group can attempt real connections.

    Every callback performs an act against a **live** store. A probe that
    simulates its answers makes this whole group meaningless, since the
    findings this group exists to catch — a `REVOKE` that returns success while
    revoking nothing, an ACL whose null value means "wide open" — are precisely
    the ones no simulation reproduces.
    """

    @typedoc "An opaque credential, as the host models it."
    @type credential :: term()

    @doc "The credential belonging to this sandbox, as tenant code would read it."
    @callback read_credential(ExSandbox.Sandbox.t()) :: {:ok, credential()} | {:error, term()}

    @doc """
    Attempts `credential` against the store belonging to `sandbox`.

    `{:ok, :connected}` when the connection succeeded, `{:refused, reason}` when
    it was turned away. Anything else is inconclusive and fails the check —
    "could not tell" is not evidence of isolation.
    """
    @callback attempt_connection(credential(), ExSandbox.Sandbox.t()) ::
                {:ok, :connected} | {:refused, term()} | term()

    @doc "Attempts `credential` against the platform's own database (`013-FR-009`)."
    @callback attempt_platform_connection(credential()) ::
                {:ok, :connected} | {:refused, term()} | term()

    @doc """
    Rotates the credential in place, returning the new one.

    `FR-020`: the sandbox must not be rebuilt or destroyed. A probe that
    reprovisions here is answering a different question.
    """
    @callback rotate(ExSandbox.Sandbox.t()) :: {:ok, credential()} | {:error, term()}

    @doc "The secret string that must never appear in a log, record, or inspect."
    @callback secret_value(credential()) :: String.t()
  end

  @doc "Emits the credentials checks into the calling test module."
  defmacro tests do
    quote do
      require ExSandbox.Conformance.Group
      import ExSandbox.Conformance.Group, only: [check: 2]

      describe "credentials (003-FR-018 - FR-021, quickstart Scenario 4)" do
        check "a sandbox can read its own credential" do
          # Scenario 4 step 1, and it must SUCCEED. Written the other way round
          # this asserts concealment, which is neither the guarantee nor
          # achievable: the code that opens the connection necessarily holds the
          # credential.
          probe = ExSandbox.Conformance.Credentials.probe!(@credential_probe)
          sandbox = ExSandbox.Conformance.Credentials.running_sandbox(@mechanism)

          case probe.read_credential(sandbox) do
            {:ok, _credential} ->
              :ok

            other ->
              guarantee_failure("003-FR-018", """
              Tenant code could not read its own credential: #{inspect(other)}

              This check asserts success on purpose. The application inside the
              sandbox needs its credential to reach its own database, and
              containment comes from the credential granting nothing elsewhere
              rather than from hiding it.
              """)
          end
        end

        check "the credential is refused against another sandbox's store" do
          # `013-FR-008`. Scenario 4 steps 2-4, the cross-sandbox half.
          probe = ExSandbox.Conformance.Credentials.probe!(@credential_probe)
          a = ExSandbox.Conformance.Credentials.running_sandbox(@mechanism)
          b = ExSandbox.Conformance.Credentials.running_sandbox(@mechanism)

          {:ok, credential} = probe.read_credential(a)

          require_refused("013-FR-008", fn ->
            case probe.attempt_connection(credential, b) do
              {:refused, reason} -> {:refused, reason}
              {:ok, :connected} -> {:succeeded, "sandbox A's credential opened sandbox B's store"}
              other -> other
            end
          end)
        end

        check "the credential is refused against the platform database" do
          # `013-FR-009` -- the half that was found broken when research R3's
          # SQL was first run against a live server (003 T023/T031 addendum).
          #
          # The cross-sandbox check above passed at the time; this one did not.
          # PostgreSQL grants CONNECT to PUBLIC on every database, and the
          # revokes in R3 only touched databases the provisioner created. The
          # platform's own database was made by the host's migration tooling and
          # so was never covered.
          #
          # The two checks are separate for exactly that reason: they are
          # different databases, created by different things, and passing one
          # says nothing about the other.
          probe = ExSandbox.Conformance.Credentials.probe!(@credential_probe)
          sandbox = ExSandbox.Conformance.Credentials.running_sandbox(@mechanism)
          {:ok, credential} = probe.read_credential(sandbox)

          require_refused("013-FR-009", fn ->
            case probe.attempt_platform_connection(credential) do
              {:refused, reason} ->
                {:refused, reason}

              {:ok, :connected} ->
                {:succeeded, "a sandbox credential opened the platform database"}

              other ->
                other
            end
          end)
        end

        check "the credential reaches its own store" do
          # The positive control. Without it, a credential that reaches nothing
          # at all -- a typo in the role name, a database that was never created
          # -- passes both refusal checks above and looks like perfect isolation.
          probe = ExSandbox.Conformance.Credentials.probe!(@credential_probe)
          sandbox = ExSandbox.Conformance.Credentials.running_sandbox(@mechanism)
          {:ok, credential} = probe.read_credential(sandbox)

          assert_guarantee(
            probe.attempt_connection(credential, sandbox) == {:ok, :connected},
            "003-FR-018",
            """
            A sandbox's own credential did not reach its own store.

            This check exists to keep the two refusal checks honest: a
            credential that reaches nothing passes both of them while providing
            no isolation, only breakage.
            """
          )
        end

        check "rotation issues a new secret without rebuilding the sandbox" do
          # `FR-020`, Scenario 4 step 5. The identity has to survive: rotation
          # that replaces the sandbox is not rotation, it is reprovisioning, and
          # every stack would then have to re-read its configuration at runtime
          # -- a stack assumption Principle VI forbids.
          probe = ExSandbox.Conformance.Credentials.probe!(@credential_probe)
          sandbox = ExSandbox.Conformance.Credentials.running_sandbox(@mechanism)

          {:ok, before} = probe.read_credential(sandbox)
          {:ok, rotated} = probe.rotate(sandbox)

          assert_guarantee(
            probe.secret_value(rotated) != probe.secret_value(before),
            "003-FR-020",
            "rotation returned the same secret, so nothing was rotated"
          )

          assert_guarantee(
            ExSandbox.status(@mechanism, sandbox) != {:ok, :absent},
            "003-FR-020",
            """
            The sandbox is gone after rotating its credential.

            `FR-020` requires rotation leave the sandbox in place. Rebuilding it
            would force every generated application to re-read credentials at
            runtime, which is a stack assumption the mechanism seam must not
            make.
            """
          )

          assert_guarantee(
            probe.attempt_connection(rotated, sandbox) == {:ok, :connected},
            "003-FR-020",
            "the rotated credential does not reach the sandbox's own store"
          )
        end

        check "the secret appears in no log line, record, or inspect output" do
          # `FR-021`, Scenario 4 step 6, and deliberately including a crash.
          # Credentials leak from error paths far more often than from happy
          # ones: an exception formats the whole changeset, and a field that is
          # redacted in the success path but not marked sensitive shows up in
          # full the first time something fails.
          probe = ExSandbox.Conformance.Credentials.probe!(@credential_probe)
          sandbox = ExSandbox.Conformance.Credentials.running_sandbox(@mechanism)
          {:ok, credential} = probe.read_credential(sandbox)
          secret = probe.secret_value(credential)

          assert_guarantee(
            not String.contains?(inspect(credential, limit: :infinity), secret),
            "003-FR-021",
            """
            The secret is visible in `inspect/1` output.

            Whatever carries it must redact on inspect -- an Ash attribute
            marked `sensitive? true`, or a struct with a custom `Inspect`
            implementation. Redacting at each call site instead fails the first
            time someone logs the struct without knowing.
            """
          )

          crash_output =
            ExSandbox.Conformance.Credentials.capture_crash(fn ->
              raise ArgumentError, "deliberate failure carrying #{inspect(credential)}"
            end)

          assert_guarantee(
            not String.contains?(crash_output, secret),
            "003-FR-021",
            """
            The secret appears in crash output:

            #{crash_output}

            The failure paths are where credentials actually leak. A value that
            is redacted in normal formatting and not in exception formatting is
            not redacted.
            """
          )
        end
      end
    end
  end

  @doc false
  # No probe means the host has no data store to probe -- reported as the third
  # outcome rather than passed. `012-FR-016`, and explicitly not an exclusion
  # under `FR-011`: the consumer cannot ask for it, and a host that *does* have
  # a data store gets a loud unavailable rather than a quiet pass.
  def probe!(nil) do
    ExSandbox.Conformance.Helpers.capability_unavailable(
      :credential_probe,
      """
      No `credential_probe:` was supplied to `use ExSandbox.Conformance`.

      This library has no database concept (`012-FR-001`), so it cannot attempt
      a connection on its own. Supply a module implementing
      `ExSandbox.Conformance.Credentials.Probe` to run this group.
      """
    )
  end

  def probe!(module), do: module

  @doc false
  def running_sandbox(mechanism) do
    sandbox = ExSandbox.Conformance.Helpers.build_sandbox()
    {:ok, provisioned} = ExSandbox.provision(mechanism, sandbox)
    {:ok, started} = ExSandbox.start(mechanism, provisioned)
    ExUnit.Callbacks.on_exit(fn -> ExSandbox.destroy(mechanism, started) end)
    started
  end

  @doc false
  # The exception's formatted output, which is what a logger would write.
  def capture_crash(fun) do
    fun.()
    ""
  rescue
    exception -> Exception.format(:error, exception, __STACKTRACE__)
  end
end
