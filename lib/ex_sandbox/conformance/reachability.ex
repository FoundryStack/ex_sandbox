defmodule ExSandbox.Conformance.Reachability do
  @moduledoc """
  Conformance group: the states a request to a sandbox can land in
  (003 T021, `FR-022` – `FR-024`, quickstart Scenario 5).

  ## Six outcomes, and why none may collapse

  `006-domain-routing` is the consumer of this. When a request arrives for a
  sandbox that is not serving, it has to choose between three different actions
  — start it on demand, wait, or report a fault — and the choice is made
  entirely from what `status/1` said.

  | State | What `006` does |
  |---|---|
  | `:running` | proxy the request |
  | `:stopped` | start on demand, then proxy |
  | `:provisioned` | still being built — wait, do not start |
  | `:starting` | a start is already in flight — wait, do not start a second |
  | `:unknown` | report a fault; do **not** act on a guess |
  | `:absent` | 404 — there is nothing to start |

  Any two of those collapsing produces a wrong action, not a vaguer one:

    * `:stopped` collapsed into `:provisioned` means a stopped sandbox is never
      started, and the request hangs until it times out.
    * `:starting` collapsed into `:stopped` means every concurrent request
      launches its own start — the double-provision of `FR-010`, arriving one
      layer up.
    * `:absent` collapsed into `:unknown` turns a definite 404 into a retry loop
      against a sandbox that will never exist.

  **The caller cannot recover information the callee discarded.** That is the
  whole reason this is a conformance check rather than a documentation note: a
  mechanism reporting `{:ok, :unknown}` for everything satisfies the *type* on
  every call, and every check that merely pattern-matches the shape passes it.

  ## `:starting` is a state, not a flag

  `FR-024` names it explicitly. A boolean `starting?` alongside `:stopped` would
  encode the same information and is the shape that tends to get written,
  because "starting" feels like a modifier on "not running". It is not: a
  sandbox that is starting must not be started again, and a sandbox that is
  stopped must be — opposite actions, so they are different states.
  """

  @doc "Emits the reachability checks into the calling test module."
  defmacro tests do
    quote do
      require ExSandbox.Conformance.Group
      import ExSandbox.Conformance.Group, only: [check: 2]

      describe "reachability (003-FR-022 - FR-024, quickstart Scenario 5)" do
        # Selects this group for `mix test --only conformance:reachability`, the
        # invocation quickstart documents. Without it that command matches
        # nothing and reports success.
        @describetag conformance: :reachability

        check "a running sandbox reports :running and carries an address" do
          sandbox = build_sandbox()
          {:ok, provisioned} = ExSandbox.provision(@mechanism, sandbox)
          {:ok, started} = ExSandbox.start(@mechanism, provisioned)
          on_exit(fn -> ExSandbox.destroy(@mechanism, started) end)

          assert_guarantee(
            ExSandbox.status(@mechanism, started) == {:ok, :running},
            "003-FR-024",
            "a started sandbox must report `:running`; got " <>
              inspect(ExSandbox.status(@mechanism, started))
          )

          # FR-022: an address, and it must come back from `start/1` rather than
          # being derived by the caller. Research on `start/1` established the
          # address may differ between runs, so a caller that computes it
          # instead of reading it sends traffic to the previous one.
          assert_guarantee(
            ExSandbox.Conformance.Reachability.addressed?(started),
            "003-FR-022",
            """
            A running sandbox has no recorded address: #{inspect(started.context)}

            `start/1` must return the address at which the sandbox can be
            reached. It is returned rather than derived because it may differ
            between runs -- a caller that computes it from the sandbox id sends
            traffic to wherever the previous run happened to land.
            """
          )
        end

        check "a provisioned-but-never-started sandbox does not report :running" do
          sandbox = build_sandbox()
          {:ok, provisioned} = ExSandbox.provision(@mechanism, sandbox)
          on_exit(fn -> ExSandbox.destroy(@mechanism, provisioned) end)

          {:ok, status} = ExSandbox.status(@mechanism, provisioned)

          assert_guarantee(
            status == :provisioned,
            "003-FR-024",
            """
            A sandbox that was provisioned but never started reported
            #{inspect(status)} rather than `:provisioned`.

            `006` distinguishes this from `:stopped` to decide whether to start
            on demand: a stopped sandbox should be started, one still being
            built should be waited for. Reporting `:running` is worse still --
            traffic is proxied to something that is not listening.
            """
          )
        end

        check "a stopped sandbox is distinguishable from one still provisioning" do
          sandbox = build_sandbox()
          {:ok, provisioned} = ExSandbox.provision(@mechanism, sandbox)
          {:ok, before_start} = ExSandbox.status(@mechanism, provisioned)

          {:ok, started} = ExSandbox.start(@mechanism, provisioned)
          {:ok, stopped} = ExSandbox.stop(@mechanism, started)
          on_exit(fn -> ExSandbox.destroy(@mechanism, stopped) end)

          {:ok, after_stop} = ExSandbox.status(@mechanism, stopped)

          assert_guarantee(
            after_stop == :stopped,
            "003-FR-024",
            "a stopped sandbox must report `:stopped`; got " <> inspect(after_stop)
          )

          # The check that actually matters: not what either state is named, but
          # that they are not the same value. A mechanism reporting `:stopped`
          # for both satisfies the assertion above and still leaves `006` unable
          # to tell "start this" from "wait for this".
          assert_guarantee(
            before_start != after_stop,
            "003-FR-024",
            """
            "still provisioning" and "stopped" both reported #{inspect(after_stop)}.

            These call for opposite actions -- wait, versus start on demand --
            and `006` chooses between them from this value alone. The caller
            cannot recover information the callee discarded.
            """
          )
        end

        check "a nonexistent sandbox reports :absent, distinct from :unknown" do
          # Never provisioned: the mechanism has no record of this id at all.
          sandbox =
            build_sandbox(
              mechanism_ref: "never-provisioned-#{System.unique_integer([:positive])}"
            )

          case ExSandbox.status(@mechanism, sandbox) do
            {:ok, :absent} ->
              :ok

            {:ok, :unknown} ->
              guarantee_failure("003-FR-024", """
              A sandbox that was never provisioned reported `:unknown`.

              `:unknown` means "we could not determine", which makes the request
              a retry candidate. This sandbox does not exist and never will, so
              the correct outcome is a definite `:absent` -- a 404 rather than a
              retry loop.
              """)

            {:ok, other} ->
              guarantee_failure(
                "003-FR-024",
                "a sandbox that was never provisioned reported #{inspect(other)}"
              )

            other ->
              guarantee_failure("003-FR-024", "status/1 returned #{inspect(other)}")
          end
        end

        check "the mechanism reports more than one distinct state" do
          # The blunt one, and the only check here that a mechanism returning a
          # single constant cannot pass. Each check above asserts one state; a
          # mechanism answering `{:ok, :running}` unconditionally fails those
          # individually, but a mechanism answering `{:ok, :unknown}`
          # unconditionally could be argued into "never determinable". This
          # says: then it has told `006` nothing, on every call.
          sandbox = build_sandbox()
          {:ok, provisioned} = ExSandbox.provision(@mechanism, sandbox)
          {:ok, s1} = ExSandbox.status(@mechanism, provisioned)

          {:ok, started} = ExSandbox.start(@mechanism, provisioned)
          {:ok, s2} = ExSandbox.status(@mechanism, started)

          :ok = ExSandbox.destroy(@mechanism, started)
          {:ok, s3} = ExSandbox.status(@mechanism, started)

          observed = Enum.uniq([s1, s2, s3])

          assert_guarantee(
            length(observed) >= 3,
            "003-FR-024",
            """
            Provisioned, running, and destroyed produced #{length(observed)}
            distinct status value(s): #{inspect(observed)}

            FR-024 requires six outcomes stay distinguishable. A mechanism whose
            `status/1` answers the same thing regardless of what the sandbox is
            doing satisfies the callback's type on every call and tells `006`
            nothing on any of them.
            """
          )
        end
      end
    end
  end

  @doc false
  # An address is mechanism-shaped -- a port, a socket path, a node name -- so
  # the suite cannot assert its form without assuming a mechanism (Principle VI).
  # It asserts only that one was recorded somewhere the caller can reach: the
  # requirement is that `start/1` *hands the address back*, not what it looks
  # like.
  def addressed?(%ExSandbox.Sandbox{context: context}) do
    case context do
      %{address: address} -> address not in [nil, ""]
      _ -> false
    end
  end
end
