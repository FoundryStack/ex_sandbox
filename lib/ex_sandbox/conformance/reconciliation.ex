defmodule ExSandbox.Conformance.Reconciliation do
  @moduledoc """
  Conformance group: what a mechanism must provide for reconciliation to be
  possible at all (003 T022, `FR-015`, `SC-008`, quickstart Scenario 6).

  ## Both directions, and the one that gets left out

  Reconciliation compares the host's registry against reality, and there are two
  ways they can disagree:

    * **recorded running, actually gone** — a sandbox died while the host was
      down. This is the direction everyone implements, because it is the one the
      registry can find by iterating its own rows.

    * **actually running, not recorded** — a sandbox the registry has no row
      for. Nothing in the registry can find this, *because the registry is what
      is missing*. Reaching it requires enumerating the mechanism's own view,
      which is `list_running/0`.

  A reconciler covering only the first direction passes every casual test and
  leaves unrecorded sandboxes running forever. They are the worse kind of leak:
  unattributable, and therefore unbillable and unauditable — nobody is charged
  for them and no audit can say whose code is running.

  `SC-008` is what makes this measurable — recorded status matches reality
  within 60 seconds — and it is unsatisfiable by construction without
  `list_running/0`.

  ## Why this group tests `list_running/0` rather than a reconciler

  The reconciler is host code (`003` T027, an Oban job). A mechanism cannot be
  held to it. What a mechanism *can* be held to is the property the reconciler
  depends on: **`list_running/0` enumerates reality, not the mechanism's own
  bookkeeping.**

  That distinction is the whole check. A mechanism that returns the sandboxes it
  believes it started is trivially consistent with itself and useless for
  reconciliation — the case it must catch is precisely the one where its beliefs
  and reality have diverged, which is when the sandbox died without telling it.
  """

  @doc "Emits the reconciliation checks into the calling test module."
  defmacro tests do
    quote do
      require ExSandbox.Conformance.Group
      import ExSandbox.Conformance.Group, only: [check: 2]

      describe "reconciliation (003-FR-015, SC-008, quickstart Scenario 6)" do
        # Selects this group for `mix test --only conformance:reconciliation`, the
        # invocation quickstart documents. Without it that command matches
        # nothing and reports success.
        @describetag conformance: :reconciliation

        check "list_running enumerates reality, not the mechanism's bookkeeping" do
          # Direction one, at the mechanism level: a sandbox that stopped
          # *without* the mechanism being asked to stop it must drop out of
          # `list_running/0`. This is the post-restart case -- the host was down,
          # the sandbox died, and nothing recorded either fact.
          sandbox = build_sandbox()
          {:ok, provisioned} = ExSandbox.provision(@mechanism, sandbox)
          {:ok, started} = ExSandbox.start(@mechanism, provisioned)
          on_exit(fn -> ExSandbox.destroy(@mechanism, started) end)

          {:ok, while_running} = ExSandbox.list_running(@mechanism)

          assert_guarantee(
            started.mechanism_ref in while_running,
            "003-FR-015",
            "a running sandbox must appear in `list_running/0`; got " <>
              inspect(while_running)
          )

          {:ok, stopped} = ExSandbox.stop(@mechanism, started)
          {:ok, after_stop} = ExSandbox.list_running(@mechanism)

          assert_guarantee(
            stopped.mechanism_ref not in after_stop,
            "003-FR-015",
            """
            A stopped sandbox still appears in `list_running/0`:
            #{inspect(after_stop)}

            The reconciler reads this to decide which recorded-running sandboxes
            are actually gone. A `list_running/0` that reports what the mechanism
            *started* rather than what is *running* is trivially consistent with
            itself and cannot detect the only case it exists for -- a sandbox
            that died without telling anyone.
            """
          )
        end

        check "list_running reports refs that status/1 confirms as running" do
          # The two views must agree, because the reconciler crosses them: it
          # takes a ref from `list_running/0` that has no registry row and has to
          # decide whether to terminate it. A ref that `status/1` does not
          # recognise makes that decision unmakeable -- and terminating on a
          # guess is worse than leaking.
          sandbox = build_sandbox()
          {:ok, provisioned} = ExSandbox.provision(@mechanism, sandbox)
          {:ok, started} = ExSandbox.start(@mechanism, provisioned)
          on_exit(fn -> ExSandbox.destroy(@mechanism, started) end)

          {:ok, running} = ExSandbox.list_running(@mechanism)

          assert_guarantee(
            started.mechanism_ref in running,
            "003-FR-015",
            "a running sandbox must appear in `list_running/0`; got " <> inspect(running)
          )

          # Reconstructed from the ref alone -- which is all the reconciler has
          # for an unrecorded orphan. If the mechanism needs more than its own
          # ref to answer, the second direction is not implementable.
          from_ref = build_sandbox(mechanism_ref: started.mechanism_ref)

          assert_guarantee(
            ExSandbox.status(@mechanism, from_ref) == {:ok, :running},
            "003-FR-015",
            """
            A ref taken from `list_running/0` did not resolve to `:running` via
            `status/1`: #{inspect(ExSandbox.status(@mechanism, from_ref))}

            An unrecorded orphan is known *only* by its ref -- there is no
            registry row to look anything up in. If `status/1` needs more than
            the ref the mechanism itself just handed out, the reconciler cannot
            confirm what it found before terminating it, and terminating on a
            guess is worse than the leak.
            """
          )
        end

        check "list_running does not report a destroyed sandbox" do
          # Direction two's precondition. Every ref in `list_running/0` with no
          # registry row is treated as an orphan and terminated; a mechanism
          # that keeps reporting destroyed sandboxes turns the reconciler into a
          # loop that repeatedly tries to terminate things that are already gone.
          sandbox = build_sandbox()
          {:ok, provisioned} = ExSandbox.provision(@mechanism, sandbox)
          {:ok, started} = ExSandbox.start(@mechanism, provisioned)

          :ok = ExSandbox.destroy(@mechanism, started)
          {:ok, after_destroy} = ExSandbox.list_running(@mechanism)

          assert_guarantee(
            started.mechanism_ref not in after_destroy,
            "003-FR-015",
            "a destroyed sandbox must not appear in `list_running/0`; got " <>
              inspect(after_destroy)
          )
        end

        check "list_running is answerable when nothing is running" do
          # `{:ok, []}` and an error are different answers and the reconciler
          # must act differently on them: an empty list means "terminate every
          # recorded sandbox's row as failed", an error means "do nothing, we
          # cannot see". A mechanism that errors when it has nothing to report
          # would have the reconciler mark every healthy sandbox failed.
          case ExSandbox.list_running(@mechanism) do
            {:ok, refs} when is_list(refs) ->
              :ok

            other ->
              guarantee_failure("003-FR-015", """
              `list_running/0` returned #{inspect(other)} rather than `{:ok, refs}`.

              An empty list and an error mean opposite things to the reconciler:
              "nothing is running, mark the recorded ones failed" versus "we
              cannot see, change nothing". Conflating them either mass-fails
              healthy sandboxes or disables reconciliation entirely.
              """)
          end
        end
      end
    end
  end
end
