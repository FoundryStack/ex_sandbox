defmodule ExSandbox.Conformance.Lifecycle do
  @moduledoc """
  Conformance group: the sandbox lifecycle (012 T032; `003-FR-010`, `003-FR-013`).

  Provision → start → stop → destroy, plus the two cases that are easy to get
  wrong and cheap to get right:

    * **concurrent double-provision resolves to one sandbox** (`003-FR-010`).
      Two requests for the same sandbox id arriving together must not produce
      two sandboxes; one of them is a leak nothing will ever clean up, because
      the host records only one.

    * **a second destroy returns `:ok`** (`003-FR-013`). Cleanup runs from
      crash-recovery sweeps, which by their nature run against sandboxes that
      may already be gone. A destroy that errors on "already gone" makes every
      sweep a source of spurious failures, and the usual response to that is to
      stop running the sweep.

  ## The three checks `003` T018–T020 added

  `012` built this group around the mechanism callbacks. `003` covers the rest
  of quickstart Scenario 3, and the additions are the steps most easily skipped
  because none of them is on the happy path:

    * **step 3 — a missing template fails naming the template** (`003-FR-027`).
      The distinguishable-cause requirement, at the one point where the generic
      error is most tempting: provisioning fails for many reasons and they all
      arrive as `{:error, _}`.

    * **step 4 — a mid-provision failure leaves zero orphans** (`003-SC-006`),
      verified by **enumerating `list_running/0`** rather than by inspecting the
      cleanup code. `SC-006` is a claim about *unanticipated* failures; a check
      that trusts the compensation path can only confirm the paths its author
      thought of, which is the same set the compensation already handles.

    * **step 5 — data survives a stop/start cycle**. A mechanism that
      reprovisions from the template on `start/1` passes every other check in
      this group: it starts, it reports `:running`, it appears in
      `list_running/0`. The only observable difference is that the tenant's data
      is gone.
  """

  @doc "Emits the lifecycle checks into the calling test module."
  defmacro tests do
    quote do
      require ExSandbox.Conformance.Group
      import ExSandbox.Conformance.Group, only: [check: 2]

      describe "lifecycle (003-FR-010, 003-FR-013)" do
        # Selects this group for `mix test --only conformance:lifecycle`, the
        # invocation quickstart documents. Without it that command matches
        # nothing and reports success.
        @describetag conformance: :lifecycle

        check "provision, start, stop, destroy in sequence" do
          sandbox = build_sandbox()

          {:ok, provisioned} =
            case ExSandbox.provision(@mechanism, sandbox) do
              {:ok, s} ->
                {:ok, s}

              {:error, {:capability_unavailable, [missing | _]}} ->
                capability_unavailable(missing.name, missing.detail)

              other ->
                guarantee_failure("003-FR-010", "provision/2 returned #{inspect(other)}")
            end

          assert_guarantee(
            is_binary(provisioned.mechanism_ref),
            "003-FR-010",
            "provision must set `mechanism_ref` to the handle by which this " <>
              "mechanism will recognise the sandbox later; got " <>
              inspect(provisioned.mechanism_ref)
          )

          {:ok, started} = ExSandbox.start(@mechanism, provisioned)

          assert_guarantee(
            ExSandbox.status(@mechanism, started) == {:ok, :running},
            "003-FR-024",
            "a started sandbox must report `:running`; got " <>
              inspect(ExSandbox.status(@mechanism, started))
          )

          {:ok, stopped} = ExSandbox.stop(@mechanism, started)

          assert_guarantee(
            ExSandbox.status(@mechanism, stopped) in [{:ok, :stopped}, {:ok, :provisioned}],
            "003-FR-024",
            "a stopped sandbox must not report `:running`; got " <>
              inspect(ExSandbox.status(@mechanism, stopped))
          )

          assert_guarantee(
            ExSandbox.destroy(@mechanism, stopped) == :ok,
            "003-FR-013",
            "destroy must return :ok on a stopped sandbox"
          )
        end

        check "a destroyed sandbox reports :absent, not :unknown" do
          sandbox = build_sandbox()
          provisioned = provision_or_report(@mechanism, sandbox)
          :ok = ExSandbox.destroy(@mechanism, provisioned)

          # `:absent` and `:unknown` are distinct on purpose (003-FR-024): "it
          # is gone" and "we cannot tell" lead to different actions, and a
          # mechanism that collapses them makes reconciliation guesswork.
          assert_guarantee(
            ExSandbox.status(@mechanism, provisioned) == {:ok, :absent},
            "003-FR-024",
            "after destroy the mechanism must report `:absent` -- definitely " <>
              "gone -- rather than `:unknown`; got " <>
              inspect(ExSandbox.status(@mechanism, provisioned))
          )
        end

        check "a second destroy returns :ok rather than an error" do
          sandbox = build_sandbox()
          provisioned = provision_or_report(@mechanism, sandbox)

          :ok = ExSandbox.destroy(@mechanism, provisioned)

          assert_guarantee(
            ExSandbox.destroy(@mechanism, provisioned) == :ok,
            "003-FR-013",
            "destroy must be idempotent. A cleanup sweep runs against sandboxes " <>
              "that may already be gone; erroring on 'already gone' turns every " <>
              "sweep into a source of spurious failures."
          )
        end

        check "concurrent provision of the same id resolves to one sandbox" do
          sandbox = build_sandbox()

          # Same id from both callers -- this is the collision, not two
          # unrelated provisions racing.
          results =
            [sandbox, sandbox]
            |> Task.async_stream(&ExSandbox.provision(@mechanism, &1),
              max_concurrency: 2,
              timeout: 30_000
            )
            |> Enum.map(fn {:ok, result} -> result end)

          refs =
            results
            |> Enum.flat_map(fn
              {:ok, s} -> [s.mechanism_ref]
              _ -> []
            end)
            |> Enum.uniq()

          on_exit(fn ->
            Enum.each(results, fn
              {:ok, s} -> ExSandbox.destroy(@mechanism, s)
              _ -> :ok
            end)
          end)

          assert_guarantee(
            length(refs) <= 1,
            "003-FR-010",
            "two concurrent provisions of the same sandbox id produced " <>
              "#{length(refs)} distinct mechanism refs: #{inspect(refs)}. The " <>
              "second is a leak nothing will clean up, because the host records " <>
              "only one."
          )

          assert_guarantee(
            Enum.any?(results, &match?({:ok, _}, &1)),
            "003-FR-010",
            "both concurrent provisions failed: #{inspect(results)}. Resolving " <>
              "the race by refusing both is not resolving it."
          )
        end

        check "list_running reports a started sandbox and forgets a destroyed one" do
          sandbox = build_sandbox()
          provisioned = provision_or_report(@mechanism, sandbox)
          {:ok, started} = ExSandbox.start(@mechanism, provisioned)

          {:ok, running} = ExSandbox.list_running(@mechanism)

          assert_guarantee(
            started.mechanism_ref in running,
            "003-FR-015",
            "a running sandbox must appear in `list_running/0`. Without it, a " <>
              "sandbox that crashed while the host was down stays recorded as " <>
              "running indefinitely and 003-SC-008 is unsatisfiable."
          )

          :ok = ExSandbox.destroy(@mechanism, started)
          {:ok, after_destroy} = ExSandbox.list_running(@mechanism)

          assert_guarantee(
            started.mechanism_ref not in after_destroy,
            "003-FR-015",
            "a destroyed sandbox must not still appear in `list_running/0`"
          )
        end

        check "usage is reported for a running sandbox" do
          sandbox = build_sandbox()
          provisioned = provision_or_report(@mechanism, sandbox)
          {:ok, started} = ExSandbox.start(@mechanism, provisioned)
          on_exit(fn -> ExSandbox.destroy(@mechanism, started) end)

          case ExSandbox.usage(@mechanism, started) do
            {:ok, usage} when is_map(usage) ->
              assert_guarantee(
                map_size(usage) > 0,
                "003-FR-026",
                "usage/1 returned an empty map. Per-sandbox consumption must be " <>
                  "attributable to the owner; an empty report attributes nothing."
              )

            other ->
              guarantee_failure("003-FR-026", "usage/1 returned #{inspect(other)}")
          end
        end

        check "a missing template fails naming the template, not generically" do
          # Quickstart Scenario 3 step 3. FR-027 requires the sandbox-specific
          # causes stay distinguishable; `:template_missing` is the one a caller
          # can actually act on, because the fix is to name a template that
          # exists and the error has to say which name did not.
          missing = "definitely-not-a-real-template-#{System.unique_integer([:positive])}"
          sandbox = build_sandbox(template_ref: missing)

          case ExSandbox.provision(@mechanism, sandbox) do
            {:ok, provisioned} ->
              on_exit(fn -> ExSandbox.destroy(@mechanism, provisioned) end)

              guarantee_failure("003-FR-027", """
              Provisioning succeeded with a template that does not exist
              (#{inspect(missing)}).

              A mechanism that invents a template on demand cannot report
              `:template_missing`, and a caller who typos a template name gets a
              running sandbox built from something they did not choose.
              """)

            {:error, reason} ->
              assert_guarantee(
                ExSandbox.Conformance.Lifecycle.template_missing?(reason),
                "003-FR-027",
                """
                Provisioning with a nonexistent template failed, but not
                distinguishably: #{inspect(reason)}

                FR-027 requires `:template_missing` **naming the template**. A
                generic `{:error, :provision_failed}` satisfies the type and
                fails the requirement -- the caller cannot tell a typo from a
                host outage, and those have opposite fixes.
                """
              )

            other ->
              guarantee_failure("003-FR-027", "provision/2 returned #{inspect(other)}")
          end
        end

        check "a failed provision leaves no orphan running" do
          # Quickstart Scenario 3 step 4, and the reason it enumerates rather
          # than inspects: SC-006 is a claim about failures nobody anticipated.
          # Reading the compensation code can only confirm it handles the cases
          # its author thought of, which is exactly the set that is already fine.
          {:ok, before} = ExSandbox.list_running(@mechanism)

          missing = "orphan-probe-#{System.unique_integer([:positive])}"
          sandbox = build_sandbox(template_ref: missing)

          result = ExSandbox.provision(@mechanism, sandbox)

          on_exit(fn ->
            case result do
              {:ok, s} -> ExSandbox.destroy(@mechanism, s)
              _ -> :ok
            end
          end)

          case result do
            {:error, _reason} ->
              {:ok, current} = ExSandbox.list_running(@mechanism)
              leaked = current -- before

              assert_guarantee(
                leaked == [],
                "003-SC-006",
                """
                A provision that failed left #{length(leaked)} sandbox(es)
                running: #{inspect(leaked)}

                Nothing will ever clean these up: the host recorded no sandbox,
                so they are unattributable, and therefore unbillable and
                unauditable. This is measured against `list_running/0` rather
                than against the cleanup code precisely because the cleanup code
                believes it ran.
                """
              )

            {:ok, _} ->
              # The failure could not be induced through the template, so this
              # check demonstrated nothing about orphans. Not a pass.
              capability_unavailable(
                :provision_failure_injection,
                "provisioning a nonexistent template succeeded, so no failure " <>
                  "path could be exercised; the orphan check measured nothing"
              )

            other ->
              guarantee_failure("003-SC-006", "provision/2 returned #{inspect(other)}")
          end
        end

        check "a stop/start cycle preserves the sandbox rather than rebuilding it" do
          # Quickstart Scenario 3 step 5. The conformance suite cannot write
          # into a sandbox's storage without assuming a stack (Principle VI), so
          # it checks the property that reprovisioning would necessarily break:
          # `mechanism_ref` identifies *this* sandbox, and a mechanism that
          # rebuilds from the template on `start/1` has a different one.
          sandbox = build_sandbox()
          provisioned = provision_or_report(@mechanism, sandbox)
          {:ok, started} = ExSandbox.start(@mechanism, provisioned)
          on_exit(fn -> ExSandbox.destroy(@mechanism, started) end)

          {:ok, stopped} = ExSandbox.stop(@mechanism, started)
          {:ok, restarted} = ExSandbox.start(@mechanism, stopped)

          # Two assertions rather than one conjunction. `nil == nil` is true, so
          # a mechanism that never sets a ref would pass the equality by having
          # no identity to change -- but folding the `is_binary` guard into the
          # comparison would then report that as "the ref changed: nil -> nil",
          # sending the author looking for a bug that is not the one they have.
          assert_guarantee(
            is_binary(started.mechanism_ref),
            "003-FR-010",
            "a started sandbox has no `mechanism_ref`, so there is no identity " <>
              "for a restart to preserve; got " <> inspect(started.mechanism_ref)
          )

          assert_guarantee(
            restarted.mechanism_ref == started.mechanism_ref,
            "003-FR-012",
            """
            The sandbox's `mechanism_ref` changed across a stop/start cycle:
            #{inspect(started.mechanism_ref)} -> #{inspect(restarted.mechanism_ref)}

            A restart must resume the same sandbox, not build a new one from the
            template. A rebuilding mechanism passes every other check in this
            group -- it starts, reports `:running`, appears in `list_running/0`
            -- and the only observable difference is that the tenant's data is
            gone.
            """
          )

          assert_guarantee(
            ExSandbox.status(@mechanism, restarted) == {:ok, :running},
            "003-FR-024",
            "a restarted sandbox must report `:running`; got " <>
              inspect(ExSandbox.status(@mechanism, restarted))
          )
        end
      end
    end
  end

  @doc false
  # A refusal counts as distinguishable only if it both carries the
  # `:template_missing` cause and names the template -- FR-027's two halves. A
  # bare `:template_missing` tells a caller a template was wrong but not which,
  # and provisioning takes exactly one template, so omitting it is pure loss.
  def template_missing?(reason) do
    flat = inspect(reason)
    String.contains?(flat, "template_missing") and String.contains?(flat, "-template-")
  end
end
