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
  """

  @doc "Emits the lifecycle checks into the calling test module."
  defmacro tests do
    quote do
      require ExSandbox.Conformance.Group
      import ExSandbox.Conformance.Group, only: [check: 2]

      describe "lifecycle (003-FR-010, 003-FR-013)" do
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
          {:ok, provisioned} = ExSandbox.provision(@mechanism, sandbox)
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
          {:ok, provisioned} = ExSandbox.provision(@mechanism, sandbox)

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
          {:ok, provisioned} = ExSandbox.provision(@mechanism, sandbox)
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
          {:ok, provisioned} = ExSandbox.provision(@mechanism, sandbox)
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
      end
    end
  end
end
