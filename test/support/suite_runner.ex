defmodule ExSandbox.SuiteRunner do
  @moduledoc """
  Runs the conformance suite against a mechanism and reports what happened
  (012 T029, T029a).

  The two meta-tests need to assert things *about a suite run* — that it failed
  a given mechanism, and what its failure message said. That means running the
  suite from inside a test.

  It works by compiling a throwaway module that `use`s `ExSandbox.Conformance`
  and then **invoking each generated test function directly**, rather than
  handing the module to a nested `ExUnit.run/0`. ExUnit generates one public
  function per `test`, so this reaches exactly the same code the real suite
  runs, while keeping the outer run's configuration and reporting untouched —
  a nested runner would reconfigure the formatter the outer suite is using.

  `setup` blocks are run explicitly, in order, because direct invocation skips
  ExUnit's callback machinery.

  Nothing here is part of the library. It exists so the suite can be held to the
  same standard the suite holds mechanisms to: demonstrated, not asserted.
  """

  @type result :: %{
          failures: [{atom(), String.t()}],
          passed: [atom()],
          unavailable: [{atom(), String.t()}],
          total: non_neg_integer()
        }

  @doc """
  Runs the conformance suite against `mechanism`.

  Failures are split into genuine guarantee violations and the suite's third
  outcome, which is reported as an ExUnit failure but is a distinct thing — the
  meta-tests need to tell them apart.
  """
  @spec run(module(), keyword()) :: result()
  def run(mechanism, opts \\ []) do
    suite = compile_suite(mechanism)

    suite.__ex_unit__().tests
    |> filter_describe(Keyword.get(opts, :describe))
    |> Enum.reduce(%{failures: [], passed: [], unavailable: [], total: 0}, fn test, acc ->
      acc
      |> Map.update!(:total, &(&1 + 1))
      |> record(test.name, run_one(suite, test))
    end)
  end

  @doc """
  Every failure message the suite produced for `mechanism`, joined.

  Convenience for the naming meta-test, which asserts on content rather than on
  which check produced it.
  """
  @spec failure_text(module()) :: String.t()
  def failure_text(mechanism) do
    mechanism
    |> run()
    |> Map.fetch!(:failures)
    |> Enum.map_join("\n\n", fn {name, message} -> "#{name}: #{message}" end)
  end

  # Lets a caller run one group. Without it, a meta-test about isolation also
  # runs the resource-limits group, whose time-budget checks deliberately block
  # for their full budget -- minutes of wall clock to assert nothing the caller
  # asked about.
  defp filter_describe(tests, nil), do: tests

  defp filter_describe(tests, describe) do
    Enum.filter(tests, fn test ->
      test.tags[:describe] && String.contains?(test.tags[:describe], describe)
    end)
  end

  defp record(acc, name, :passed), do: Map.update!(acc, :passed, &[name | &1])

  defp record(acc, name, {:unavailable, message}),
    do: Map.update!(acc, :unavailable, &[{name, message} | &1])

  defp record(acc, name, {:failed, message}),
    do: Map.update!(acc, :failures, &[{name, message} | &1])

  defp run_one(suite, test) do
    context = run_setups(suite, test)

    apply(suite, test.name, [context])
    :passed
  rescue
    error ->
      message = Exception.message(error)

      # The third outcome arrives as an ExUnit failure carrying this marker --
      # see `ExSandbox.Conformance.Group`, which re-raises rather than swallowing
      # it, because ExUnit has no runtime skip.
      if String.contains?(message, "NOT DEMONSTRATED") do
        {:unavailable, message}
      else
        {:failed, message}
      end
  catch
    kind, value -> {:failed, "#{kind}: #{inspect(value)}"}
  end

  # Direct invocation bypasses ExUnit's callback machinery, so `setup` blocks
  # are applied here. A check whose setup raises CapabilityUnavailable is the
  # third outcome for that check, not a crash of the run.
  defp run_setups(suite, test) do
    Enum.reduce(setup_callbacks(suite, test), %{test: test.name, module: suite}, fn callback,
                                                                                    context ->
      merge_context(context, apply(suite, callback, [context]))
    end)
  end

  defp setup_callbacks(suite, test) do
    describe = test.tags[:describe]

    suite.__info__(:functions)
    |> Enum.filter(fn {name, arity} ->
      arity == 1 and Atom.to_string(name) =~ ~r/^__ex_unit_setup_/ and
        relevant_setup?(name, describe)
    end)
    |> Enum.map(&elem(&1, 0))
    |> Enum.sort()
  end

  # Setups defined inside a `describe` are numbered per-describe; module-level
  # ones apply everywhere. Without a public API for the mapping this errs
  # toward running all of them, which is safe here because the suite's only
  # setup is the isolation group's.
  defp relevant_setup?(_name, _describe), do: true

  defp merge_context(context, %{} = returned), do: Map.merge(context, returned)
  defp merge_context(context, {:ok, %{} = returned}), do: Map.merge(context, returned)

  defp merge_context(context, keyword) when is_list(keyword),
    do: Map.merge(context, Map.new(keyword))

  defp merge_context(context, _other), do: context

  defp compile_suite(mechanism) do
    name = Module.concat([ExSandbox.GeneratedSuite, "S#{System.unique_integer([:positive])}"])

    Module.create(
      name,
      quote do
        # `use ExSandbox.Conformance` brings in `use ExUnit.Case`, which
        # registers this module with `ExUnit.Server`. In a single-app run that
        # is harmless -- collection has already finished. In the umbrella it is
        # not: `ex_sandbox`'s meta-tests create these modules while `ex_sandbox`
        # runs, and the *next* app's run collects them, reporting every
        # deliberate fixture failure as a real failure.
        #
        # The ordering is load-bearing. `@moduletag` applies only to tests
        # defined *after* it, and `use ExSandbox.Conformance` defines all of
        # them -- so the tag has to precede it, which in turn means `use
        # ExUnit.Case` has to come first for `@moduletag` to exist at all.
        # Setting the tag after the `use` compiles fine and skips nothing.
        use ExUnit.Case, async: false
        @moduletag :skip

        use ExSandbox.Conformance, mechanism: unquote(mechanism)
      end,
      Macro.Env.location(__ENV__)
    )

    name
  end
end
