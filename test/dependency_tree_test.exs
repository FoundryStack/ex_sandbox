defmodule ExSandbox.DependencyTreeTest do
  @moduledoc """
  `ex_sandbox` fetches nothing (012 T015, SC-002, SC-003).

  ## What this test does and does not prove

  ⚠️ It proves **nothing was fetched**, which is a weaker claim than **nothing
  was referenced**. Research R2 ran exactly this check with a deliberate
  boundary violation present — `ExSandbox.Bad.leak/0` calling into a sibling
  app — and it **passed**: `mix deps.tree` printed `ex_sandbox` alone, because a
  module reference does not create a dependency entry.

  The check that catches a *reference* is `mix compile --warnings-as-errors`,
  tested in `ExSandbox.BoundaryEnforcementTest`. `SC-002` and `SC-003` require
  this one too, so it stays — but it must be understood as the weaker of the
  two, or a future reader will take a green run here as proof of a boundary it
  does not check.
  """
  use ExUnit.Case, async: true

  @moduletag :boundary

  @app_dir Path.expand(Path.join(__DIR__, ".."))

  # Any of these appearing in `ex_sandbox`'s tree is a FR-001 violation.
  @forbidden ~w(ash ash_postgres ecto ecto_sql phoenix plug axonn axonn_web)

  defp deps_tree(dir) do
    {output, 0} = System.cmd("mix", ["deps.tree"], cd: dir, stderr_to_stdout: true)
    output
  end

  # Named exhaustively rather than checked as a count. A test asserting "at
  # most one dependency" would let the next one in as long as an old one left;
  # this one requires a deliberate edit here, which is where the argument for
  # the dependency belongs.
  @allowed ~w(telemetry)

  test "ex_sandbox depends on nothing beyond :telemetry (FR-001, SC-003)" do
    tree = deps_tree(@app_dir)

    actual =
      tree
      |> String.split("\n", trim: true)
      # Every line but the first is a dependency; the tree-drawing characters
      # are how `mix deps.tree` expresses nesting.
      |> Enum.filter(&String.contains?(&1, "──"))
      |> Enum.map(fn line ->
        line |> String.split("──") |> List.last() |> String.trim() |> String.split(" ") |> hd()
      end)
      |> Enum.sort()

    assert actual == Enum.sort(@allowed),
           """
           ex_sandbox's dependencies changed. Expected #{inspect(@allowed)}, got #{inspect(actual)}.

           FR-001 forbids Axonn, Ash, and web frameworks. `:telemetry` is admitted
           as a leaf Erlang library with no dependencies of its own -- see
           `ExSandbox.Telemetry`. Anything else needs the same argument made
           explicitly, here.

           Tree:
           #{tree}
           """
  end

  test "the one permitted dependency is itself childless" do
    tree = deps_tree(@app_dir)

    # `:telemetry` having no dependencies is the reason it is admissible. If it
    # ever grows one, this library's zero-transitive-dependency claim ends and
    # the decision deserves revisiting.
    refute tree =~ ~r/──.*\n.*│/,
           "a dependency of ex_sandbox has dependencies of its own:\n#{tree}"
  end

  test "ex_sandbox depends on no Ash, Ecto, or web framework (FR-001, SC-003)" do
    tree = deps_tree(@app_dir)

    for dep <- @forbidden do
      refute tree =~ ~r/\b#{dep}\b/,
             "ex_sandbox's dependency tree contains #{dep}:\n#{tree}"
    end
  end

  test "ash_sandbox depends on ex_sandbox and Ash, but never on Axonn (FR-002, SC-002)" do
    tree = deps_tree(Path.expand(Path.join([__DIR__, "..", "..", "ash_sandbox"])))

    assert tree =~ "ex_sandbox"
    assert tree =~ "ash"

    for dep <- ~w(axonn axonn_web) do
      refute tree =~ ~r/\b#{dep}\b/,
             "ash_sandbox's dependency tree contains #{dep}:\n#{tree}"
    end
  end

  test "neither library declares a dependency on Axonn in its mix.exs" do
    # The declaration check, separate from the resolved tree: a tree is built
    # from declarations, so catching it here names the actual line to delete.
    for app <- ~w(ex_sandbox ash_sandbox) do
      mix_exs = Path.expand(Path.join([__DIR__, "..", "..", app, "mix.exs"])) |> File.read!()

      refute mix_exs =~ ":axonn",
             "#{app}/mix.exs declares a dependency on Axonn"
    end
  end
end
