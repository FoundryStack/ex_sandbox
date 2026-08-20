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

  ## Why `--format plain`

  ⚠️ The oracle must not depend on the encoding of the shell that runs the
  suite. `mix deps.tree`'s default `pretty` format draws the tree with Unicode
  box-drawing characters, and when the calling shell has no UTF-8 locale
  (`LANG`, `LC_ALL` and `LC_CTYPE` all empty — reproducible with
  `env -u LANG -u LC_ALL mix deps.tree`) Erlang's stdout encoding falls back to
  latin1 and Mix emits them as **literal ASCII escape text**: the 12-character
  string `\\x{2514}\\x{2500}\\x{2500} telemetry ...` rather than
  `└── telemetry ...`.

  Both failure modes that produced are worth keeping written down, because they
  point in opposite directions and only one of them is loud:

  1. The `@allowed` test **failed falsely**. It filtered lines on `──`, matched
     nothing, and reported `Expected ["telemetry"], got []` while printing a
     tree that plainly contained telemetry.
  2. The childless test **passed vacuously**. Its oracle was
     `refute tree =~ ~r/──.*\\n.*│/`, and under escaped output that pattern can
     never match — so it was green whether or not `:telemetry` had grown
     children. A silent green is the worse of the two.

  `--format plain` (Elixir ≥ 1.17, and the default on Windows) draws the same
  tree in pure ASCII — `|--`, `` `-- ``, and four-column indents — and is
  byte-identical under both locales. Nothing here is normalised or
  locale-forced: there is no escaped form to normalise, and forcing
  `LC_ALL=en_US.UTF-8` would assume a locale the host may not have.

  The parse below is guarded by `dependencies!/1`, which fails when the output
  yields no dependency lines at all. That guard is what keeps the childless
  test honest: it is an **exclusion**, and an exclusion over an empty set is
  green for free, so an unparseable format has to be a failure rather than a
  silent empty set.
  """
  use ExUnit.Case, async: true

  @moduletag :boundary

  @app_dir Path.expand(Path.join(__DIR__, ".."))

  # Any of these appearing in `ex_sandbox`'s tree is a FR-001 violation.
  @forbidden ~w(ash ash_postgres ecto ecto_sql phoenix plug axonn axonn_web)

  # A dependency line in `--format plain`: an indent built from four-column
  # units (`|   ` under a continuing branch, four spaces under a closed one),
  # then the branch marker, then the application name.
  @dep_line ~r/^(?<indent>(?:[| ]   )*)[|`]-- (?<name>[A-Za-z0-9_]+)/

  defp deps_tree(dir) do
    {output, 0} =
      System.cmd("mix", ["deps.tree", "--format", "plain"], cd: dir, stderr_to_stdout: true)

    output
  end

  # Parses the tree into `{depth, name}` pairs — depth 0 being a direct
  # dependency of the app, and anything deeper a transitive one. Raises rather
  # than returning `[]`, so that a format change lands as a failure in whichever
  # test asked, instead of quietly satisfying every exclusion below it.
  defp dependencies!(tree) do
    deps =
      tree
      |> String.split("\n", trim: true)
      |> Enum.flat_map(fn line ->
        case Regex.named_captures(@dep_line, line) do
          nil -> []
          %{"indent" => indent, "name" => name} -> [{div(String.length(indent), 4), name}]
        end
      end)

    assert deps != [],
           """
           No dependency lines parsed out of `mix deps.tree --format plain`.

           Either the app genuinely has no dependencies -- in which case the
           `@allowed` list below is wrong -- or the output format changed and
           this parse needs updating. Both are failures: the exclusions in this
           file are all vacuously true against an empty dependency list, so an
           unparseable tree must never read as a clean one.

           Tree:
           #{tree}
           """

    deps
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
      |> dependencies!()
      |> Enum.filter(fn {depth, _name} -> depth == 0 end)
      |> Enum.map(fn {_depth, name} -> name end)
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
    #
    # `dependencies!/1` is what stops this reading green for the wrong reason:
    # every direct dependency is a line too, so the list is non-empty on any
    # tree this test is meant to run against, and an empty parse is a failure
    # rather than an exclusion satisfied by having nothing to exclude.
    transitive =
      tree
      |> dependencies!()
      |> Enum.filter(fn {depth, _name} -> depth > 0 end)
      |> Enum.map(fn {_depth, name} -> name end)

    assert transitive == [],
           """
           a dependency of ex_sandbox has dependencies of its own: #{inspect(transitive)}

           Tree:
           #{tree}
           """
  end

  test "ex_sandbox depends on no Ash, Ecto, or web framework (FR-001, SC-003)" do
    tree = deps_tree(@app_dir)

    # The refutes below are unaffected by the encoding fault -- these names are
    # plain ASCII and match either way -- and they stay as raw-text matches
    # deliberately: a forbidden name on a line the parse failed to recognise
    # still has to be caught. The parse runs anyway, for its emptiness guard,
    # so an unreadable tree cannot satisfy eight refutes by being unreadable.
    _ = dependencies!(tree)

    for dep <- @forbidden do
      refute tree =~ ~r/\b#{dep}\b/,
             "ex_sandbox's dependency tree contains #{dep}:\n#{tree}"
    end
  end

  test "ash_sandbox depends on ex_sandbox and Ash, but never on Axonn (FR-002, SC-002)" do
    tree = deps_tree(Path.expand(Path.join([__DIR__, "..", "..", "ash_sandbox"])))
    names = dependencies!(tree) |> Enum.map(fn {_depth, name} -> name end)

    # The positive half reads the parse: `tree =~ "ash"` is satisfied by
    # `ash_postgres`, or by the word appearing in a version requirement, so it
    # would not distinguish a tree that lost `:ash` itself.
    assert "ex_sandbox" in names
    assert "ash" in names

    # The negative half stays raw-text, for the same reason as above.
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
