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
  #
  # ⚠️ This list USED TO END `axonn, axonn_web`, and dropping those two names
  # was part of extracting the library rather than an accidental loosening. While
  # this lived inside Axonn's umbrella, "does the tree mention axonn" was a sharp
  # question -- Axonn was the sibling one wrong `in_umbrella: true` away. Outside
  # it, `axonn` is one arbitrary package name among all the ones not listed here,
  # and a denylist that happens to name it while permitting every other host
  # application reads as a stronger check than it is.
  #
  # What replaces it is the ALLOWLIST in `consumer_facing_deps/0` below: the tree
  # a consumer receives is exactly `telemetry`, so every host application is
  # excluded by construction rather than by enumeration. This denylist stays for
  # the frameworks, where naming them buys a failure message that says which
  # forbidden thing arrived instead of only that something did.
  @forbidden ~w(ash ash_postgres ecto ecto_sql phoenix plug)

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

  # ⚠️ `mix deps.tree` prints DECLARATIONS, not what any particular environment
  # resolves. `MIX_ENV=prod mix deps.tree` prints `ex_doc` and its six
  # transitive packages exactly as `MIX_ENV=dev` does -- MEASURED during the
  # extraction, and it is why the two tests below stopped being able to read
  # their answer out of the tree alone the moment a `:dev` dependency existed.
  #
  # The question FR-001 actually asks is what a CONSUMER receives, and that is
  # decided by `only:`. Hex omits a dependency scoped away from `:prod` from the
  # published package's requirements entirely, so `{:ex_doc, only: :dev}` reaches
  # nobody's application while `{:telemetry, "~> 1.0"}` reaches everyone's.
  #
  # Introspecting `Mix.Project.config()` rather than parsing more text: the
  # declaration is the thing being asserted about, and reading it directly cannot
  # disagree with itself the way a second parser could.
  defp consumer_facing_deps do
    Mix.Project.config()[:deps]
    |> Enum.reject(fn dep ->
      only = dep |> dep_opts() |> Keyword.get(:only)
      only != nil and :prod not in List.wrap(only)
    end)
    |> Enum.map(fn dep -> dep |> elem(0) |> Atom.to_string() end)
    |> Enum.sort()
  end

  defp dep_opts(dep) when is_tuple(dep) do
    case Tuple.to_list(dep) do
      [_name, opts] when is_list(opts) -> opts
      [_name, _req, opts] when is_list(opts) -> opts
      _ -> []
    end
  end

  # The lines strictly beneath `name`'s own line, i.e. its transitive closure.
  # A four-column indent unit is the format's nesting, so a child is any
  # following entry deeper than the parent, up to the next entry at or above the
  # parent's depth.
  defp subtree_of(deps, name) do
    case Enum.split_while(deps, fn {_depth, dep} -> dep != name end) do
      {_before, []} ->
        nil

      {_before, [{depth, ^name} | rest]} ->
        rest
        |> Enum.take_while(fn {child_depth, _} -> child_depth > depth end)
        |> Enum.map(fn {_, child} -> child end)
    end
  end

  test "ex_sandbox depends on nothing beyond :telemetry (FR-001, SC-003)" do
    tree = deps_tree(@app_dir)

    # Parsed for its emptiness guard, so an unreadable tree cannot make the
    # assertion below vacuous by supplying nothing to compare against.
    _ = dependencies!(tree)

    actual = consumer_facing_deps()

    assert actual == Enum.sort(@allowed),
           """
           ex_sandbox's consumer-facing dependencies changed.
           Expected #{inspect(@allowed)}, got #{inspect(actual)}.

           FR-001 forbids a host application, Ash, and web frameworks.
           `:telemetry` is admitted as a leaf Erlang library with no dependencies
           of its own -- see `ExSandbox.Telemetry`. Anything else needs the same
           argument made explicitly, here.

           A dependency scoped `only: :dev` or `only: :test` is not consumer
           facing and does not belong on this list -- Hex leaves it out of the
           published requirements. If you are reading this because you added
           tooling, scope it rather than widening `@allowed`.

           Declared: #{inspect(Mix.Project.config()[:deps])}

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
    # ⚠️ Scoped to `:telemetry`'s own subtree rather than to "every line at
    # depth > 0". The broad form was correct while `telemetry` was the only
    # declaration; with `{:ex_doc, only: :dev}` present it fails on ex_doc's six
    # transitive packages, which reach no consumer and say nothing about this
    # claim. Narrowing it keeps the assertion pointed at the dependency the
    # claim is actually about.
    deps = dependencies!(tree)
    transitive = subtree_of(deps, "telemetry")

    refute is_nil(transitive),
           """
           `telemetry` does not appear in the dependency tree at all, so this
           check has nothing to assert about and would pass for free.

           Tree:
           #{tree}
           """

    assert transitive == [],
           """
           :telemetry has grown dependencies of its own: #{inspect(transitive)}

           Its childlessness is the reason it is admissible at all, so this
           library's zero-transitive-dependency claim ends here and the decision
           deserves revisiting rather than the list being widened.

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

  # ⚠️ Two tests were REMOVED here during the extraction, and neither was
  # dropped: `ash_sandbox depends on ex_sandbox and Ash, but never on Axonn` and
  # `neither library declares a dependency on Axonn in its mix.exs` both read
  # `../../ash_sandbox`, a sibling that exists only inside Axonn's umbrella.
  #
  # Kept here they would not merely fail -- they would assert a fact this
  # repository cannot establish. Whether `ash_sandbox` avoids depending on Axonn
  # is Axonn's invariant to hold, checkable only where both are present, so they
  # moved to `apps/ash_sandbox/test/` in that repository rather than being
  # weakened into something this one could run.
end
