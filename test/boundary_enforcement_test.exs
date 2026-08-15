defmodule ExSandbox.BoundaryEnforcementTest do
  @moduledoc """
  Proves the boundary gate actually catches an upward reference (012 T011,
  FR-001, FR-002; quickstart Scenario 3).

  This is a test *of the gate*, not of library code. Research R2 established
  that a wrong-direction reference inside `ex_sandbox` compiles cleanly, exits
  0, passes `mix deps.tree`, and fails only at runtime inside a third-party
  consumer's application. `--warnings-as-errors` is the only build-time check
  that catches it, which makes the gate load-bearing rather than stylistic — so
  it needs a test the same way any load-bearing thing does.

  ## Why both halves are asserted

  Asserting only that `--warnings-as-errors` fails would still pass if plain
  `mix compile` started failing too. That sounds harmless, but it would mean the
  premise had changed: Elixir would be erroring on upward references on its own,
  and this whole gate would be redundant machinery nobody would know to remove.
  Asserting the *asymmetry* is what keeps the test honest about why the gate
  exists.
  """
  use ExUnit.Case, async: false

  @moduletag :boundary

  # A reference to a module `ex_sandbox` neither defines nor depends on. Exactly
  # the shape research R2 tested: `Axonn.Repo` lives in a sibling umbrella app
  # that `ex_sandbox` must never depend on.
  @violation """
  defmodule ExSandbox.BoundaryFixture do
    @moduledoc false
    def leak, do: Axonn.Repo.config()
  end
  """

  @mix_exs """
  defmodule BoundaryProbe.MixProject do
    use Mix.Project

    def project do
      [app: :boundary_probe, version: "0.1.0", elixir: "~> 1.14", deps: []]
    end

    def application, do: [extra_applications: [:logger]]
  end
  """

  setup do
    dir =
      Path.join(System.tmp_dir!(), "ex_sandbox_boundary_#{System.unique_integer([:positive])}")

    File.mkdir_p!(Path.join(dir, "lib"))
    File.write!(Path.join(dir, "mix.exs"), @mix_exs)
    File.write!(Path.join([dir, "lib", "boundary_fixture.ex"]), @violation)

    on_exit(fn -> File.rm_rf!(dir) end)

    {:ok, project: dir}
  end

  # A real throwaway Mix project, not a bare `elixirc` run. The distinction is
  # not incidental: `elixirc --warnings-as-errors` does *not* fail on an
  # undefined-module warning, while `mix compile --warnings-as-errors` does.
  # Since the gate in CI and in both `precommit` aliases is the Mix one, the
  # test has to exercise the Mix one -- testing `elixirc` would have reported
  # the gate broken while the real gate worked fine.
  defp compile(dir, args) do
    System.cmd("mix", ["compile" | args],
      cd: dir,
      stderr_to_stdout: true,
      env: [{"MIX_ENV", "dev"}, {"MIX_BUILD_ROOT", Path.join(dir, "_build")}]
    )
  end

  test "a plain compile lets the violation through", %{project: dir} do
    {output, status} = compile(dir, [])

    # The dangerous half. This is not the gate working -- it is the reason a
    # gate is needed at all.
    assert status == 0,
           "expected a plain compile to succeed despite the violation, got:\n#{output}"

    assert output =~ "Axonn.Repo",
           "expected a warning naming the undefined module, got:\n#{output}"
  end

  test "--warnings-as-errors rejects the violation", %{project: dir} do
    {output, status} = compile(dir, ["--warnings-as-errors"])

    refute status == 0,
           "expected --warnings-as-errors to fail the compile, got:\n#{output}"

    assert output =~ "Axonn.Repo"
  end

  test "both library apps run the gate in their own precommit alias" do
    # The gate only enforces anything if it is wired per-app: the umbrella root
    # alias does not fail on a child app's warnings (T009).
    for app <- ["ex_sandbox", "ash_sandbox"] do
      mix_exs =
        Path.join([__DIR__, "..", "..", app, "mix.exs"])
        |> Path.expand()
        |> File.read!()

      assert mix_exs =~ "precommit:", "#{app} has no precommit alias"

      assert mix_exs =~ "compile --warnings-as-errors",
             "#{app}'s precommit does not run the boundary gate"
    end
  end
end
