defmodule ExSandbox.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_sandbox,
      version: "1.0.0",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      # A floor, not the platform's version. Pinning this to whatever Axonn
      # happens to run on would force every consumer onto Axonn's Elixir, which
      # is the opposite of what extracting the library is for (T003).
      elixir: "~> 1.14",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {ExSandbox.Application, []}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Deliberately empty, and checked by `test/dependency_tree_test.exs` (T004,
  # T015). FR-001 forbids Ash, any web framework, and Axonn. Elixir/OTP only.
  defp deps do
    [
      # The only dependency, and a deliberate one. `FR-001` forbids Axonn, Ash,
      # and web frameworks; `:telemetry` is none of those -- it is a leaf
      # Erlang library with no dependencies of its own, and the conventional
      # way a library emits events without dictating how they are consumed.
      #
      # The alternative -- a host-supplied callback module -- would make every
      # consumer write the plumbing `:telemetry` already standardises, and
      # would still not let two libraries' events be handled uniformly.
      {:telemetry, "~> 1.0"}
    ]
  end

  # Per-app rather than inherited: the umbrella root alias does not fail on a
  # child app's warnings, and `--warnings-as-errors` is this library's *boundary
  # enforcement*, not a style preference (research R2, T009).
  # `precommit` runs `test`, and a `test` invoked from inside another command
  # inherits that command's environment -- which is `dev`, where the test
  # helpers are not compiled. Without this the gate fails on its own plumbing
  # rather than on anything it is checking.
  def cli do
    [preferred_envs: [precommit: :test]]
  end

  defp aliases do
    [
      precommit: [
        "compile --warnings-as-errors --force",
        # A mutation exits 0 and therefore cannot gate; `--check-unused`
        # is the check. `format --check-formatted` below was already right.
        "deps.unlock --check-unused",
        "format --check-formatted",
        "test"
      ]
    ]
  end
end
