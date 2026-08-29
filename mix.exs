defmodule Mix.Tasks.Compile.NetnsNif do
  @moduledoc false
  # Builds `c_src/netns_nif.c` into `priv/netns_nif.so`.
  #
  # Hand-rolled rather than `elixir_make` so the library keeps its single
  # runtime dependency and its dependency tree stays assertable (see
  # `test/dependency_tree_test.exs`). The whole build is two `cc` arguments;
  # taking on a build dependency to express that is a poor trade.
  #
  # ⚠️ A failure here is a WARNING, never an error. Two reasons, and both are
  # about where refusal belongs:
  #
  #   * Off Linux there is no `setns(2)` and nothing to build. macOS consumers
  #     use `Mechanism.Docker`, which sets `--network none` and never reaches
  #     the egress path at all. Failing their build for a file they cannot use
  #     would be gratuitous.
  #
  #   * On Linux without a C compiler, the honest outcome is that namespace-local
  #     sockets are unavailable -- which `ExSandbox.Egress.NetnsSocket.available?/0`
  #     reports and the capability check turns into a refusal to launch. That is
  #     this project's discipline: refuse at the point the capability is wanted,
  #     with a reason, rather than at a point where the reason is lost.
  use Mix.Task.Compiler

  @source "c_src/netns_nif.c"
  @target "priv/netns_nif.so"

  @impl true
  def run(_args) do
    if :os.type() == {:unix, :linux}, do: build(), else: :noop
  end

  @impl true
  def clean, do: File.rm(@target)

  defp build do
    cond do
      not File.exists?(@source) -> :noop
      fresh?() -> :noop
      true -> compile()
    end
  end

  # `mtime` rather than a content hash: the source is one file with no
  # includes of our own, so there is nothing a hash would catch that a
  # timestamp does not.
  defp fresh? do
    with {:ok, %{mtime: target}} <- File.stat(@target, time: :posix),
         {:ok, %{mtime: source}} <- File.stat(@source, time: :posix) do
      target >= source
    else
      _ -> false
    end
  end

  defp compile do
    case System.find_executable("cc") || System.find_executable("gcc") do
      nil ->
        warn("no C compiler (cc/gcc) on PATH")

      cc ->
        File.mkdir_p!("priv")
        include = Path.join([to_string(:code.root_dir()), "usr", "include"])

        args = ["-O2", "-fPIC", "-shared", "-o", @target, @source, "-I" <> include]

        case System.cmd(cc, args, stderr_to_stdout: true) do
          {_, 0} -> :ok
          {output, _} -> warn("#{cc} failed:\n#{output}")
        end
    end
  end

  defp warn(reason) do
    Mix.shell().info([
      :yellow,
      "ex_sandbox: netns_nif not built -- #{reason}.\n",
      "  Namespace-local sockets are unavailable, so ExSandbox.Mechanism.Beam\n",
      "  will refuse to launch sandboxes that require network restriction.",
      :reset
    ])

    :noop
  end
end

defmodule ExSandbox.MixProject do
  use Mix.Project

  @version "1.1.0"
  @source_url "https://github.com/FoundryStack/ex_sandbox"

  def project do
    [
      app: :ex_sandbox,
      version: @version,
      # A floor, not the platform's version. Pinning this to whatever the host
      # application happens to run on would force every consumer onto that
      # application's Elixir, which is the opposite of what extracting this
      # library was for (T003).
      elixir: "~> 1.14",
      elixirc_paths: elixirc_paths(Mix.env()),
      compilers: [:netns_nif] ++ Mix.compilers(),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      name: "ExSandbox",
      description: description(),
      package: package(),
      docs: docs(),
      source_url: @source_url
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

  defp description do
    "Isolated execution sandboxes: a composition and evidence layer over " <>
      "operating-system containment facilities, which refuses to run rather " <>
      "than confine partially."
  end

  # ⚠️ `c_src/` is not optional and is the easiest thing here to lose.
  # `Mix.Tasks.Compile.NetnsNif` builds `c_src/netns_nif.c` into
  # `priv/netns_nif.so` in the CONSUMER's tree, and without it
  # `ExSandbox.Egress.NetnsSocket.available?/0` is false on every host. A tarball
  # missing it builds, installs, compiles and passes every unit test -- and then
  # every policed launch refuses, which is the last place a reader looks for a
  # packaging defect. The refusal at least names itself; the same omission under
  # the Python helper this replaced produced a failure at spawn time instead.
  # T8.2 verifies the built tarball with `tar tzf` rather than trusting this
  # list, for exactly that reason.
  #
  # ⚠️ `boundary.md` lives under `priv/` and NOT under `docs/`, and that is a
  # correctness requirement rather than a filing preference. It is READ AT
  # RUNTIME: a consumer checking its own boundary resolves the public-interface
  # table through `Application.app_dir(:ex_sandbox, "priv/boundary.md")` and
  # parses it, instead of keeping a copy that drifts.
  #
  # MEASURED, and 1.0.0 shipped it wrong. Mix links exactly `ebin` and `priv`
  # into an application's build directory -- `_build/<env>/lib/ex_sandbox` held
  # `.mix/`, `ebin/` and a `priv` symlink, and nothing else. So the file was in
  # the tarball, `tar tzf` found it, and `Application.app_dir/2` still could not:
  # `File.exists?` on the documented path returned false in the first consumer
  # that tried it. A packaging check that stops at "is it in the tarball" cannot
  # see this, because the tarball was never the thing that was wrong.
  #
  # `docs/` still ships, for `requirement-ids.md`, which is read by people.
  defp package do
    [
      name: "ex_sandbox",
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => @source_url <> "/blob/main/CHANGELOG.md"
      },
      files: ~w(lib c_src priv docs mix.exs README.md CHANGELOG.md LICENSE),
      # ⚠️ MEASURED, not precautionary, and the lesson outlived the file that
      # taught it. The first `mix hex.build` shipped
      # `priv/egress/__pycache__/nsacceptor.cpython-313.pyc` -- a bytecode cache
      # CPython wrote beside the acceptor the first time it was imported.
      # Untracked by git, so nothing in the repository hinted at it: `files:`
      # globs the working directory, not the index.
      #
      # The Python is gone, so that pattern would now exclude nothing. What
      # replaced it is the same mistake one build later: `Mix.Tasks.Compile.NetnsNif`
      # writes `priv/netns_nif.so`, which is equally untracked and equally
      # globbed. Shipping it would put the maintainer's architecture in every
      # consumer's tarball, and the compiler skips a target newer than its
      # source, so the wrong binary would be preferred to building the right
      # one. `c_src/` ships instead and the consumer builds it.
      exclude_patterns: ["priv/netns_nif.so"]
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url,
      # ⚠️ Two consumers read `priv/boundary.md` and they want opposite things
      # from the same row, which is why this option exists rather than an edit
      # to the document.
      #
      # `ExSandbox.Application` is `@moduledoc false`, and the row that names it
      # is the row declaring it PRIVATE -- naming it is the whole point. ExDoc
      # autolinks any module in backticks and warns when the target is hidden,
      # so `mix docs --warnings-as-errors` fails on a document that is correct.
      # The strict parser in `library_boundary_test.exs` (here and in the
      # originating umbrella) requires those backticks: a row without them is a
      # malformed table and it raises rather than skipping.
      #
      # MEASURED, and in that order: the backticks were lost during extraction,
      # which made `mix docs` pass and the parser refuse the whole table.
      # Restoring them fixed the parser and broke the docs build -- on CI, not
      # locally, because `precommit` did not run `mix docs` until this commit.
      # Dropping the backticks again would trade a build failure for a silent
      # contract failure, which is the worse of the two.
      skip_code_autolink_to: ["ExSandbox.Application"],
      extras: [
        "README.md",
        "CHANGELOG.md",
        "docs/requirement-ids.md",
        "priv/boundary.md"
      ],
      groups_for_modules: [
        Interface: [ExSandbox, ExSandbox.Mechanism, ExSandbox.Sandbox, ExSandbox.Capability],
        Mechanisms: [ExSandbox.Mechanism.Beam, ExSandbox.Mechanism.Docker],
        Conformance: [~r/^ExSandbox\.Conformance/],
        Hardening: [~r/^ExSandbox\.Hardening/],
        Egress: [~r/^ExSandbox\.Egress/]
      ]
    ]
  end

  # One runtime dependency, and `test/dependency_tree_test.exs` asserts the
  # resolved tree is exactly that and nothing else.
  defp deps do
    [
      # The only one, and a deliberate one. `FR-001` forbids a host application,
      # Ash, and web frameworks; `:telemetry` is none of those -- it is a leaf
      # Erlang library with no dependencies of its own, and the conventional way
      # a library emits events without dictating how they are consumed.
      #
      # The alternative -- a host-supplied callback module -- would make every
      # consumer write the plumbing `:telemetry` already standardises, and would
      # still not let two libraries' events be handled uniformly.
      {:telemetry, "~> 1.0"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end

  # Per-app rather than inherited, from when this lived in an umbrella whose root
  # alias did not fail on a child app's warnings. It stays because
  # `--warnings-as-errors` is this library's *boundary enforcement*, not a style
  # preference (research R2, T009): a wrong-direction reference compiles cleanly,
  # exits 0, passes `mix deps.tree`, and fails only at runtime inside a
  # third-party consumer's application.
  #
  # `precommit` runs `test`, and a `test` invoked from inside another command
  # inherits that command's environment -- which is `dev`, where the test helpers
  # are not compiled. Without this the gate fails on its own plumbing rather than
  # on anything it is checking.
  def cli do
    [preferred_envs: [precommit: :test]]
  end

  defp aliases do
    [
      precommit: [
        "compile --warnings-as-errors --force",
        # ⚠️ It used to be listed twice, which did nothing the once did not.
        "format --check-formatted",
        # ⚠️ NEW, and only possible now. In the umbrella this app's `lockfile`
        # pointed at the SHARED `../../mix.lock`, so run scoped to this directory
        # the check saw only `deps/0` and reported every package the REST of the
        # umbrella needed -- phoenix, ash_postgres, oban, all of it -- as unused.
        # MEASURED: it failed 100% of the time, which is why it was absent here
        # and why the comment in its place explained the absence at length.
        #
        # The lockfile is this repository's own now, so the check finally means
        # what it says. Note `deps.unlock --check-unused`, not the mutating
        # `deps.unlock --unused`: the latter rewrites the tree and exits 0, so as
        # a gate step it cannot fail and would never gate anything.
        "deps.unlock --check-unused",
        # ⚠️ Added after CI caught what this gate could not. `mix docs
        # --warnings-as-errors` is a real gate step -- it rejects a broken
        # autolink, a missing extra, and a reference to a hidden module -- and
        # it ran ONLY on CI, so the first push failed on a defect that had been
        # committed and locally green for two commits. A gate that a consumer's
        # CI enforces and the author's machine does not is a gate that reports
        # late, and the cost of running it here is one ex_doc compile that Mix
        # then caches.
        # ⚠️ `cmd`, and via `MIX_ENV=dev`, because `ex_doc` is `only: :dev`
        # while `preferred_envs` puts this whole alias in `:test`. Written
        # as a plain `"docs --warnings-as-errors"` step it fails with
        # `The task "docs" could not be found` -- a gate that reports a
        # missing task rather than a documentation defect.
        "cmd env MIX_ENV=dev mix docs --warnings-as-errors",
        "test"
      ]
    ]
  end
end
