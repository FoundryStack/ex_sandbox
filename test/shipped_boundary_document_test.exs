defmodule ExSandbox.ShippedBoundaryDocumentTest do
  @moduledoc """
  Asserts the boundary document is reachable the way a consumer reaches it
  (`012-FR-014`, `FR-004`).

  `priv/boundary.md` is the public/private list, and the design is that a
  consumer parses the installed copy rather than keeping one of its own. That
  only works if the documented call resolves, and 1.0.0 shipped a release where
  it did not: the file was under `docs/`, `mix hex.build` put it in the tarball,
  `tar tzf` listed it, and `Application.app_dir/2` could not see it. Mix links
  exactly `ebin` and `priv` into an application's build directory; a file
  anywhere else is packaged and unreachable.

  ⚠️ The failure is invisible from inside this repository unless a test makes
  the call. Every path here is repo-relative during development, so reading
  `docs/boundary.md` off the source tree works perfectly and says nothing about
  what an installed dependency exposes. That is why this test goes through
  `app_dir/2` rather than `Path.join(__DIR__, "..")` — the point is the
  resolution, not the content.
  """
  use ExUnit.Case, async: true

  @doc_path "priv/boundary.md"

  describe "the shipped boundary document" do
    test "resolves through Application.app_dir/2, the only path a consumer has" do
      path = Application.app_dir(:ex_sandbox, @doc_path)

      assert File.exists?(path), """
      #{@doc_path} is not reachable from the built application.

      Resolved to: #{path}

      Mix links only `ebin` and `priv` into an application's build directory. If
      this document has been moved to `docs/` or anywhere else outside `priv/`,
      it still ships in the tarball and still fails here — which is exactly the
      defect 1.0.1 fixed. Consumers parse this file to check their own use of the
      boundary; an unreachable copy silently removes that check.
      """
    end

    test "is the module table, not an empty or truncated file" do
      content = Application.app_dir(:ex_sandbox, @doc_path) |> File.read!()

      assert content =~ "## Public interface of `ex_sandbox`",
             "the shipped document has no `## Public interface of` heading to key off"

      assert content =~ ~r/^\|\s*Module\s*\|\s*Purpose\s*\|\s*Stability\s*\|\s*$/m,
             "the shipped document has no `| Module | Purpose | Stability |` table"

      assert content =~ "ExSandbox.Conformance.{",
             "the brace-expanded Conformance row is missing, so a consumer's parser " <>
               "would silently see a narrower public list than the contract states"
    end

    # ⚠️ The check that would have caught BOTH of 1.0.0's packaging defects.
    #
    # A module on the Public list that the release does not contain is a promise
    # the package breaks at the consumer's first call, and it is invisible from
    # inside this repository: `ExSandbox.LoopFormatter` lived in `test/support`,
    # so every check here loaded it happily while `package/0`'s `files:` shipped
    # no `test/` at all. `Code.ensure_loaded?/1` on a module compiled from
    # `test/support` cannot tell the difference -- `elixirc_paths(:test)` put it
    # on the path. Asserting the SOURCE FILE is under `lib/` is what does.
    test "every module on the Public list is shipped, not merely loadable" do
      unshipped =
        public_modules()
        |> Enum.reject(fn module ->
          case Code.ensure_loaded(module) do
            {:module, ^module} ->
              module.module_info(:compile)[:source]
              |> to_string()
              |> String.contains?("/lib/")

            _ ->
              false
          end
        end)

      assert unshipped == [], """
      these modules are on the Public list in #{@doc_path} but are not compiled
      from `lib/`, so `package/0` does not ship them:

      #{Enum.map_join(unshipped, "\n", &"  - #{inspect(&1)}")}

      A consumer resolving one of these gets `:undef`. Either move the module
      into `lib/`, or take its row off the Public list -- but the list and the
      release have to agree.
      """
    end

    test "every module on the Public list exists" do
      missing = Enum.reject(public_modules(), &match?({:module, _}, Code.ensure_loaded(&1)))

      assert missing == [],
             "on the Public list in #{@doc_path} but not defined anywhere: " <>
               inspect(missing)
    end

    test "`package/0` ships the directory it lives in" do
      files = Mix.Project.config()[:package][:files]

      assert "priv" in files, """
      `package/0`'s `files:` does not list `priv`, so #{@doc_path} would not be
      published at all. The previous two tests pass regardless, because they read
      this repository's own build rather than an installed release.
      """
    end
  end

  # A deliberately small parser: the two row shapes the Public rows actually use.
  # It is not the umbrella's strict parser and does not need to be -- a shape it
  # cannot read yields no modules, which makes the assertions above weaker rather
  # than wrong, and the strict parse already runs in the consumer that reads this
  # same file.
  defp public_modules do
    Application.app_dir(:ex_sandbox, @doc_path)
    |> File.read!()
    |> String.split("\n")
    |> Enum.filter(&Regex.match?(~r/^\|.*\|\s*Public\b.*\|\s*$/, &1))
    |> Enum.flat_map(fn row ->
      row
      |> String.split("|")
      |> Enum.at(1, "")
      |> expand()
    end)
    |> Enum.map(&Module.concat([&1]))
  end

  defp expand(cell) do
    braced =
      Regex.scan(~r/`([A-Z][\w.]*)\.\{([^}]*)\}`/, cell)
      |> Enum.flat_map(fn [_, prefix, leaves] ->
        leaves |> String.split(",") |> Enum.map(&(prefix <> "." <> String.trim(&1)))
      end)

    plain =
      Regex.scan(~r/`([A-Z][A-Za-z0-9_]*(?:\.[A-Z][A-Za-z0-9_]*)*)`/, cell)
      |> Enum.map(fn [_, m] -> m end)

    braced ++ plain
  end
end
