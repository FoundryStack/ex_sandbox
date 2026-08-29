defmodule ExSandbox.DocumentationPointersTest do
  @moduledoc """
  Every backticked filename in this repository's prose resolves, or is declared
  absent for a stated reason.

  ## Why this is a test and not a review habit

  This library's comments cite the thing that measured a claim, which is what
  keeps "MEASURED" from being decoration. A citation that no longer resolves
  costs more than no citation at all: it reads as evidence, and the reader who
  goes looking finds nothing and cannot tell whether the file moved, was
  renamed, or never existed.

  ⚠️ MEASURED, and the reason this file exists. Renaming `ExSandbox.Egress.Pool`
  to `ExSandbox.Egress.Decision` renamed `pool_decide_test.exs` with it and left
  three pointers behind -- one of them a present-tense claim that
  `pool_decide_test.exs` covers the decision, in the very test file asserting
  what the supervision tree does and does not hold. Nothing caught them. Compile
  warnings do not read comments, `mix docs --warnings-as-errors` checks module
  autolinks rather than filenames, and the rename passed both.

  ## Renamed modules leave the same wreckage, and ExDoc does not catch it

  ⚠️ MEASURED, second round. The same rename left six live present-tense claims
  that code "calls `Pool.decide/3`", in `beam.ex`, `node_launcher.ex`,
  `census-baseline.txt` and three test files. ExDoc autolinks a **fully
  qualified** module in backticks and fails the build when it cannot resolve
  one, which is why the rename's fully-qualified references were caught at the
  time. A bare alias is not autolinked, so every one of these passed
  `mix docs --warnings-as-errors`.

  The rule below closes that: a removed module is written with the qualifier it
  had (`Egress.Pool.relay/2`), never bare. A bare `Pool.` is then always a
  pointer at something gone, which is a thing a regex can find.

  ## The four ways a name is allowed to be absent

  `docs/provenance.md` describes them and lists every name. The check here is
  that the two agree: a name in `@absent` that the document does not mention
  fails the second test, so the allowlist cannot grow without the reason being
  written down somewhere a reader will find it.
  """
  use ExUnit.Case, async: true

  @provenance "docs/provenance.md"

  # `@provenance` itself lists these names in backticks, so scanning it would
  # report every declared absence as an unresolved reference.
  @sources Path.wildcard("lib/**/*.ex") ++
             Path.wildcard("test/**/*.exs") ++
             Path.wildcard("docker/*.md") ++
             Path.wildcard("docker/*.txt") ++
             ["mix.exs", "README.md", "CHANGELOG.md", "docs/requirement-ids.md"]

  # A backticked token that looks like a file: at least one path segment and one
  # of the extensions this repository actually writes. Deliberately not every
  # dotted token -- `:inet.port_number/0` and `1.1.0` are not filenames.
  @reference ~r/`([A-Za-z0-9_.\/-]+\.(?:exs|ex|c|h|py|sh|md|yml|txt|so|json))`/

  @umbrella ~w(
    contracts/egress.md contracts/hardening.md 012/contracts/execution-seam.md
    008/data-model.md egress-path-measurements.md spec.md quickstart.md
    docs/legacy/specify/014-desktop-deployment/spikes/darwin-hardening/baseline.md
    spin.c provision.ex library_boundary_test.exs delegated_launch_test.exs
    apps/axonn/test/axonn/model_access/credential_leak_test.exs
    docker/launch-ordering-probe.sh docker/wired-egress-e2e.sh
    docker/netns-first-e2e.sh netns-first-e2e.sh docker/acceptor-e2e.sh
    acceptor-e2e.sh docker/unprivileged-census-probe.sh
    docker/acceptor-mark-probe.py docker/loopback-redirect-probe.py
    docker/compose.memtiming.yml
  )

  @deleted ~w(
    nsacceptor.py pool_relay_wiring_test.exs pool_transport_test.exs
    pool_decide_test.exs
  )

  @generated ~w(priv/netns_nif.so census.txt secret.txt)

  # ⚠️ Present in the repository and absent from the isolation image, which
  # `.dockerignore` builds without `.git/` and `.github/` on purpose. MEASURED:
  # this test passed on the host and FAILED inside the container on `ci.yml`,
  # cited by `test_helper.exs` and by this file.
  #
  # `File.exists?/1` is consulted before this map, so on a full checkout the
  # reference resolves the ordinary way and this entry is never reached. It only
  # answers where the file genuinely is not, which keeps a real deletion of the
  # workflow catchable everywhere the workflow is supposed to be.
  @partial_copy ~w(ci.yml)

  @absent Map.new(
            Enum.map(@umbrella, &{&1, :umbrella}) ++
              Enum.map(@deleted, &{&1, :deleted}) ++
              Enum.map(@generated, &{&1, :generated}) ++
              Enum.map(@partial_copy, &{&1, :partial_copy})
          )

  test "every backticked filename resolves in this tree or is declared absent" do
    unresolved =
      for source <- @sources,
          File.exists?(source),
          {line, number} <- Enum.with_index(File.stream!(source), 1),
          [_, reference] <- Regex.scan(@reference, line),
          not resolves?(reference),
          not Map.has_key?(@absent, reference),
          do: "#{source}:#{number}  #{reference}"

    assert unresolved == [],
           """
           These backticked names point at nothing. Either the file moved and the
           pointer needs updating, or the name is genuinely absent -- in which case
           add it to `@absent` here AND to #{@provenance}, which says why.

           #{Enum.join(Enum.uniq(unresolved), "\n")}
           """
  end

  test "every declared absence is explained in #{@provenance}" do
    document = File.read!(@provenance)

    undocumented = Enum.reject(Map.keys(@absent), &String.contains?(document, &1))

    assert undocumented == [],
           """
           `@absent` grew without #{@provenance} growing with it. A reader who
           follows a citation to one of these names has to be able to find out
           where it went; the allowlist alone only silences the check.

           #{Enum.join(Enum.sort(undocumented), "\n")}
           """
  end

  # Removed modules whose bare alias must never appear in backticks again.
  # `ExSandbox.Egress.Pool` became `ExSandbox.Egress.Decision` and
  # `ExSandbox.Egress.Verdict` was deleted with the AF_UNIX verdict socket, both
  # in 1.1.0. Their history is still worth citing, which is why the fix is a
  # naming convention rather than a ban on mentioning them.
  @removed ~r/`(Pool|Verdict)\./

  test "a removed module is never cited by its bare alias" do
    # This file states the rule, so it has to spell the banned form to do it.
    # It stays in the filename scan above; only this one check skips it.
    bare =
      for source <- @sources,
          source != __ENV__.file |> Path.relative_to_cwd(),
          File.exists?(source),
          {line, number} <- Enum.with_index(File.stream!(source), 1),
          Regex.match?(@removed, line),
          do: "#{source}:#{number}  #{String.trim(line)}"

    assert bare == [],
           """
           These name a module that no longer exists, by an alias short enough that
           ExDoc does not try to resolve it. If the sentence is about today's code,
           it means `Decision`; if it is about history, qualify it as `Egress.Pool`
           or `Egress.Verdict` so the reader can tell which.

           #{Enum.join(bare, "\n")}
           """
  end

  defp resolves?(reference) do
    File.exists?(reference) or basenames() |> MapSet.member?(Path.basename(reference))
  end

  defp basenames do
    # `.github` is listed on its own: `Path.wildcard/1` skips dot-directories,
    # and `test_helper.exs` cites `ci.yml` by basename.
    Path.wildcard("{lib,test,docker,docs,priv,c_src,config}/**/*")
    |> Enum.concat(Path.wildcard(".github/**/*"))
    |> Enum.concat(Path.wildcard("*"))
    |> Enum.reject(&File.dir?/1)
    |> MapSet.new(&Path.basename/1)
  end
end
