defmodule ExSandbox.LoopFormatter do
  @moduledoc """
  An `ExUnit` formatter that writes a machine-readable per-test report.

  ExUnit has no such output, and `mix verify.change`'s quarantine ceiling needs
  one: the count of tests excluded by the `:quarantine` tag is the number the
  ceiling bounds, and stdout scraping cannot distinguish that exclusion from
  the several others this suite already applies (`:playwright`,
  `:integration_caddy`, `:integration_cli`).

  ## Why it lives in `ex_sandbox`, and why in `lib/`

  A consumer with several applications needs one formatter every one of their
  suites can load, and the only module that qualifies is one they all already
  depend on. This library is that module for its own consumers, which is the
  whole of the reason — nothing here is about sandboxing, and nothing here
  names any particular application.

  ⚠️ `lib/`, and it was `test/support/` until 1.0.1. Inside an umbrella that
  worked, because `test/support` is on `elixirc_paths` under `MIX_ENV=test` and
  the compiled module landed in `_build/test/lib/ex_sandbox/ebin` where every
  sibling app's `mix test` could load it. A published package has no such
  arrangement: `test/` is not in `package/0`'s `files:`, so 1.0.0 listed this
  module as Public in `priv/boundary.md` and shipped a release that does not
  contain it. The consumer's own `--formatter ExSandbox.LoopFormatter` then
  fails to load a module its dependency promised.

  ## Why TSV rather than JSON

  `ex_sandbox` depends on `:telemetry` and nothing else -- no JSON encoder is
  available here, and adding one to the dependency root of the umbrella to
  format a test report is not a trade worth making. The consumer is a bash 3.2
  runner with `awk`, which reads TSV natively.

  ## The last line is the point

  The report ends with a `summary` row whose final field is `COMPLETE`. A run
  that crashes, is killed, or fills the disk leaves a report without it.

  This matters more than it looks. A gate that reads a truncated report sees
  fewer failures and fewer quarantined tests than actually exist, and passes --
  reporting green because it was handed less evidence, which is the exact
  failure `docker/census-gate.sh` was written to close and the one this
  repository has been bitten by three times. `mix verify.change` therefore
  treats a report without a trailing `COMPLETE` as a gate failure, never as an
  empty result.

  ## Enabling

  Set `LOOP_REPORT` to the destination path. Unset, the formatter records
  nothing and costs nothing, so it is safe to leave configured.

      LOOP_REPORT=.loop/runs/report.tsv mix test --formatter ExSandbox.LoopFormatter

  Rows are appended, because an umbrella `mix test` runs each app in its own
  ExUnit process and this formatter is initialised once per app. The consumer
  sums across every `summary` row and requires the file's last row to be one.
  """
  use GenServer

  @impl true
  def init(_opts) do
    case System.get_env("LOOP_REPORT") do
      path when path in [nil, ""] ->
        {:ok, :disabled}

      path ->
        File.mkdir_p!(Path.dirname(path))
        {:ok, device} = File.open(path, [:append, :utf8])
        {:ok, %{device: device, counts: %{}}}
    end
  end

  @impl true
  def handle_cast(_event, :disabled), do: {:noreply, :disabled}

  def handle_cast({:test_finished, %ExUnit.Test{} = test}, state) do
    state_name = state_name(test.state)

    row(state.device, [
      "test",
      inspect(test.module),
      to_string(test.name),
      state_name,
      quarantined(test.tags)
    ])

    {:noreply, update_in(state.counts, &Map.update(&1, state_name, 1, fn n -> n + 1 end))}
  end

  def handle_cast({:suite_finished, _times}, state) do
    counts = state.counts
    total = counts |> Map.values() |> Enum.sum()

    row(state.device, [
      "summary",
      to_string(total),
      to_string(Map.get(counts, "failed", 0)),
      to_string(Map.get(counts, "excluded", 0)),
      to_string(Map.get(counts, "skipped", 0)),
      to_string(Map.get(counts, "invalid", 0)),
      "COMPLETE"
    ])

    # Closed here rather than in `terminate/2`: `terminate` is not guaranteed
    # to run, and an unflushed COMPLETE row is indistinguishable from a crash.
    File.close(state.device)
    {:noreply, %{state | device: :closed}}
  end

  def handle_cast(_event, state), do: {:noreply, state}

  defp state_name(nil), do: "passed"
  defp state_name({:failed, _}), do: "failed"
  defp state_name({:excluded, _}), do: "excluded"
  defp state_name({:skipped, _}), do: "skipped"
  defp state_name({:invalid, _}), do: "invalid"
  defp state_name(_), do: "unknown"

  defp quarantined(%{quarantine: q}) when q not in [nil, false], do: "quarantine"
  defp quarantined(_), do: "-"

  # A test name is author-supplied text and may contain anything. Tabs and
  # newlines would silently reshape the row into a different number of fields,
  # which is how a report starts lying rather than failing.
  defp row(:closed, _fields), do: :ok

  defp row(device, fields) do
    IO.write(device, Enum.map_join(fields, "\t", &escape/1) <> "\n")
  end

  defp escape(field) do
    field
    |> String.replace("\t", "\\t")
    |> String.replace("\n", "\\n")
  end
end
