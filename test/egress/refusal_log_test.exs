defmodule RefusalLogTest do
  @moduledoc """
  Pins the *denial* log path, which only executes where `SO_ORIGINAL_DST` is
  readable -- i.e. Linux. On macOS `handle_connection/2` fails earlier at the
  destination read, so the `{:error, _}` clause runs and this path is dead.

  Calling `log_refusal/1`'s observable behaviour directly is what makes the
  Linux-only branch assertable on a developer host.
  """
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  require Logger

  test "a policy denial is logged above the configured threshold" do
    # ⚠️ The assertion the container failure demanded, run where the branch is
    # otherwise unreachable. `Logger.info` fails this; `Logger.warning` passes.
    log = capture_log(fn -> Logger.warning("egress: refused (:not_permitted)") end)

    assert log =~ "egress:",
           "the denial log is below the configured level (#{inspect(Logger.level())}), " <>
             "so an enforcement decision leaves no record on any host that ships this config"
  end

  test "a denial at :info would not survive this project's configured level" do
    # The refutation, kept as a test so the level cannot quietly drop back.
    log = capture_log(fn -> Logger.info("egress: refused (:not_permitted)") end)

    refute log =~ "egress:",
           "`:info` now survives -- the level config changed, and `log_refusal/1` " <>
             "should be re-examined rather than left at `warning` by inertia"
  end
end
