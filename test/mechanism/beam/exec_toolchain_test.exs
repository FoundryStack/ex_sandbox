defmodule ExSandbox.Mechanism.Beam.ExecToolchainTest do
  @moduledoc """
  A host's toolchain outside `/usr` reaches a sandboxed command's `PATH`.

  OBSERVED 2026-09-21 on production: a deployment's build ran `mix deps.get`
  in a Beam sandbox and got `mix: command not found`. Elixir there lives in a
  version manager's install root, and the command's `PATH` was a fixed
  `/usr/local/bin:/usr/bin:...`.
  """
  # Mutates `:ex_sandbox, :beam`, which is global.
  use ExUnit.Case, async: false

  alias ExSandbox.Mechanism.Beam.Exec

  setup do
    previous = Application.get_env(:ex_sandbox, :beam, [])
    on_exit(fn -> Application.put_env(:ex_sandbox, :beam, previous) end)
    %{previous: previous}
  end

  test "configured bin directories come first, the system path after", %{previous: previous} do
    Application.put_env(
      :ex_sandbox,
      :beam,
      Keyword.put(previous, :exec_path, ["/tc/erl/bin", "/tc/ex/bin"])
    )

    assert {"PATH", "/tc/erl/bin:/tc/ex/bin:/usr/local/bin:" <> _} =
             List.keyfind(Exec.default_env(), "PATH", 0)
  end

  test "configured variables are carried, and cannot replace PATH", %{previous: previous} do
    Application.put_env(
      :ex_sandbox,
      :beam,
      Keyword.put(previous, :exec_env, [{"MIX_HOME", "/tc/ex/.mix"}, {"PATH", "/nowhere"}])
    )

    env = Exec.default_env()
    assert {"MIX_HOME", "/tc/ex/.mix"} in env
    assert [{"PATH", "/usr/local/bin:" <> _}] = Enum.filter(env, &(elem(&1, 0) == "PATH"))
  end
end
