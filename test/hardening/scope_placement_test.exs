defmodule ExSandbox.Hardening.ScopePlacementTest do
  @moduledoc """
  `config :ex_sandbox, :beam` `slice:` and `oom_score_adjust:` place the scope
  in a host's slice and raise the sandbox's out-of-memory score; unset, the
  argv is unchanged.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Hardening.Linux

  setup do
    original = Application.get_env(:ex_sandbox, :beam, [])
    :persistent_term.put({Linux, :scope_mode}, :user)

    on_exit(fn ->
      Application.put_env(:ex_sandbox, :beam, original)
      Linux.forget_scope_mode()
    end)

    %{original: original}
  end

  defp args do
    sandbox = %ExSandbox.Sandbox{
      id: "sb-#{System.unique_integer([:positive])}",
      owner_ref: "owner-1",
      template_ref: "tpl",
      memory_limit_mb: 256,
      cpu_limit: 500,
      disk_quota_mb: 1024
    }

    {:ok, {_path, args}} = Linux.compose_for_inspection(sandbox)
    args
  end

  defp put(original, opts), do: Application.put_env(:ex_sandbox, :beam, original ++ opts)

  test "unset, no slice and no score adjustment", %{original: original} do
    put(original, [])
    a = args()

    refute Enum.any?(a, &String.starts_with?(&1, "--slice"))
    refute "choom" in a
    assert ["--user", "--scope", "--quiet" | _] = a
  end

  test "a slice puts the scope in it", %{original: original} do
    put(original, slice: "axonn-sandbox.slice")
    a = args()

    assert "--slice=axonn-sandbox.slice" in a

    assert Enum.find_index(a, &(&1 == "--slice=axonn-sandbox.slice")) <
             Enum.find_index(a, &(&1 == "setpriv"))
  end

  test "a score is set by choom inside the scope, before the privilege drop", %{
    original: original
  } do
    put(original, oom_score_adjust: 500)
    a = args()

    i = Enum.find_index(a, &(&1 == "choom"))
    assert ["choom", "-n", "500", "--", "setpriv" | _] = Enum.drop(a, i)
    refute Enum.any?(a, &String.starts_with?(&1, "OOMScoreAdjust"))
  end

  test "a score outside the kernel's range raises", %{original: original} do
    put(original, oom_score_adjust: 1001)
    assert_raise ArgumentError, ~r/oom_score_adjust/, fn -> args() end
  end
end
