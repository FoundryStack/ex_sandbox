defmodule ExSandbox.Hardening.MemoryPressureArgsTest do
  @moduledoc """
  `config :ex_sandbox, :beam` `memory_high_ratio:` and `swap_max_mb:`, and the
  sandbox context's `memory_low_mb:` and `memory_high_mb:`, set a scope's soft limit, bounded swap and
  floor; unset, the argv is unchanged.
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

  defp properties(context \\ nil) do
    sandbox = %ExSandbox.Sandbox{
      id: "sb-#{System.unique_integer([:positive])}",
      owner_ref: "owner-1",
      template_ref: "tpl",
      memory_limit_mb: 1536,
      cpu_limit: 500,
      disk_quota_mb: 1024,
      context: context
    }

    {:ok, {_path, args}} = Linux.compose_for_inspection(sandbox)

    args
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.filter(&match?(["-p", _], &1))
    |> Enum.map(&List.last/1)
  end

  defp put(original, opts), do: Application.put_env(:ex_sandbox, :beam, original ++ opts)

  test "unset, today's properties", %{original: original} do
    put(original, [])

    assert ["MemoryMax=1536M", "CPUQuota=50%", "MemorySwapMax=0"] = properties()
  end

  test "a ratio sets MemoryHigh below the cap", %{original: original} do
    put(original, memory_high_ratio: 0.85)
    assert "MemoryHigh=1305M" in properties()
  end

  test "a swap bound replaces MemorySwapMax=0", %{original: original} do
    put(original, swap_max_mb: 256)
    props = properties()
    assert "MemorySwapMax=256M" in props
    refute "MemorySwapMax=0" in props
  end

  test "a context floor sets MemoryLow", %{original: original} do
    put(original, [])
    assert "MemoryLow=256M" in properties(%{memory_low_mb: 256})
  end

  test "a context soft limit replaces the ratio, never above the cap", %{original: original} do
    put(original, memory_high_ratio: 0.85)
    props = properties(%{memory_high_mb: 400})
    assert "MemoryHigh=400M" in props
    refute "MemoryHigh=1305M" in props

    assert "MemoryHigh=1536M" in properties(%{memory_high_mb: 4096})
  end

  test "values outside their range raise", %{original: original} do
    put(original, memory_high_ratio: 1.5)
    assert_raise ArgumentError, ~r/memory_high_ratio/, fn -> properties() end

    put(original, swap_max_mb: -1)
    assert_raise ArgumentError, ~r/swap_max_mb/, fn -> properties() end
  end
end
