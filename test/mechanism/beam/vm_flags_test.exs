defmodule ExSandbox.Mechanism.Beam.VmFlagsTest do
  @moduledoc """
  `config :ex_sandbox, :beam, size_vm_to_cpu: true` gives a sandbox VM as many
  schedulers as its CPU limit has whole cores and turns busy-waiting off;
  unset, the VM boots with the emulator's defaults.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Mechanism.Beam.NodeLauncher

  setup do
    original = Application.get_env(:ex_sandbox, :beam, [])
    on_exit(fn -> Application.put_env(:ex_sandbox, :beam, original) end)
    %{original: original}
  end

  defp sandbox(cpu_limit),
    do: %ExSandbox.Sandbox{id: "sb", owner_ref: "o", template_ref: "t", cpu_limit: cpu_limit}

  test "unset, no flags", %{original: original} do
    Application.put_env(:ex_sandbox, :beam, original)
    assert NodeLauncher.vm_flags(sandbox(2000)) == []
  end

  test "a limit rounds up to whole cores", %{original: original} do
    Application.put_env(:ex_sandbox, :beam, original ++ [size_vm_to_cpu: true])

    assert ["+S", "2:2", "+SDcpu", "2:2" | busy_wait] = NodeLauncher.vm_flags(sandbox(2000))
    assert busy_wait == ["+sbwt", "none", "+sbwtdcpu", "none", "+sbwtdio", "none"]
    assert ["+S", "1:1" | _] = NodeLauncher.vm_flags(sandbox(500))
    assert ["+S", "2:2" | _] = NodeLauncher.vm_flags(sandbox(1500))
  end

  test "no CPU limit, no flags", %{original: original} do
    Application.put_env(:ex_sandbox, :beam, original ++ [size_vm_to_cpu: true])
    assert NodeLauncher.vm_flags(sandbox(nil)) == []
  end

  test "the flags boot a VM with that many schedulers" do
    flags = [
      "+S",
      "2:2",
      "+SDcpu",
      "2:2",
      "+sbwt",
      "none",
      "+sbwtdcpu",
      "none",
      "+sbwtdio",
      "none"
    ]

    {out, 0} =
      System.cmd(
        "erl",
        flags ++
          [
            "-noshell",
            "-eval",
            ~s|io:format("~p", [{erlang:system_info(schedulers_online), erlang:system_info(dirty_cpu_schedulers_online)}]), halt().|
          ]
      )

    assert out == "{2,2}"
  end
end
