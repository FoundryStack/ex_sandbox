defmodule ExSandbox.ReleaseApplicationsTest do
  @moduledoc """
  Every OTP application whose module ex_sandbox calls is one it declares, so
  `ex_sandbox_gateway`, which ships only what the app spec reaches, has it.
  """
  use ExUnit.Case, async: true

  test "the app spec names every application ex_sandbox's code calls into" do
    {:ok, modules} = :application.get_key(:ex_sandbox, :modules)
    {:ok, declared} = :application.get_key(:ex_sandbox, :applications)
    otp_lib = :code.lib_dir()

    called =
      for module <- modules,
          {:ok, {_, [imports: imports]}} = :beam_lib.chunks(:code.which(module), [:imports]),
          {callee, _fun, _arity} <- imports,
          path = :code.which(callee),
          is_list(path),
          List.starts_with?(path, otp_lib),
          app = owning_app(path, otp_lib),
          app not in [:kernel, :stdlib, :erts],
          uniq: true,
          do: app

    assert called -- declared == []
  end

  defp owning_app(path, otp_lib) do
    path
    |> Path.relative_to(List.to_string(otp_lib))
    |> Path.split()
    |> hd()
    |> String.split("-")
    |> hd()
    |> String.to_atom()
  end
end
