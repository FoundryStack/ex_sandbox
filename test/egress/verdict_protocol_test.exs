defmodule ExSandbox.Egress.VerdictProtocolTest do
  @moduledoc """
  The two ends of the verdict protocol, driven against each other (005 T060a1).

  `verdict_test.exs` checks the Elixir side against itself. That is not enough,
  and the reason is a bug this file exists because of: the server replied
  `"PERMIT"` without a newline while both ends framed with `packet: :line`, so
  the caller blocked until close and read `{:error, :closed}`.

  ⚠️ The acceptor treats any unreadable verdict as DENY. So the symptom of that
  framing mismatch was **every destination silently refused** — blanket denial
  wearing the appearance of a working allowlist, which passes every denial check
  in the conformance suite. It is precisely the failure T060 exists to end, and
  no single-language test could have seen it.

  So the real Python helper is imported and its real `ask_platform` is called
  against a real `Verdict` server.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Registry
  alias ExSandbox.Egress.Verdict

  @source_key {10, 0, 4, 0}
  @allowed {"api.example.com", 443}

  setup_all do
    case System.find_executable("python3") do
      nil -> {:ok, python: nil}
      path -> {:ok, python: path}
    end
  end

  setup %{python: python} do
    if is_nil(python) do
      # ⚠️ Skipped honestly rather than passed vacuously. A host without
      # python3 cannot run the helper, and reporting a pass here would claim
      # the two ends agree on a host where neither was executed.
      :ok
    else
      :ok
    end

    registry =
      start_supervised!({Registry, name: :"vp_reg_#{System.unique_integer([:positive])}"})

    path =
      Path.join(System.tmp_dir!(), "axonn-vp-#{System.unique_integer([:positive])}.sock")

    start_supervised!(
      {Verdict,
       name: :"vp_srv_#{System.unique_integer([:positive])}", path: path, registry: registry}
    )

    :ok = Registry.assign(@source_key, [@allowed], registry)
    on_exit(fn -> File.rm(path) end)

    %{path: path}
  end

  describe "the helper's ask_platform/4 against a real verdict server" do
    test "a permitted destination is True", %{path: path, python: python} do
      assert ask(python, path, "api.example.com", 443) == "True"
    end

    test "a denied destination is False", %{path: path, python: python} do
      assert ask(python, path, "evil.example.com", 443) == "False"
    end

    test "the port is part of the agreement", %{path: path, python: python} do
      assert ask(python, path, "api.example.com", 80) == "False"
    end

    test "an unreachable verdict socket is False, never True", %{python: python} do
      # ⚠️ The fail-closed rule, stated where it can be checked. A platform that
      # cannot be reached must not widen the boundary -- "allow on error" here
      # makes a dead supervisor indistinguishable from a permissive allowlist.
      missing = Path.join(System.tmp_dir!(), "axonn-vp-absent.sock")
      File.rm(missing)
      assert ask(python, missing, "api.example.com", 443) == "False"
    end
  end

  defp ask(nil, _path, _host, _port), do: flunk("python3 is required to run this test")

  defp ask(python, path, host, port) do
    helper = Path.join([__DIR__, "..", "..", "priv", "egress", "nsacceptor.py"])

    script = """
    import importlib.util
    spec = importlib.util.spec_from_file_location("nsacceptor", "#{Path.expand(helper)}")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    print(m.ask_platform("#{path}", "10.0.4.0", "#{host}", #{port}))
    """

    {out, 0} = System.cmd(python, ["-c", script])
    String.trim(out)
  end
end
