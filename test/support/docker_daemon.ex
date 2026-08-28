defmodule ExSandbox.Test.DockerDaemon do
  @moduledoc """
  One answer to "can this host run a container right now", shared by
  `test_helper.exs` (which decides the `:docker` exclusion) and by the tests
  themselves (which must be able to say the same thing back).

  ⚠️ Asked of the **daemon**, not of the executable. Docker Desktop leaves
  `/usr/local/bin/docker` on `PATH` with the VM stopped, so `find_executable/1`
  answers yes on a host where every `docker create` fails; excluding on the
  binary alone would let the whole group run and fail against a daemon that is
  not there. `docker version` is the cheapest call that reaches the server --
  its `{{.Server.Version}}` field is only rendered once the client has talked to
  one.

  ⚠️ The result is cached in `:persistent_term`. The probe shells out, the
  `:docker` group will ask this question many times, and -- more importantly --
  a probe that could answer differently between the exclusion decision and the
  test body would produce exactly the silent-skip this tag exists to prevent.
  One answer per suite run, taken before anything is excluded.
  """

  @key {__MODULE__, :probe}

  @typedoc "`{:ok, server_version}` or `{:error, human-readable reason}`."
  @type probe :: {:ok, String.t()} | {:error, String.t()}

  @doc "True when a container runtime answered on this host."
  @spec reachable?() :: boolean()
  def reachable?, do: match?({:ok, _version}, probe())

  @doc """
  Why the daemon is unreachable, phrased for an operator reading a banner.

  Returns `nil` when it is reachable, so a caller can pattern-match rather than
  parse.
  """
  @spec unreachable_reason() :: String.t() | nil
  def unreachable_reason do
    case probe() do
      {:ok, _version} -> nil
      {:error, reason} -> reason
    end
  end

  @doc "The cached probe. Runs at most once per suite run."
  @spec probe() :: probe()
  def probe do
    case :persistent_term.get(@key, :unset) do
      :unset ->
        result = run_probe()
        :persistent_term.put(@key, result)
        result

      cached ->
        cached
    end
  end

  defp run_probe do
    if System.find_executable("docker") do
      ask_daemon()
    else
      {:error, "no `docker` executable on PATH"}
    end
  rescue
    # `System.cmd/3` raises rather than returning when the executable vanishes
    # between the lookup and the call, and a raise here would abort the suite
    # before a single test ran -- a harsher outcome than the absence deserves.
    error -> {:error, Exception.message(error)}
  end

  defp ask_daemon do
    case System.cmd("docker", ["version", "--format", "{{.Server.Version}}"],
           stderr_to_stdout: true
         ) do
      {output, 0} ->
        {:ok, output |> String.trim() |> first_line()}

      {output, status} ->
        {:error, "`docker version` exited #{status}: #{first_line(output)}"}
    end
  end

  defp first_line(output) do
    output
    |> String.split("\n", trim: true)
    |> List.first()
    |> Kernel.||("(no output)")
  end
end
