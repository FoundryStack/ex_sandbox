defmodule ExSandbox.Capability do
  @moduledoc """
  What this library needs from its host, and whether it is actually there
  (012 T013, T022, FR-016).

  ## Determined, never assumed

  `FR-016` requires a library state what it needs and **report at runtime when
  it is unavailable**, rather than assuming it. The distinction is not academic:
  `005` R9 found that six of ten isolation criteria require Linux, and `013`
  Finding V2 found a capability that is absent under some container
  configurations. A library that assumed them would provide no isolation on
  those hosts while claiming to.

  ## Availability is evidence, not configuration

  A capability is reported available only on `FR-012a`'s evidence standard —
  observed behaviour, not the presence of a mechanism. `005` R9b measured the
  failure this guards against: `taskpolicy -m 100 sandbox-exec ... ./hog 300`
  allocates 300 MB under a nominal 100 MB cap and exits 0, because the limit is
  silently lost across the intervening `exec`. Every check short of *trigger a
  breach and watch it stop* reports that composition as working.

  So a check here answers "could this host enforce the cap at all", and it
  errs toward `false`. Whether a **particular mechanism** actually enforces it
  is `ExSandbox.Conformance`'s question, answered by breaching it.
  """

  @type name :: :resource_limits | :filesystem_confinement | :privilege_separation

  @type t :: %__MODULE__{
          name: name(),
          available?: boolean(),
          detail: String.t() | nil
        }

  @enforce_keys [:name, :available?]
  defstruct [:name, :available?, :detail]

  @known [:resource_limits, :filesystem_confinement, :privilege_separation]

  @doc "Every capability this library knows how to check."
  @spec known() :: [name()]
  def known, do: @known

  @doc """
  Checks one capability against the running host.

  Returns a report; it never raises, because "cannot determine" is a legitimate
  answer that must be *reported* rather than thrown (`FR-012b`).
  """
  @spec check(name() | atom()) :: t()
  def check(name) when name in @known do
    do_check(name, :os.type())
  end

  # ⚠️ An unknown name is **reported**, not raised. The docstring above promises
  # this function never raises because "cannot determine" is a legitimate answer,
  # and a `FunctionClauseError` here breaks that promise exactly where it matters
  # most: a mechanism whose `required_capabilities/0` names something this
  # library has not heard of would crash every caller that tried to check it --
  # including `ExSandbox.Conformance`, whose whole job is to *report* on hosts
  # rather than blow up on them. Measured: `Mechanism.Beam` returned
  # `:process_isolation` and the conformance suite died with a
  # `FunctionClauseError` instead of reporting anything.
  #
  # `available?: false` is the safe direction. An unrecognised capability is one
  # nothing has verified, and treating it as satisfied is the fail-open shape
  # this module exists to prevent.
  def check(name) when is_atom(name) do
    %__MODULE__{
      name: name,
      available?: false,
      detail:
        "unknown capability #{inspect(name)}; this library knows #{inspect(@known)}. " <>
          "A mechanism requiring it must either use a known name or extend this module."
    }
  end

  @doc "Checks every known capability."
  @spec check_all() :: [t()]
  def check_all, do: Enum.map(@known, &check/1)

  @doc """
  True when every capability in `required` is available.

  This is what an entry point calls before starting a sandbox: a mechanism whose
  required capability is missing must refuse rather than start unconfined
  (spec Edge Cases; `005` R9's macOS rule).
  """
  @spec satisfied?([name()]) :: boolean()
  def satisfied?(required) do
    Enum.all?(required, fn name -> check(name).available? end)
  end

  @doc """
  The capabilities in `required` that this host cannot provide.

  Returned rather than raised so a caller can report *which* one is missing —
  "unavailable" with no detail is the kind of message that gets ignored.
  """
  @spec missing([name()]) :: [t()]
  def missing(required) do
    required
    |> Enum.map(&check/1)
    |> Enum.reject(& &1.available?)
  end

  # cgroup v2 is the only mechanism here that caps memory in a way that survives
  # an intervening exec (005 R9b). Its absence is not a degraded mode -- it means
  # a cap can be configured and silently not apply, so this reports false.
  defp do_check(:resource_limits, {:unix, :linux}) do
    if File.exists?("/sys/fs/cgroup/cgroup.controllers") do
      available(:resource_limits)
    else
      unavailable(
        :resource_limits,
        "cgroup v2 is not mounted at /sys/fs/cgroup; memory and CPU caps cannot be enforced"
      )
    end
  end

  defp do_check(:resource_limits, {:unix, :darwin}) do
    unavailable(
      :resource_limits,
      "macOS `taskpolicy -m` applies to its immediate child only and is silently " <>
        "lost across an intervening exec (005 R9b), so a configured cap is not an " <>
        "enforced cap"
    )
  end

  defp do_check(:filesystem_confinement, {:unix, :linux}) do
    cond do
      executable?("bwrap") ->
        available(:filesystem_confinement)

      File.exists?("/proc/self/ns/mnt") ->
        available(:filesystem_confinement)

      true ->
        unavailable(
          :filesystem_confinement,
          "neither bubblewrap nor mount namespaces are available"
        )
    end
  end

  defp do_check(:filesystem_confinement, {:unix, :darwin}) do
    if executable?("sandbox-exec") do
      available(:filesystem_confinement)
    else
      unavailable(:filesystem_confinement, "sandbox-exec not found")
    end
  end

  defp do_check(:privilege_separation, {:unix, _}) do
    # Dropping to an unprivileged uid needs privilege to start with.
    case System.cmd("id", ["-u"], stderr_to_stdout: true) do
      {"0\n", 0} ->
        available(:privilege_separation)

      {_, 0} ->
        unavailable(
          :privilege_separation,
          "not running as root, so the sandbox cannot drop to a separate uid"
        )

      _ ->
        unavailable(:privilege_separation, "could not determine the effective uid")
    end
  end

  # Anything unrecognised reports unavailable rather than assuming. Under-
  # claiming on an unknown host is FR-012b's rule.
  defp do_check(name, os) do
    unavailable(name, "unsupported host: #{inspect(os)}")
  end

  defp executable?(name), do: System.find_executable(name) != nil

  defp available(name), do: %__MODULE__{name: name, available?: true, detail: nil}

  defp unavailable(name, detail),
    do: %__MODULE__{name: name, available?: false, detail: detail}
end
