defmodule ExSandbox.Test.IsolationLaunch do
  @moduledoc """
  Provisioning for the `@tag :isolation` tests, which run only where the
  mechanism can actually launch (005 T036a, `012-FR-016a`).

  ## Why this exists

  Every isolation test did `{:ok, provisioned} = Beam.provision(sandbox(tag))`.
  On a host where the mechanism correctly *refuses* — because a capability it
  requires is absent — that raises a `MatchError`, and the test reports a
  **failure of the guarantee it names**.

  ⚠️ Measured, and it is the reason this module exists: when
  `network_restriction` began reporting its true value, nineteen tests failed,
  including "a sandbox cannot see the platform's processes" and "one sandbox
  halting leaves the platform serving". Neither had stopped being true. There
  was simply no sandbox to try them in, because the mechanism refused to launch
  one — which is the *correct* behaviour, reported as a breach.

  That is the same false report the conformance census avoids with its third
  outcome (`capability_unavailable`), and these tests are the layer that never
  got it. `ExSandbox.Conformance.ResourceLimits` distinguishes
  `{:could_not_provision, _}` from a breach and is the model here.

  ## Why skip rather than pass

  A skipped test is visibly not run. A passing one claims a guarantee was
  demonstrated, and "the sandbox could not see the platform's processes because
  there was no sandbox" is exactly the vacuous pass this whole suite exists to
  eliminate — the `--unshare-net` shape, one layer up.

  The isolation suite already refuses to exit 0 having verified nothing
  (`run-isolation-tests.sh`), so a run where everything skips is caught there
  rather than mistaken for success here.
  """

  import ExUnit.Callbacks, only: [on_exit: 1]

  @doc """
  Provisions a sandbox, or skips the test naming what the host cannot do.

  ⚠️ Skips **only** on a refusal the mechanism itself reports — a missing
  capability, or `:mechanism_error` from a launch path that could not be built.
  Any other return still raises, because a mechanism returning something
  unexpected is a defect and must not be silently tolerated.
  """
  @spec provision_or_skip(module(), ExSandbox.Sandbox.t()) :: ExSandbox.Sandbox.t()
  def provision_or_skip(mechanism, sandbox) do
    case mechanism.provision(sandbox) do
      {:ok, provisioned} ->
        on_exit(fn -> mechanism.destroy(provisioned) end)
        provisioned

      {:error, {:capability_unavailable, missing}} ->
        names = missing |> Enum.map(& &1.name) |> Enum.join(", ")

        raise_skip("""
        host capability unavailable: #{names}

        The mechanism refused to provision, which is correct. This test cannot
        demonstrate its guarantee here, and reporting it as a failure would
        name a breach that did not happen.
        """)

      {:error, :mechanism_error} ->
        raise_skip("""
        the mechanism could not launch a sandbox on this host.

        `require_hardening/0` refuses when any required capability is missing,
        so this is a host limitation rather than a breach of the guarantee this
        test names. Run `ExSandbox.Hardening.Linux.capabilities/0` to see which.
        """)
    end
  end

  # ⚠️ `ExUnit` has no runtime skip, so this raises a recognisable error rather
  # than passing. The distinction that matters is visible-not-run versus
  # claimed-demonstrated; an erroring test is at least the former, and the
  # message says which capability is missing.
  #
  # ⚠️ The message is framed by `Conformance.Group.not_demonstrated/1`, and that
  # is the load-bearing part rather than a formatting nicety.
  # `Conformance.Census` classifies an outcome as the third one by matching the
  # marker that function produces, so a distinct exception type alone was not
  # enough: these nineteen tests raised `Unavailable`, carried no marker, and
  # were counted `failed`. Measured -- `passed=330 unavailable=0 failed=19`,
  # where every one of the nineteen names a guarantee that did not stop holding
  # and simply had no sandbox to be demonstrated in.
  #
  # Routing through the shared framing is also what keeps this from drifting:
  # the census's own moduledoc argues the marker must have exactly one producer,
  # and `ExSandbox.ConformanceExclusionsTest` fails if the wording moves.
  defp raise_skip(message) do
    # ⚠️ `Exception.exception/1` rather than the struct literal: the nested
    # `Unavailable` module is defined below this function, and a `%Mod{}` literal
    # is expanded at compile time, so it does not exist yet.
    exception = ExSandbox.Test.IsolationLaunch.Unavailable.exception(message)

    raise ExSandbox.Test.IsolationLaunch.Unavailable,
          ExSandbox.Conformance.Group.not_demonstrated(exception)
  end

  defmodule RefusingMechanism do
    @moduledoc """
    A mechanism that refuses to provision, so `provision_or_skip/2`'s refusal
    path can be driven for real in a test.

    Exists because the alternative — asserting on a marker string the test
    built itself — would keep passing if `raise_skip/1` stopped framing its
    message, which is the exact defect the test pins.
    """
    def provision(_sandbox), do: {:error, :mechanism_error}
  end

  defmodule Unavailable do
    @moduledoc """
    Raised when a host cannot run an isolation test at all.

    A distinct exception type so a reader — and a future runner that learns to
    count these separately — can tell "this host cannot demonstrate it" from
    "the guarantee was breached".
    """
    defexception [:message]
  end
end
