defmodule ExSandbox.CapabilityGatingDefaultsTest do
  @moduledoc """
  `Capability.known/0` is a reporting vocabulary; `Capability.gating_defaults/0`
  is a refusal gate. They were the same list until `014` T004 added
  `:time_budget` to `known/0`, and `ExSandbox.required_capabilities/1` falls
  back to the gate for any mechanism that omits the optional
  `c:ExSandbox.Mechanism.required_capabilities/0` callback.

  `:time_budget` is `unavailable` on **every** host by design -- it is a
  per-launch argument, not a host fact. A gate containing it can never be
  satisfied anywhere, which turns an optional callback into a mandatory one and
  reports the failure as a capability the operator cannot install rather than as
  the callback the mechanism forgot to write.

  These tests exist so that re-merging the two lists goes red instead of
  silently refusing every under-declaring mechanism on every host forever.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Capability
  alias ExSandbox.Sandbox

  defmodule DeclaresNothing do
    @moduledoc """
    A mechanism that omits `required_capabilities/0`. Its lifecycle callbacks
    are deliberately inert: the assertion is about what the gate asks of it
    *before* `provision/1` is ever reached, so reaching `provision/1` at all is
    itself an observable outcome.
    """
    @behaviour ExSandbox.Mechanism

    @impl true
    def provision(sandbox), do: {:ok, sandbox}

    @impl true
    def start(sandbox), do: {:ok, sandbox}

    @impl true
    def stop(sandbox), do: {:ok, sandbox}

    @impl true
    def destroy(_sandbox), do: :ok

    @impl true
    def status(_sandbox), do: {:ok, :stopped}

    @impl true
    def list_running, do: {:ok, []}

    @impl true
    def usage(_sandbox), do: {:ok, %{}}

    @impl true
    def execute(_sandbox, _command, _opts), do: {:error, {:could_not_run, :inert}}
  end

  describe "the two lists are kept apart" do
    test "every gated name is one the library knows how to check" do
      assert Capability.gating_defaults() -- Capability.known() == [],
             "a gate entry that check/1 does not understand cannot be satisfied"
    end

    test ":time_budget is in the vocabulary and never in the gate" do
      assert :time_budget in Capability.known(),
             "014 T004 put it in the report; this test guards the split, not the report"

      refute :time_budget in Capability.gating_defaults(),
             "unavailable on every host by design -- gating on it refuses every " <>
               "mechanism that omits required_capabilities/0, on every host, forever"
    end
  end

  describe "a mechanism that declares nothing" do
    test "is gated on gating_defaults/0, not on known/0" do
      sandbox = %Sandbox{
        id: "gate-#{System.unique_integer([:positive])}",
        owner_ref: "test",
        template_ref: "test"
      }

      expected = Capability.missing(Capability.gating_defaults())

      case ExSandbox.provision(DeclaresNothing, sandbox) do
        {:error, {:capability_unavailable, missing}} ->
          assert Enum.map(missing, & &1.name) == Enum.map(expected, & &1.name)

          refute :time_budget in Enum.map(missing, & &1.name),
                 "the fallback reached known/0 instead of gating_defaults/0"

        {:ok, provisioned} ->
          assert expected == [],
                 "provision succeeded while #{inspect(Enum.map(expected, & &1.name))} " <>
                   "was reported missing"

          assert provisioned.id == sandbox.id
      end
    end
  end
end
