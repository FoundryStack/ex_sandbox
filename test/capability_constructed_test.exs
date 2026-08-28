defmodule ExSandbox.CapabilityConstructedTest do
  @moduledoc """
  `ExSandbox.Capability.check/1` asks the *host* a question. That is the right
  question for `Mechanism.Beam`, which confines a process using the host's own
  kernel, and the wrong one for any mechanism that brings its own kernel: a
  container gets a mount namespace from the container runtime whether or not
  the macOS host can make one, so a host-keyed probe refuses a mechanism that
  would in fact have worked.

  `c:ExSandbox.Mechanism.constructed_capabilities/0` is the seam. It does not
  weaken the gate -- what a mechanism does not claim, the host must still
  provide -- and it is a claim, not a proof: `ExSandbox.Conformance` is what
  establishes the claim by watching a breach be stopped.

  These tests pin the arithmetic in `ExSandbox.ensure_capable/2`, so that
  widening the gate cannot quietly become opening it.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Capability
  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  # Every stub is inert past the gate on purpose: reaching `provision/1` at all
  # is the observable outcome, so the callback only has to be distinguishable
  # from a refusal.
  defmodule Stub do
    @moduledoc false

    defmacro __using__(_opts) do
      quote do
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
    end
  end

  defmodule ReportsNothing do
    @moduledoc """
    Declares what it needs and stays silent about what it builds -- the shape
    of every mechanism written before the callback existed.
    """
    use Stub

    @impl true
    def required_capabilities, do: Beam.required_capabilities()
  end

  defmodule ConstructsWhatItNeeds do
    @moduledoc """
    A container-shaped mechanism: it needs the gate's full list and reports
    building all of it itself.
    """
    use Stub

    @impl true
    def required_capabilities, do: Capability.gating_defaults()

    @impl true
    def constructed_capabilities, do: Capability.gating_defaults()
  end

  defmodule ConstructsAllButOne do
    @moduledoc """
    The same mechanism with one honest omission. `:filesystem_confinement` is
    left for the host to provide, so on a host without it the refusal must name
    that name and no other.
    """
    use Stub

    @impl true
    def required_capabilities, do: Capability.gating_defaults()

    @impl true
    def constructed_capabilities, do: Capability.gating_defaults() -- [:filesystem_confinement]
  end

  defp sandbox do
    %Sandbox{
      id: "constructed-#{System.unique_integer([:positive])}",
      owner_ref: "test",
      template_ref: "test"
    }
  end

  defp gate(mechanism), do: ExSandbox.provision(mechanism, sandbox())

  defp refused_names({:error, {:capability_unavailable, missing}}),
    do: Enum.map(missing, & &1.name)

  defp refused_names({:ok, _sandbox}), do: []

  describe "a mechanism that reports nothing constructed" do
    test "is gated exactly as it was before the callback existed" do
      # The pre-existing gate, restated independently of ensure_capable/2: the
      # host probe over the mechanism's own required list, with nothing
      # subtracted.
      expected = Enum.map(Capability.missing(Beam.required_capabilities()), & &1.name)

      assert refused_names(gate(ReportsNothing)) == expected,
             "absent constructed_capabilities/0 must subtract [], not widen the gate"
    end
  end

  describe "a mechanism that reports constructing what the host lacks" do
    test "is permitted to provision" do
      # The host's own answer, recorded so a green run on a host that provides
      # everything is not mistaken for proof that the seam works. On darwin all
      # five gated names are unavailable, so this is a real widening; on a host
      # that reports none missing the assertion still holds but shows nothing.
      host_lacks = Enum.map(Capability.missing(Capability.gating_defaults()), & &1.name)

      assert {:ok, provisioned} = gate(ConstructsWhatItNeeds)
      assert provisioned.owner_ref == "test"

      if host_lacks == [] do
        IO.puts(
          "\n  note: this host provides every gated capability, so the assertion above " <>
            "passes without exercising the widening."
        )
      end
    end
  end

  describe "a mechanism whose report leaves a required capability unaccounted for" do
    test "is refused naming exactly that capability" do
      unaccounted = Capability.missing([:filesystem_confinement])

      case gate(ConstructsAllButOne) do
        {:error, {:capability_unavailable, missing}} ->
          assert Enum.map(missing, & &1.name) == [:filesystem_confinement],
                 "the refusal must name the capability nobody provides, and only that one"

          refute unaccounted == [],
                 "refused on a host where the probe says :filesystem_confinement is available"

        {:ok, _provisioned} ->
          assert unaccounted == [],
                 "provisioned while :filesystem_confinement was neither constructed nor " <>
                   "available on this host"
      end
    end
  end
end
