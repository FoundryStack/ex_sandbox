defmodule ExSandbox.Mechanism.Beam.AtomReclamationTest do
  @moduledoc """
  Stopping a sandbox reclaims its atom table (005 T035, `FR-006`, `SC-003`).

  ## Why this must run all 50 cycles

  Atoms are **never garbage collected**. A sandbox implemented as a supervised
  process tree inside the platform's VM therefore leaks its atom table
  permanently on every stop, and the platform eventually dies of
  `system_limit` — the failure `FR-006` exists to prevent.

  One cycle cannot distinguish that from a real boundary: a single sandbox's
  atoms are a rounding error either way. Only the **trend** across many cycles
  separates them. A shortened run is not a weaker version of this test, it is a
  different test that passes unconditionally, so the cycle count is load-bearing
  rather than a tuning knob.
  """
  use ExUnit.Case, async: false

  @moduletag :reclamation
  @moduletag timeout: 600_000

  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  @cycles 50
  @atoms_per_cycle 20_000

  test "50 launch/stop cycles creating atoms show no monotonic host growth" do
    samples =
      for cycle <- 1..@cycles do
        sb = %Sandbox{
          id: "atom-#{cycle}-#{System.unique_integer([:positive])}",
          owner_ref: "owner-atoms",
          template_ref: "conformance-template",
          cpu_limit: 500,
          memory_limit_mb: 256,
          disk_quota_mb: 64
        }

        {:ok, provisioned} = Beam.provision(sb)

        # Created inside the sandbox, from strings unique to this cycle, so the
        # atoms genuinely cannot be interned anywhere they already exist.
        #
        # ⚠️ Stdio, not `:erpc`: the sandbox has no network interfaces.
        Beam.call(
          provisioned,
          :erlang,
          :apply,
          # ⚠️ Pure Erlang -- `String.to_atom/1` is `:undef` inside the sandbox,
          # so the fun would die before interning anything and the host's atom
          # count would stay flat for the wrong reason: this test would report
          # "no monotonic growth" having created no atoms at all.
          [create_atoms(@atoms_per_cycle), []],
          60_000
        )

        :ok = Beam.destroy(provisioned)

        # Measured on the *host*, which is the thing `FR-006` protects. The
        # sandbox's own count is irrelevant once it is gone -- unless it was
        # never really separate, which is what this measurement detects.
        :erlang.garbage_collect()
        %{cycle: cycle, host_atoms: :erlang.system_info(:atom_count)}
      end

    first_ten = samples |> Enum.take(10) |> Enum.map(& &1.host_atoms) |> average()
    last_ten = samples |> Enum.take(-10) |> Enum.map(& &1.host_atoms) |> average()
    growth = last_ten - first_ten

    # 50 cycles x 20k atoms = 1M atoms if none are reclaimed. A tolerance of a
    # few thousand absorbs the test suite's own atom use while remaining three
    # orders of magnitude below a genuine leak.
    assert growth < 5_000,
           """
           the host's atom table grew by #{round(growth)} atoms across #{@cycles} cycles.

           first 10 cycles averaged #{round(first_ten)}, last 10 averaged #{round(last_ten)}.

           Atoms are never garbage collected, so growth proportional to the
           cycle count means sandbox atoms are being interned in the PLATFORM's
           table -- the sandbox is not a separate OS process, and the platform
           will eventually die of system_limit (FR-006).
           """
  end

  defp average(values), do: Enum.sum(values) / length(values)

  # ⚠️ A **self-contained** fun: a capture would reference this test module,
  # which the sandbox cannot load, so it would die with `:undef` having interned
  # nothing -- and the host's atom count would stay flat for the wrong reason,
  # reporting "no monotonic growth" from a test that created no atoms.
  #
  # `:erlang.list_to_atom/1` is the OTP primitive behind `String.to_atom/1`
  # (itself `:undef` there). The uniqueness of each string is what makes the
  # atoms genuinely new rather than interned copies of existing ones.
  defp create_atoms(count) do
    fn ->
      make = fn
        _make, 0 ->
          :ok

        make, n ->
          _ =
            :erlang.list_to_atom(
              ~c"sandbox_atom_" ++
                :erlang.integer_to_list(:erlang.unique_integer([:positive])) ++
                ~c"_" ++ :erlang.integer_to_list(n)
            )

          make.(make, n - 1)
      end

      make.(make, count)
    end
  end
end
