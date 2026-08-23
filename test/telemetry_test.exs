defmodule ExSandbox.TelemetryTest do
  @moduledoc """
  Events carry the opaque `owner_ref` and leave attribution to the host
  (012 T043).

  The library has no tenant concept and cannot decompose `owner_ref` — `FR-007`
  makes it opaque precisely so it cannot try. What these tests establish is that
  the value arrives at a handler **unaltered**, which is what makes host-side
  attribution possible at all.

  The recorded mismatches with `010-observability` are in `ExSandbox.Telemetry`'s
  moduledoc; the last test here keeps them from being quietly dropped.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Conformance.Helpers

  defp attach(events) do
    handler = "test-#{System.unique_integer([:positive])}"
    parent = self()

    :telemetry.attach_many(
      handler,
      events,
      fn event, measurements, metadata, _ ->
        send(parent, {:telemetry, event, measurements, metadata})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler) end)
  end

  describe "lifecycle spans carry owner_ref (T043)" do
    test "provision emits a span with the owner attached" do
      attach([[:ex_sandbox, :provision, :start], [:ex_sandbox, :provision, :stop]])

      sandbox = Helpers.build_sandbox(owner_ref: "tenant-abc")
      {:ok, _} = ExSandbox.provision(ExSandbox.EchoMechanism, sandbox)

      assert_received {:telemetry, [:ex_sandbox, :provision, :start], _,
                       %{owner_ref: "tenant-abc"}}

      assert_received {:telemetry, [:ex_sandbox, :provision, :stop], %{duration: _},
                       %{owner_ref: "tenant-abc", result: :ok}}
    end

    test "start, stop and destroy each emit" do
      attach([
        [:ex_sandbox, :start, :stop],
        [:ex_sandbox, :stop, :stop],
        [:ex_sandbox, :destroy, :stop]
      ])

      sandbox = Helpers.build_sandbox(owner_ref: "tenant-xyz")
      {:ok, s} = ExSandbox.provision(ExSandbox.EchoMechanism, sandbox)
      {:ok, s} = ExSandbox.start(ExSandbox.EchoMechanism, s)
      {:ok, s} = ExSandbox.stop(ExSandbox.EchoMechanism, s)
      :ok = ExSandbox.destroy(ExSandbox.EchoMechanism, s)

      assert_received {:telemetry, [:ex_sandbox, :start, :stop], _, %{owner_ref: "tenant-xyz"}}
      assert_received {:telemetry, [:ex_sandbox, :stop, :stop], _, %{owner_ref: "tenant-xyz"}}
      assert_received {:telemetry, [:ex_sandbox, :destroy, :stop], _, %{owner_ref: "tenant-xyz"}}
    end
  end

  describe "owner_ref is propagated, never interpreted (FR-007)" do
    test "a structured owner_ref reaches the handler byte-for-byte" do
      attach([[:ex_sandbox, :provision, :stop]])

      # Shapes a library might be tempted to parse: a delimiter, a path, a
      # null byte, quotes.
      hostile = "tenant:42/project/../x\0' OR 1=1"
      sandbox = Helpers.build_sandbox(owner_ref: hostile)
      {:ok, _} = ExSandbox.provision(ExSandbox.EchoMechanism, sandbox)

      assert_received {:telemetry, [:ex_sandbox, :provision, :stop], _, metadata}
      assert metadata.owner_ref == hostile
    end

    test "no event metadata contains a decomposition of owner_ref" do
      attach([[:ex_sandbox, :provision, :stop]])

      sandbox = Helpers.build_sandbox(owner_ref: "tenant:42:project:9")
      {:ok, _} = ExSandbox.provision(ExSandbox.EchoMechanism, sandbox)

      assert_received {:telemetry, [:ex_sandbox, :provision, :stop], _, metadata}

      # A `tenant_id` key here would mean the library split the opaque value --
      # exactly what FR-007 forbids, and what 010-FR-002 might tempt someone
      # into adding.
      refute Map.has_key?(metadata, :tenant_id)
      refute Map.has_key?(metadata, :project_id)
    end
  end

  describe "failure causes stay distinguishable (010-FR-004)" do
    defmodule FailingMechanism do
      @moduledoc false
      @behaviour ExSandbox.Mechanism
      @impl true
      def execute(_sandbox, {_cmd, _args}, _opts \\ []),
        do: {:error, {:could_not_run, :not_supported}}

      @impl true
      def required_capabilities, do: []
      @impl true
      def provision(_s), do: {:error, {:image_pull_failed, "no such template"}}
      @impl true
      def start(s), do: {:ok, s}
      @impl true
      def stop(s), do: {:ok, s}
      @impl true
      def destroy(_s), do: :ok
      @impl true
      def status(_s), do: {:ok, :absent}
      @impl true
      def list_running, do: {:ok, []}
      @impl true
      def usage(_s), do: {:ok, %{}}
    end

    test "a specific error reaches the handler without being flattened" do
      attach([[:ex_sandbox, :provision, :stop]])

      {:error, _} =
        ExSandbox.provision(FailingMechanism, Helpers.build_sandbox(owner_ref: "t"))

      assert_received {:telemetry, [:ex_sandbox, :provision, :stop], _, metadata}

      # Collapsing this to `:error` is the cheapest thing to get wrong and the
      # thing that makes a telemetry stream useless for diagnosis.
      assert metadata.result == {:error, {:image_pull_failed, "no such template"}}
    end
  end

  describe "capability refusals are visible" do
    defmodule NeedsEverything do
      @moduledoc false
      @behaviour ExSandbox.Mechanism
      @impl true
      def execute(_sandbox, {_cmd, _args}, _opts \\ []),
        do: {:error, {:could_not_run, :not_supported}}

      # ⚠️ Requires a capability **no host provides**, rather than relying on the
      # host lacking one of the real ones.
      #
      # This previously declared nothing, which the caller treats as "requires
      # every capability" -- a refusal on any host missing one. That made the
      # test pass on macOS and fail in the isolation container, because the
      # container genuinely provides all five: provision succeeded, correctly,
      # and the assertion of a refusal had nothing to catch. The check was
      # measuring the host's poverty rather than the refusal path.
      @impl true
      def required_capabilities, do: [:no_host_provides_this]

      @impl true
      def provision(s), do: {:ok, s}
      @impl true
      def start(s), do: {:ok, s}
      @impl true
      def stop(s), do: {:ok, s}
      @impl true
      def destroy(_s), do: :ok
      @impl true
      def status(_s), do: {:ok, :absent}
      @impl true
      def list_running, do: {:ok, []}
      @impl true
      def usage(_s), do: {:ok, %{}}
    end

    test "a refusal to provision emits rather than failing silently" do
      attach([[:ex_sandbox, :capability, :unavailable]])

      {:error, {:capability_unavailable, _}} =
        ExSandbox.provision(NeedsEverything, Helpers.build_sandbox(owner_ref: "t"))

      assert_received {:telemetry, [:ex_sandbox, :capability, :unavailable], %{count: 1},
                       %{owner_ref: "t", missing: missing}}

      assert missing != []
    end
  end

  describe "the 010 mismatch stays recorded (T043)" do
    test "the moduledoc still names both unresolved requirements" do
      {:docs_v1, _, _, _, %{"en" => doc}, _, _} = Code.fetch_docs(ExSandbox.Telemetry)

      # T043 asks that any mismatch with 010's actual requirements be recorded
      # rather than adapted to silently. If someone later "fixes" this by
      # deleting the note, 010's implementation loses the finding.
      assert doc =~ "010-FR-002",
             "the recorded attribution mismatch with 010-FR-002 was removed"

      assert doc =~ "010-FR-006",
             "the recorded redaction mismatch with 010-FR-006 was removed"
    end
  end
end
