defmodule ExSandbox.Egress.ContextFieldsTest do
  @moduledoc """
  The shape of the three egress fields a mechanism publishes for the network
  conformance group (005 T060a4, `005-FR-011e`).

  ## Why shape is worth its own suite

  `context` is documented as propagated and never parsed -- by *callers*. The
  conformance suite is the one component that does parse it, and it parses by
  pattern match:

      defp sandbox_address(_mechanism, %{context: %{address: {host, port}}}), do: {:ok, {host, port}}
      defp sandbox_address(_mechanism, _sandbox), do: :unknown

  A value of the wrong shape does not raise and does not fail. It falls to the
  second clause, and the check reports `capability_unavailable` -- whose message
  reads *"this mechanism's sandbox `context` carries no `:address`"*.

  ⚠️ **That message is wrong in exactly the way that is hardest to notice.** The
  BEAM mechanism published `address: "peer:" <> sandbox.id` -- present,
  non-empty, and satisfying `FR-022`'s reachability check, which asks only that
  *something* came back. The network group asks for `{host, port}` and saw
  nothing. So the census recorded an unbuilt boundary for a mechanism that had
  published an address, and the census entry told a reader to go implement a
  thing that already existed.

  Two consumers, one key, different contracts, and no disagreement visible from
  either side alone. These tests hold both against the same value.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Conformance.Reachability
  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  defp sandbox(context) do
    %Sandbox{
      id: "fields-#{System.unique_integer([:positive])}",
      owner_ref: "tenant-a",
      template_ref: nil,
      context: context
    }
  end

  # The network group's accessors are private, so these mirror their *match*
  # exactly. A mirror is acceptable here and a reimplementation would not be:
  # the thing under test is whether a published value satisfies a pattern, and
  # the pattern is copied character for character rather than paraphrased.
  defp network_reads_address?(%Sandbox{context: %{address: {_host, _port}}}), do: true
  defp network_reads_address?(_), do: false

  defp network_reads_permitted?(%Sandbox{context: %{permitted: {_host, _port}}}), do: true
  defp network_reads_permitted?(_), do: false

  defp published(host_context) do
    base = sandbox(host_context)
    %{base | context: Beam.context_for(base)}
  end

  describe ":address is not published in a shape the network group will dial" do
    test "the address stays out of reach of the peer-crossing probe until a listener exists" do
      # ⚠️ This asserts the *opposite* of what it first asserted, and the
      # reversal is the finding.
      #
      # The observation that started this: `Reachability.addressed?/1` accepts
      # `"peer:" <> id` and `Network.sandbox_address/2` does not, so the census
      # reports "carries no `:address`" for a mechanism that publishes one. That
      # much is true. The conclusion drawn from it -- publish a tuple so both
      # consumers can read it -- was wrong, and passed a shape test while making
      # the system worse.
      #
      # Trace what the network group does with `{"peer", sandbox_id}`:
      #
      #   1. `sandbox_address/2` matches and returns `{:ok, {"peer", id}}`,
      #   2. `probe_connect/5` hands both halves to `context.connect`,
      #   3. `connect_from_sandbox/3` calls `:gen_tcp.connect(~c"peer", id, ...)`,
      #   4. that fails, and the clause returns `:refused`,
      #   5. the group scores `:refused` as **the boundary holding**.
      #
      # `003-FR-002` would be reported as demonstrated by a mechanism that never
      # attempted a crossing -- an honest `capability_unavailable` converted into
      # a false pass by a change that looks like a type fix.
      #
      # So the string stays until the sandbox has a real listener, and this test
      # exists to stop the tuple being reintroduced by someone who notices the
      # same mismatch and reaches for the same fix.
      published = published(%{})

      refute network_reads_address?(published),
             """
             `context.address` now matches `{host, port}`, so `Conformance.Network`
             will dial it. Unless this sandbox has a real listener, that connect
             fails, scores `:refused`, and reports `003-FR-002` as demonstrated
             without a crossing ever being attempted.

             Got: #{inspect(Map.get(published.context, :address))}

             A tuple here is only correct once it names a socket something is
             listening on.
             """
    end

    test "the address still satisfies FR-022, which asks only that one comes back" do
      # The other half of the two-consumers-one-key pair. `FR-022` is satisfied
      # by any non-empty value, and dropping `:address` entirely to silence the
      # network group would break it -- the opposite over-correction.
      published = published(%{})

      assert Reachability.addressed?(published),
             "no address came back at all, which `003-FR-022` requires independently of the network group"
    end
  end

  describe ":permitted is drawn from the tenant's own allowlist" do
    test "a permitted destination is published when the environment names one" do
      # The allowlist is the value the T060a2 merge fix rescued: resolved by
      # `Axonn.Sandbox.Provision`, carried in `context`, and -- until that fix --
      # discarded here. Publishing `:permitted` is what finally *reads* it, so
      # this is also the first test that would fail if the merge regressed.
      published = published(%{network_allowlist: [{"example.com", 443}]})

      assert network_reads_permitted?(published),
             "no `:permitted` was published from an allowlist that names one, so `FR-011a` " <>
               "cannot be established by connecting to a destination that should work"

      assert Map.get(published.context, :permitted) == {"example.com", 443}
    end

    test "an empty allowlist publishes no permitted destination" do
      # ⚠️ Absent, not a placeholder. The check's `:no_allowlist` branch reports
      # the third outcome, which is honest. A fabricated destination would be
      # probed, would fail to connect because nothing is there, and a *failure to
      # reach a permitted host* scores as the boundary being too tight rather
      # than as the fiction it is.
      published = published(%{network_allowlist: []})

      refute Map.has_key?(published.context, :permitted),
             "an empty allowlist published a permitted destination it cannot honour"
    end

    test "a sandbox provisioned without any allowlist key publishes none" do
      published = published(%{})

      refute Map.has_key?(published.context, :permitted)
    end

    test "an :any_port entry is not published as a permitted destination" do
      # ⚠️ The case a reader is most likely to wave through. `:any_port` is a
      # valid allowlist entry and it is *not* a port -- `{"example.com",
      # :any_port}` published verbatim matches the suite's `{host, port}`
      # pattern, so the check would proceed and hand `:any_port` to
      # `:gen_tcp.connect/4`, which cannot dial it.
      #
      # The connect fails, and a failed connect to a *permitted* destination is
      # scored as a boundary that is too restrictive: a real failure reported
      # against a mechanism that did nothing wrong, caused entirely by this
      # module publishing a value it had no business publishing.
      published = published(%{network_allowlist: [{"example.com", :any_port}]})

      refute Map.has_key?(published.context, :permitted),
             "`:any_port` was published as a port; the suite will dial it and score the failure against the boundary"
    end

    test "a concrete entry is preferred over an :any_port entry in the same allowlist" do
      # Order-independent: the concrete entry is dialable and the wildcard is
      # not, so the choice is driven by what can actually be probed rather than
      # by list position.
      wildcard_first =
        published(%{network_allowlist: [{"example.com", :any_port}, {"api.example.com", 443}]})

      assert Map.get(wildcard_first.context, :permitted) == {"api.example.com", 443}

      wildcard_last =
        published(%{network_allowlist: [{"api.example.com", 443}, {"example.com", :any_port}]})

      assert Map.get(wildcard_last.context, :permitted) == {"api.example.com", 443}
    end
  end

  describe ":permitted is derived, never accepted from the host" do
    test "a host-supplied permitted destination does not survive an empty allowlist" do
      # ⚠️ This test exists because **two sabotages passed without it**, and the
      # gap they exposed was real rather than a testing artefact.
      #
      # Reordering the merge so the host's context won was invisible: `published`
      # carries `:address`, `:exec`, and `:connect`, so the merge protects those
      # three and `:permitted` was never among them. Nothing to clobber means
      # nothing to notice.
      #
      # Measured before the fix: a host passing `permitted: {"evil.example.com",
      # 443}` with an **empty** allowlist had it published verbatim. The network
      # group dials whatever this key names and scores the outcome as `FR-011a`
      # evidence -- so the check would report on a destination the mechanism
      # never authorized, chosen by the party the check exists to constrain.
      #
      # This is the same provenance defect 673373b closed for `:address` and
      # `:connect`, in the one field that fix did not reach.
      published = published(%{network_allowlist: [], permitted: {"evil.example.com", 443}})

      refute Map.has_key?(published.context, :permitted),
             "a host-supplied `:permitted` survived: the network group would probe " <>
               "`#{inspect(Map.get(published.context, :permitted))}`, which no allowlist authorized"
    end

    test "a host-supplied permitted destination loses to the one the allowlist names" do
      # The other direction. Above, the host wins by default because nothing
      # overwrites it; here it must lose to a real derivation rather than merely
      # coexisting with one.
      published =
        published(%{
          network_allowlist: [{"api.example.com", 443}],
          permitted: {"evil.example.com", 443}
        })

      assert Map.get(published.context, :permitted) == {"api.example.com", 443},
             "the host's destination outranked the tenant's own allowlist"
    end
  end
end
