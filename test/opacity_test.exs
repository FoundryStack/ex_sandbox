defmodule ExSandbox.OpacityTest do
  @moduledoc """
  `owner_ref`, `mechanism_ref`, and `context` are carried, never interpreted
  (012 T018, FR-007, FR-003).

  These three fields are the seam that lets a host keep its own concepts out of
  the library. The moment library code parses an `owner_ref` — splits it on a
  delimiter, checks a prefix, branches on its shape — the host is no longer free
  to supply whatever it likes, and `FR-003` ("no particular multi-tenancy model")
  becomes false without anyone having decided to make it false.

  So this test asserts two different things: that the values survive a round
  trip byte-identical, and that no library source file looks inside them.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Sandbox

  @mechanism ExSandbox.EchoMechanism

  # Deliberately hostile shapes. Each is a value some host might plausibly use
  # and a naive library might try to be clever about.
  @owner_refs [
    "tenant_01a006b2-025d-7e22-b2ad-cadeb56a6a0b",
    "acct:12345",
    "",
    "not/a/uuid at all",
    "{\"json\":\"looking\"}",
    "  leading and trailing  "
  ]

  defp sandbox(overrides) do
    struct!(
      %Sandbox{
        id: "sb-#{System.unique_integer([:positive])}",
        owner_ref: "owner-1",
        template_ref: "template-1"
      },
      overrides
    )
  end

  describe "opaque values survive a full lifecycle (FR-007)" do
    test "owner_ref comes back byte-identical for every shape" do
      for owner_ref <- @owner_refs do
        sb = sandbox(owner_ref: owner_ref)

        {:ok, provisioned} = ExSandbox.provision(@mechanism, sb)
        {:ok, started} = ExSandbox.start(@mechanism, provisioned)
        {:ok, stopped} = ExSandbox.stop(@mechanism, started)
        :ok = ExSandbox.destroy(@mechanism, stopped)

        assert stopped.owner_ref == owner_ref
        assert byte_size(stopped.owner_ref) == byte_size(owner_ref)
      end
    end

    test "context survives even when it is a term with no string form" do
      # `context` is `term()`, so a host may put anything there. A library that
      # assumed a map or a binary would break on the first host that did not.
      contexts = [
        nil,
        %{tenant_id: "abc", actor: %{id: 1}},
        {:tuple, :of, :atoms},
        [1, 2, 3],
        make_ref(),
        self()
      ]

      for context <- contexts do
        sb = sandbox(context: context)

        {:ok, provisioned} = ExSandbox.provision(@mechanism, sb)
        {:ok, started} = ExSandbox.start(@mechanism, provisioned)

        assert started.context === context
      end
    end

    test "mechanism_ref round-trips without the library touching it" do
      sb = sandbox(mechanism_ref: "node@host:weird/ref#1")

      {:ok, provisioned} = ExSandbox.provision(@mechanism, sb)
      {:ok, started} = ExSandbox.start(@mechanism, provisioned)

      assert started.mechanism_ref == "node@host:weird/ref#1"
    end
  end

  describe "no library module interprets an opaque value (FR-003)" do
    # The round-trip test above would still pass if a library function parsed
    # `owner_ref` to make a decision and then handed the original back. This is
    # the check that catches that -- it reads the source.
    @lib_root Path.expand(Path.join([__DIR__, "..", "lib"]))

    defp library_sources do
      Path.wildcard(Path.join(@lib_root, "**/*.ex"))
    end

    test "no source splits, parses, or matches on the opaque fields" do
      # Operations that only make sense if you are looking *inside* the value.
      forbidden =
        for field <- ["owner_ref", "mechanism_ref", "context"],
            op <- [
              "String.split(#{field}",
              "String.starts_with?(#{field}",
              "String.ends_with?(#{field}",
              "String.contains?(#{field}",
              "String.to_integer(#{field}",
              "String.to_atom(#{field}",
              "Jason.decode(#{field}",
              "URI.parse(#{field}"
            ],
            do: op

      for path <- library_sources(), op <- forbidden do
        source = File.read!(path)

        refute source =~ op,
               "#{Path.relative_to(path, @lib_root)} interprets an opaque value: #{op}"
      end
    end

    test "no source pattern-matches a prefix out of an opaque field" do
      # `<<"tenant_", rest::binary>> = owner_ref` is the idiomatic Elixir way to
      # do exactly what FR-007 forbids, and it does not contain any of the
      # function names above.
      for path <- library_sources() do
        source = File.read!(path)

        refute source =~ ~r/<<[^>]*>>\s*=\s*(owner_ref|mechanism_ref)/,
               "#{Path.relative_to(path, @lib_root)} destructures an opaque value"

        refute source =~ ~r/def \w+\(\s*<<[^>]*>>\s*=\s*(owner_ref|mechanism_ref)/,
               "#{Path.relative_to(path, @lib_root)} matches on an opaque value in a head"
      end
    end
  end
end
