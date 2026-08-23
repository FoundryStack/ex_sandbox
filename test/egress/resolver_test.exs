defmodule ExSandbox.Egress.ResolverTest do
  @moduledoc """
  The platform's DNS service, and the two things it exists to make true
  (029 T015/T016, `029-FR-013`, `029-FR-012`, `029-FR-015`).

  ## What this file can and cannot establish

  ⚠️ It exercises `answer/3` — the service minus its transport. That is
  deliberate and it is also the limit: it establishes that a query is answered,
  that the binding is filed, and that an excluded answer is dropped. It
  establishes **nothing** about whether a sandbox can reach the resolver, which
  needs a namespace and belongs to the checkpoint.

  ⚠️ **Upstream resolution is injected**, so these run on a machine with no
  network and give the same answer on one with a hostile DNS server. A test
  whose result depends on what `api.github.com` resolves to today is a test that
  reports the internet's state rather than this module's.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Policy
  alias ExSandbox.Egress.Registry, as: EgressRegistry
  alias ExSandbox.Egress.Resolver

  require Record

  Record.defrecordp(:dns_rec, Record.extract(:dns_rec, from_lib: "kernel/src/inet_dns.hrl"))

  Record.defrecordp(
    :dns_header,
    Record.extract(:dns_header, from_lib: "kernel/src/inet_dns.hrl")
  )

  Record.defrecordp(:dns_query, Record.extract(:dns_query, from_lib: "kernel/src/inet_dns.hrl"))
  Record.defrecordp(:dns_rr, Record.extract(:dns_rr, from_lib: "kernel/src/inet_dns.hrl"))

  setup do
    registry =
      start_supervised!({EgressRegistry, name: :"registry_#{System.unique_integer([:positive])}"})

    %{registry: registry}
  end

  defp query(name, type \\ :a) do
    :inet_dns.encode(
      dns_rec(
        header: dns_header(id: 4242, qr: false, opcode: :query, rd: true),
        qdlist: [dns_query(domain: String.to_charlist(name), type: type, class: :in)]
      )
    )
  end

  defp upstream(answers, name) do
    fn ^name, _type ->
      {:ok,
       dns_rec(
         header: dns_header(id: 1, qr: true, rd: true, ra: true),
         qdlist: [dns_query(domain: String.to_charlist(name), type: :a, class: :in)],
         anlist:
           Enum.map(answers, fn address ->
             dns_rr(
               domain: String.to_charlist(name),
               type: :a,
               class: :in,
               ttl: 60,
               data: address
             )
           end)
       )}
    end
  end

  defp answers_in(response) do
    {:ok, decoded} = :inet_dns.decode(response)
    decoded |> dns_rec(:anlist) |> Enum.map(&dns_rr(&1, :data))
  end

  describe "answering files the binding FR-012 later consults" do
    test "an answered A record is recorded against the asking sandbox", %{registry: registry} do
      key = {10, 0, 0, 0}
      :ok = EgressRegistry.assign(key, [{"api.github.com", 443}], registry)

      {:ok, response} =
        Resolver.answer(query("api.github.com"), key,
          registry: registry,
          resolve: upstream([{20, 205, 243, 168}], "api.github.com")
        )

      assert answers_in(response) == [{20, 205, 243, 168}]

      assert %{"api.github.com" => addresses} = EgressRegistry.resolutions(key, registry)
      assert MapSet.member?(addresses, {20, 205, 243, 168})
    end

    test "the recorded binding is what makes the hostname entry match", %{registry: registry} do
      # ⚠️ This is the assertion the whole task is for, and it is written as a
      # BEFORE and an AFTER on purpose. `Policy.permits?/3` refusing after the
      # resolution would be a bug; refusing *before* it is the pre-029
      # behaviour, and without the before-leg a permits?/3 that returned `true`
      # unconditionally would pass this test.
      key = {10, 0, 4, 0}
      allowed = [{"api.github.com", 443}]
      :ok = EgressRegistry.assign(key, allowed, registry)

      refute Policy.permits?(allowed, {{20, 205, 243, 168}, 443}, %{}),
             "a hostname entry must not match an address before anything resolved it"

      {:ok, _} =
        Resolver.answer(query("api.github.com"), key,
          registry: registry,
          resolve: upstream([{20, 205, 243, 168}], "api.github.com")
        )

      assert Policy.permits?(
               allowed,
               {{20, 205, 243, 168}, 443},
               EgressRegistry.resolutions(key, registry)
             )
    end

    test "the response carries the client's own query id", %{registry: registry} do
      key = {10, 0, 8, 0}
      :ok = EgressRegistry.assign(key, [], registry)

      {:ok, response} =
        Resolver.answer(query("example.test"), key,
          registry: registry,
          resolve: upstream([{93, 184, 216, 34}], "example.test")
        )

      {:ok, decoded} = :inet_dns.decode(response)
      assert dns_header(dns_rec(decoded, :header), :id) == 4242
      assert dns_header(dns_rec(decoded, :header), :qr) == true
    end

    test "answers accumulate across queries rather than replacing", %{registry: registry} do
      # A rotation gives a different member each time, and a connection opened
      # against the first answer must not be refused because a second arrived.
      key = {10, 0, 12, 0}
      :ok = EgressRegistry.assign(key, [{"rotating.test", 443}], registry)

      for address <- [{1, 2, 3, 4}, {5, 6, 7, 8}] do
        {:ok, _} =
          Resolver.answer(query("rotating.test"), key,
            registry: registry,
            resolve: upstream([address], "rotating.test")
          )
      end

      %{"rotating.test" => addresses} = EgressRegistry.resolutions(key, registry)
      assert MapSet.size(addresses) == 2
    end
  end

  describe "FR-015 applies to what a resolver answers, not only to what an operator writes" do
    test "a name resolving to loopback yields neither an answer nor a binding", %{
      registry: registry
    } do
      # ⚠️ The rebinding shape: the operator's entry is a name they control, it
      # parses clean, and the zone points it at the host. Every parse-time test
      # stays green while this happens, which is why the check is here.
      key = {10, 0, 16, 0}
      allowed = [{"rebound.test", 443}]
      :ok = EgressRegistry.assign(key, allowed, registry)

      {:ok, response} =
        Resolver.answer(query("rebound.test"), key,
          registry: registry,
          resolve: upstream([{127, 0, 0, 1}], "rebound.test")
        )

      assert answers_in(response) == [],
             "the tenant must not even be told the address"

      assert EgressRegistry.resolutions(key, registry) == %{}

      refute Policy.permits?(
               allowed,
               {{127, 0, 0, 1}, 443},
               EgressRegistry.resolutions(key, registry)
             )
    end

    test "the excluded member is dropped and the rest of the set survives", %{registry: registry} do
      # ⚠️ The permitted-path control for the refusal above, in the same test.
      # A filter that dropped *everything* would pass the previous test while
      # breaking every legitimate name, and the symptom -- names that do not
      # resolve -- reads as a broken network rather than as an over-strict
      # filter.
      key = {10, 0, 20, 0}
      :ok = EgressRegistry.assign(key, [{"mixed.test", 443}], registry)

      {:ok, response} =
        Resolver.answer(query("mixed.test"), key,
          registry: registry,
          resolve: upstream([{127, 0, 0, 1}, {93, 184, 216, 34}], "mixed.test")
        )

      assert answers_in(response) == [{93, 184, 216, 34}]

      %{"mixed.test" => addresses} = EgressRegistry.resolutions(key, registry)
      assert MapSet.to_list(addresses) == [{93, 184, 216, 34}]
    end

    test "an address named as a host alias is excluded too", %{registry: registry} do
      # `:host_alias` is the one class that is not a property of the address, so
      # it is the one that can only be reached by handing the set in.
      key = {10, 0, 24, 0}
      :ok = EgressRegistry.assign(key, [{"gateway.test", 443}], registry)

      {:ok, response} =
        Resolver.answer(query("gateway.test"), key,
          registry: registry,
          host_aliases: [{198, 51, 100, 7}],
          resolve: upstream([{198, 51, 100, 7}], "gateway.test")
        )

      assert answers_in(response) == []

      # The control: the same address with no alias set is a perfectly ordinary
      # public address and passes.
      {:ok, control} =
        Resolver.answer(query("gateway.test"), key,
          registry: registry,
          host_aliases: [],
          resolve: upstream([{198, 51, 100, 7}], "gateway.test")
        )

      assert answers_in(control) == [{198, 51, 100, 7}]
    end
  end

  describe "what it declines to do" do
    test "a resolution for an unregistered /30 answers but files nothing", %{registry: registry} do
      key = {10, 0, 28, 0}

      {:ok, response} =
        Resolver.answer(query("orphan.test"), key,
          registry: registry,
          resolve: upstream([{93, 184, 216, 34}], "orphan.test")
        )

      assert answers_in(response) == [{93, 184, 216, 34}]

      # ⚠️ Nothing filed, so nothing is permitted by it. An entry created here
      # would be filed under a /30 no release will ever be called for, and the
      # next tenant assigned that /30 would inherit it.
      assert EgressRegistry.resolutions(key, registry) == %{}
    end

    test "a query with no question is declined rather than guessed at", %{registry: registry} do
      empty =
        :inet_dns.encode(dns_rec(header: dns_header(id: 7, opcode: :query), qdlist: []))

      assert {:error, {:unsupported_question_count, 0}} =
               Resolver.answer(empty, {10, 0, 32, 0}, registry: registry)
    end

    test "undecodable bytes are declined, never answered", %{registry: registry} do
      assert {:error, {:undecodable_query, _}} =
               Resolver.answer(<<0, 1, 2, 3>>, {10, 0, 36, 0}, registry: registry)
    end

    test "an upstream failure is an error, not an empty answer", %{registry: registry} do
      # ⚠️ An empty NOERROR would tell the tenant the name does not exist, which
      # is a claim the platform is not in a position to make when it simply
      # could not ask.
      assert {:error, {:upstream_failed, "down.test", :timeout}} =
               Resolver.answer(query("down.test"), {10, 0, 40, 0},
                 registry: registry,
                 resolve: fn _name, _type -> {:error, :timeout} end
               )
    end
  end
end
