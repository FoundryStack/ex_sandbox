defmodule ExSandbox.Egress.PublicDestinationTest do
  @moduledoc """
  The `"public"` allowlist entry: every address outside the refused classes, on
  any port, decided on the address each connection was dialled to.

  The oracle is a generated table checked against a reference written here
  from the CIDR list, independently of `ExSandbox.Egress.Refusal`'s clauses. A
  table that only compared `permits?/3` with `refused?/2` would restate the
  implementation; the reference is what makes a wrong clause in either fail.
  """
  use ExUnit.Case, async: true

  import Bitwise

  alias ExSandbox.Egress.Allowlist
  alias ExSandbox.Egress.Decision
  alias ExSandbox.Egress.Policy
  alias ExSandbox.Egress.Refusal
  alias ExSandbox.Egress.Registry

  @public [{:public, []}]

  @refused_v4 [
    {{127, 0, 0, 0}, 8},
    {{0, 0, 0, 0}, 8},
    {{10, 0, 0, 0}, 8},
    {{172, 16, 0, 0}, 12},
    {{192, 168, 0, 0}, 16},
    {{169, 254, 0, 0}, 16}
  ]

  @refused_v6 [
    {{0, 0, 0, 0, 0, 0, 0, 1}, 128},
    {{0, 0, 0, 0, 0, 0, 0, 0}, 128},
    {{0xFE80, 0, 0, 0, 0, 0, 0, 0}, 10},
    {{0xFC00, 0, 0, 0, 0, 0, 0, 0}, 7}
  ]

  describe "the generated table" do
    test "public permits an address iff the reference refuses none of its classes" do
      :rand.seed(:exsss, {29, 15, 235})

      rows = table()
      {refused, permitted} = Enum.split_with(rows, &reference_refused?/1)

      assert length(refused) > 200 and length(permitted) > 800,
             "the table stopped covering both sides"

      # ⚠️ Not a `for` with `expected = ...` beside the generator: there that is
      # a filter, and every refused row (expected `false`) was silently skipped.
      # Measured: narrowing 172.16/12 to 172.16-172.30 left this test green.
      mismatches =
        Enum.reject(rows, fn address ->
          port = :rand.uniform(65_535)
          expected = not reference_refused?(address)

          Policy.permits?(@public, {address, port}) == expected and
            Refusal.refused?(address) != expected
        end)
        |> Enum.map(&(&1 |> :inet.ntoa() |> to_string()))

      assert mismatches == [], "public disagreed with the reference on #{inspect(mismatches)}"
    end
  end

  describe "parsing" do
    test "\"public\" and :public both parse to the entry, carrying the alias addresses" do
      aliases = [{10, 0, 0, 1}, "::ffff:192.0.2.9", "host.internal"]

      assert {:ok, [{:public, addresses}, {:public, addresses}]} =
               Allowlist.parse(["public", :public], aliases)

      assert Enum.sort(addresses) == [{10, 0, 0, 1}, {192, 0, 2, 9}],
             "a name alias, which no dialled address can equal, was carried"
    end

    test "an already-parsed entry is rebuilt with this parse's aliases" do
      assert {:ok, [{:public, [{192, 0, 2, 9}]}]} =
               Allowlist.parse([{:public, []}], [{192, 0, 2, 9}])
    end

    test "sits beside ordinary entries" do
      assert {:ok, [{"api.example.com", 443}, {:public, []}]} =
               Allowlist.parse(["api.example.com:443", "public"], [])
    end
  end

  describe "Policy.permits?/3 under public" do
    test "refuses a host alias the class table does not cover" do
      allowed = [{:public, [{192, 0, 2, 9}]}]

      refute Policy.permits?(allowed, {{192, 0, 2, 9}, 443})
      refute Policy.permits?(allowed, {{0, 0, 0, 0, 0, 0xFFFF, 0xC000, 0x0209}, 443})
      assert Policy.permits?(allowed, {{192, 0, 2, 10}, 443})
    end

    test "never permits a name, only an address" do
      refute Policy.permits?(@public, {"example.com", 443})
      assert Policy.permits?(@public, {"93.184.216.34", 443})
      refute Policy.permits?(@public, {"10.0.0.5", 443})
    end
  end

  describe "a public name that resolves inward" do
    setup do
      registry =
        start_supervised!({Registry, name: :"public_#{System.unique_integer([:positive])}"})

      source = {10, 200, 0, 1}
      :ok = Registry.assign(Policy.source_key(source), @public, registry)
      %{registry: registry, source: source}
    end

    test "is refused on the address it was dialled to", %{registry: r, source: source} do
      # ⚠️ The resolver drops an inward answer before recording it, so this
      # recording is what a rebinding zone the resolver missed would leave
      # behind. The decision must still see 10.0.0.5, not the public name.
      :ok =
        Registry.record_resolution(
          Policy.source_key(source),
          "rebind.example.com",
          [{10, 0, 0, 5}],
          r
        )

      assert Decision.decide(source, {{10, 0, 0, 5}, 443}, r) == {:refused, :not_permitted},
             "a public name resolving to 10.0.0.5 reached it under public"

      assert Decision.decide(source, {{93, 184, 216, 34}, 443}, r) == :permitted
    end
  end

  # -- The table -------------------------------------------------------------

  defp table do
    edges =
      for {prefix, len} <- @refused_v4 ++ @refused_v6,
          address <- cidr_samples(prefix, len),
          do: address

    random_v4 = for _ <- 1..400, do: random_v4()
    random_v6 = for _ <- 1..400, do: random_v6()
    global_v6 = for _ <- 1..100, do: put_elem(random_v6(), 0, 0x2000 + :rand.uniform(0x1FFF))

    mapped =
      for v4 <- Enum.take(edges, 60) ++ Enum.take(random_v4, 60),
          tuple_size(v4) == 4,
          do: mapped(v4)

    Enum.uniq(edges ++ random_v4 ++ random_v6 ++ global_v6 ++ mapped)
  end

  # The first and last address of the range, one either side of it, and random
  # addresses inside it.
  defp cidr_samples(prefix, len) do
    bits = width(prefix)
    first = to_int(prefix)
    last = first + (1 <<< (bits - len)) - 1
    max = (1 <<< bits) - 1
    inside = for _ <- 1..20, do: first + :rand.uniform(last - first + 1) - 1

    [first, last, first - 1, last + 1 | inside]
    |> Enum.filter(&(&1 >= 0 and &1 <= max))
    |> Enum.map(&from_int(&1, bits))
  end

  defp reference_refused?({0, 0, 0, 0, 0, 0xFFFF, _, _} = address),
    do: reference_refused?(from_int(to_int(address) &&& 0xFFFFFFFF, 32))

  defp reference_refused?(address) do
    ranges = if tuple_size(address) == 4, do: @refused_v4, else: @refused_v6
    Enum.any?(ranges, fn {prefix, len} -> in_cidr?(address, prefix, len) end)
  end

  defp in_cidr?(address, prefix, len) do
    shift = width(prefix) - len
    to_int(address) >>> shift == to_int(prefix) >>> shift
  end

  defp width(address) when tuple_size(address) == 4, do: 32
  defp width(address) when tuple_size(address) == 8, do: 128

  defp to_int({_, _, _, _} = a),
    do: a |> Tuple.to_list() |> Enum.reduce(0, &((&2 <<< 8) + &1))

  defp to_int({_, _, _, _, _, _, _, _} = a),
    do: a |> Tuple.to_list() |> Enum.reduce(0, &((&2 <<< 16) + &1))

  defp from_int(n, 32), do: {n >>> 24 &&& 255, n >>> 16 &&& 255, n >>> 8 &&& 255, n &&& 255}

  defp from_int(n, 128),
    do: 7..0//-1 |> Enum.map(&(n >>> (&1 * 16) &&& 0xFFFF)) |> List.to_tuple()

  defp random_v4, do: from_int(:rand.uniform(1 <<< 32) - 1, 32)
  defp random_v6, do: from_int(:rand.uniform(1 <<< 128) - 1, 128)

  defp mapped({a, b, c, d}), do: {0, 0, 0, 0, 0, 0xFFFF, (a <<< 8) + b, (c <<< 8) + d}
end
