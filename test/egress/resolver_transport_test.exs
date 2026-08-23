defmodule ExSandbox.Egress.ResolverTransportTest do
  @moduledoc """
  The socket the in-namespace listener speaks to (029 T015).

  ⚠️ **This exists because the frame format has two implementations in two
  languages** — `nsacceptor.py`'s `ask_resolver/3` and this module's `serve/2` —
  and nothing compiles them together. If they drift, a sandbox's every name
  lookup times out, which reads as a slow or absent network rather than as a
  protocol mismatch. So the framing is exercised from the outside here, by a
  client that builds the bytes by hand rather than by calling the server's own
  helpers.
  """
  use ExUnit.Case, async: true

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
    unique = System.unique_integer([:positive])
    registry = start_supervised!({EgressRegistry, name: :"reg_#{unique}"})
    path = Path.join(System.tmp_dir!(), "axonn-resolver-test-#{unique}.sock")

    resolver =
      start_supervised!(
        {Resolver, name: :"resolver_#{unique}", path: path, registry: registry, host_aliases: []}
      )

    on_exit(fn -> File.rm(path) end)
    %{registry: registry, path: path, resolver: resolver}
  end

  defp query(name) do
    :inet_dns.encode(
      dns_rec(
        header: dns_header(id: 1234, qr: false, opcode: :query, rd: true),
        qdlist: [dns_query(domain: String.to_charlist(name), type: :a, class: :in)]
      )
    )
  end

  # The client the helper implements, written by hand: a 4-byte big-endian
  # length, then `"<source-key>\n" <> <query bytes>`.
  defp ask(path, source_key_text, payload) do
    {:ok, socket} =
      :gen_tcp.connect({:local, path}, 0, [:binary, active: false, packet: 4], 2_000)

    :ok = :gen_tcp.send(socket, source_key_text <> "\n" <> payload)
    result = :gen_tcp.recv(socket, 0, 5_000)
    :gen_tcp.close(socket)
    result
  end

  test "a framed query over the socket comes back as a framed answer", %{
    path: path,
    registry: registry
  } do
    # ⚠️ The upstream is the host's real resolver here, which is why the name
    # asked for is one that either resolves or does not without changing the
    # claim: what is asserted is that BYTES CROSSED THE SOCKET AND CAME BACK
    # DECODABLE, not what the internet said.
    :ok = EgressRegistry.assign({10, 0, 0, 0}, [{"localhost.", 443}], registry)

    case ask(path, "10.0.0.0", query("localhost")) do
      {:ok, response} ->
        assert {:ok, decoded} = :inet_dns.decode(response)
        assert dns_header(dns_rec(decoded, :header), :id) == 1234

      {:error, :closed} ->
        # The host could not resolve at all. The socket still carried the
        # request and the server still declined in the documented way (silence),
        # which is the behaviour `nsacceptor.py` turns into a dropped datagram.
        :ok
    end
  end

  test "a frame naming no readable source key is answered with silence", %{path: path} do
    # ⚠️ Silence, never a synthesised response. Answering here would mean
    # inventing a name-to-address mapping for a sandbox the platform cannot
    # identify -- and the tenant would then connect to an address no entry can
    # match, which is a refusal that looks like a broken allowlist.
    assert {:error, :closed} = ask(path, "not-an-address", query("example.test"))
  end

  test "the helper's own client, run as Python, is understood by this server", %{
    registry: registry
  } do
    # ⚠️ The tests above build the frame by hand in Elixir, which checks this
    # server against *this file's* reading of the format -- not against the
    # implementation that will actually call it. If `ask_resolver/3` and
    # `serve/2` drift, both sides keep passing their own tests and every lookup
    # inside a sandbox times out, which reads as a slow network rather than as
    # a protocol mismatch. So this one executes `nsacceptor.py` itself.
    case System.find_executable("python3") do
      nil ->
        # Recorded rather than silently passed: a skip that leaves no trace is
        # how a check stops running without anyone noticing.
        IO.puts("resolver_transport: no python3 -- cross-language framing UNOBSERVED")

      python3 ->
        # ⚠️ A STUBBED upstream, deliberately. Against the host's real resolver
        # a failure to resolve and a framing bug both look like "no bytes came
        # back", so the assertion below could not distinguish them -- and a
        # check that cannot fail is worth nothing. With a known answer, silence
        # means the framing is wrong and nothing else.
        answer =
          dns_rec(
            header: dns_header(id: 1234, qr: true, opcode: :query, rd: true, ra: true),
            qdlist: [dns_query(domain: ~c"example.test", type: :a, class: :in)],
            anlist: [
              dns_rr(
                domain: ~c"example.test",
                type: :a,
                class: :in,
                ttl: 60,
                data: {93, 184, 216, 34}
              )
            ]
          )

        unique = System.unique_integer([:positive])
        # Short, because `sun_path` is ~104 bytes and a long temp directory
        # fails `bind` with `:einval` -- measured on this host.
        path = Path.join(System.tmp_dir!(), "axr-#{unique}.sock")

        start_supervised!(
          {Resolver,
           name: :"resolver_x_#{unique}",
           path: path,
           registry: registry,
           host_aliases: [],
           resolve: fn _name, _type -> {:ok, answer} end},
          id: :"resolver_x_#{unique}"
        )

        on_exit(fn -> File.rm(path) end)
        :ok = EgressRegistry.assign({10, 0, 0, 0}, [{"example.test", 443}], registry)

        helper = Path.join(:code.priv_dir(:ex_sandbox), "egress/nsacceptor.py")
        query_path = Path.join(System.tmp_dir!(), "axr-#{unique}.bin")
        File.write!(query_path, query("example.test"))
        on_exit(fn -> File.rm(query_path) end)

        script = """
        import importlib.util, sys
        spec = importlib.util.spec_from_file_location("nsacceptor", sys.argv[1])
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        q = open(sys.argv[3], "rb").read()
        good = m.ask_resolver(sys.argv[2], "10.0.0.0", q)
        bad = m.ask_resolver(sys.argv[2], "not-an-address", q)
        print("GOOD", "none" if good is None else int.from_bytes(good[:2], "big"))
        print("BAD", "none" if bad is None else len(bad))
        """

        {output, 0} =
          System.cmd(python3, ["-c", script, helper, path, query_path], stderr_to_stdout: true)

        # The permitted path and its refusal control in one run: a frame this
        # server can attribute comes back carrying the client's own query id,
        # and a frame it cannot is answered with silence rather than an
        # invented mapping.
        assert output =~ "GOOD 1234", output
        assert output =~ "BAD none", output

        # ...and the binding was filed, which is what makes the address the
        # tenant just learned connectable at all.
        assert EgressRegistry.resolutions({10, 0, 0, 0}, registry)
               |> Map.fetch!("example.test")
               |> MapSet.member?({93, 184, 216, 34})
    end
  end

  # ⚠️ A mode assertion, and the weakest test in this file: it inspects
  # configuration rather than attempting the operation, because the operation
  # that fails needs a SECOND uid and the suite runs as one. The real evidence
  # is a measurement inside the isolation image, recorded on
  # `Resolver.permit_acceptor/1`: with the inherited `0755`, a running
  # sandbox's own counters showed the queries arriving at the in-namespace
  # listener (`Udp InDatagrams +3`) and nothing going back, and `:inet_res`
  # inside the tenant returned `{:error, :timeout}`. This test exists so the
  # widening cannot be silently dropped, not to prove it works.
  test "the socket is connectable by a uid that is not the platform's", %{path: path} do
    %File.Stat{mode: mode} = File.stat!(path)

    # `connect(2)` on a unix socket needs write, not read.
    assert Bitwise.band(mode, 0o022) == 0o022,
           "resolver socket mode #{inspect(mode, base: :octal)} denies connect(2) to the " <>
             "in-namespace listener, which runs under the holder's user namespace"
  end

  test "the socket is bound where the verdict socket lives, not at a second constant" do
    # Two configured directories are two chances to configure them differently,
    # and `/var/run` is writable on a deployment host and not on a developer's.
    assert Path.dirname(Resolver.default_path()) ==
             Path.dirname(ExSandbox.Egress.Verdict.default_path())
  end
end
