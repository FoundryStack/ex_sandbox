defmodule ExSandbox.Egress.Resolver do
  @moduledoc """
  The platform's DNS service for sandboxes (029 T015, `029-FR-013`,
  `029-FR-012`, `029-FR-015`).

  ## Why a sandbox needs one at all

  `FR-013`'s own text calls a working DNS story *"a **precondition** for FR-012
  rather than a separate nicety"*, and it is right in a stronger sense than it
  reads. Two independent things both stop without it:

    * **`T011`'s ruling made DNS the only permitted UDP destination.** The
      `inet filter output` chain ends in a terminal `meta l4proto udp drop`, so
      until something names a resolver, a sandbox sends no UDP at all — DNS is
      *off*, not permissive.
    * **`FR-012` matches a hostname entry against what this sandbox resolved
      that name to.** Something has to have done the resolving, and it has to
      be the platform, because the whole point is that the tenant does not get
      to decide what its own allowlist means.

  So this module is both halves: it *answers* the query, and the act of
  answering is what files the name→address binding the verdict later consults.
  Those are deliberately the same event. A design where resolution and
  recording are two steps has a state in which a sandbox has an answer the
  platform did not record — and a tenant that reaches that state connects to an
  address no entry can match, which reads as a broken allowlist.

  ## Mechanism-neutral, and what that costs

  ⚠️ **Written mechanism-neutral from the first line** (`D27`'s transfer
  column). Nothing here knows about `pasta`, network namespaces, `nft`, or
  `bwrap`. It receives DNS query bytes and a source key, and returns DNS
  response bytes. A second mechanism supplies the same two things by whatever
  route it has and reuses this untouched.

  What that costs is a transport, and the transport is the same one the verdict
  socket already uses and for the same reason: a network namespace isolates the
  network stack, not the filesystem, so an `AF_UNIX` socket on a host path is
  reachable from inside a sandbox's netns while being invisible to the tenant,
  which `bwrap` never binds into its mount view. See `ExSandbox.Egress.Verdict`
  for the measurement.

  ⚠️ The listener that *carries* datagrams to this socket runs inside the
  namespace (`nsacceptor.py`), for the identical reason the TCP acceptor does:
  a socket's network namespace is fixed by the namespace of the calling
  process, and the BEAM never enters the sandbox's.

  ## Every answer passes the same structural filter as every entry

  ⚠️ **This is the hole `FR-012` opens, closed in the same module that opens
  it.** Name matching means a tenant who controls a DNS record for a name in
  their own allowlist can point it at `127.0.0.1` — and every parse-time test
  stays green while they do it. `spec.md` calls this *"the sharpest concrete
  instance of this spec's own thesis"*.

  So every address this module is about to record is first put through
  `ExSandbox.Egress.Allowlist.classify/2` — **the same classifier** the written
  entries go through, not a second copy. A refused answer is dropped from the
  record and from the response, so:

    * the tenant never learns the address from us, and
    * the address is not in the record, so a connect to it matches no entry and
      is refused by `Policy` at connect time,

  and the refusal names the same class (`:loopback`, `:rfc1918_private`, …) a
  written entry would have been refused for.

  ⚠️ **Dropping the answer rather than refusing the query is deliberate.** A
  `SERVFAIL` would tell the tenant which of its names the platform declines to
  resolve, and more importantly it would make a rebinding attempt look like an
  outage. An `A` record set with the excluded members removed is the honest
  answer to *"which of these may this sandbox be told about?"*.

  ## Answers accumulate; they do not replace

  A name that resolves into a rotation gives a different member on each query,
  and a connection opened against the first answer while the second is being
  recorded must not be refused for it. `Registry.record_resolution/4` unions.
  The set is bounded by the sandbox's own lifetime, because it lives in the
  registry entry that `Binding.release/2` deletes.

  ## What this module deliberately does not do

  It does not decide anything. `Policy` decides; this records. And it does not
  resolve on the verdict path — a resolution performed *at connect time* on the
  platform's behalf would compare the tenant's connection against an answer the
  tenant never received.
  """

  use GenServer

  require Logger
  require Record

  alias ExSandbox.Egress.Allowlist
  alias ExSandbox.Egress.HostAliases
  alias ExSandbox.Egress.Policy
  alias ExSandbox.Egress.Registry, as: EgressRegistry

  # ⚠️ Extracted from OTP's own header rather than written out as tuples. The
  # `dns_header` record gained fields between OTP releases, so a literal tuple
  # is correct on the machine it was written on and silently mis-parses
  # elsewhere -- and the failure would be a malformed response, which from
  # inside a sandbox reads as a name that does not resolve.
  Record.defrecordp(:dns_rec, Record.extract(:dns_rec, from_lib: "kernel/src/inet_dns.hrl"))

  Record.defrecordp(
    :dns_header,
    Record.extract(:dns_header, from_lib: "kernel/src/inet_dns.hrl")
  )

  Record.defrecordp(:dns_query, Record.extract(:dns_query, from_lib: "kernel/src/inet_dns.hrl"))
  Record.defrecordp(:dns_rr, Record.extract(:dns_rr, from_lib: "kernel/src/inet_dns.hrl"))

  @default_path "/var/run/axonn-egress-resolver.sock"

  # ⚠️ The address a sandbox finds its resolver at, **inside its own network
  # namespace**. It is loopback there, which is the namespace's loopback and
  # not the host's -- reaching it reaches the in-namespace listener, never a
  # host service. `--no-map-gw` plus `-u none`/`-U none` mean the host is not
  # reachable over UDP from the namespace at all, so a host-side address would
  # simply be unreachable.
  #
  # ⚠️ `127.0.0.1:53` specifically, because glibc with **no** `/etc/resolv.conf`
  # defaults to exactly that -- and `Hardening.Linux` binds no `/etc` into the
  # tenant's mount view. So the tenant needs no configuration to find it, and
  # there is no file to keep in step with this constant.
  @default_resolver {{127, 0, 0, 1}, 53}

  @upstream_timeout 4_000

  @typedoc "Where a sandbox finds the resolver, as `Netns.resolver()` spells it."
  @type address :: {:inet.ip_address(), :inet.port_number()}

  @doc """
  The address a sandbox reaches this resolver at, inside its own namespace.

  ⚠️ This is what `ExSandbox.Egress.LaunchPlan` turns into the single `accept`
  rule ahead of the UDP drop, and what `ExSandbox.Hardening.Linux` writes into
  the tenant's `/etc/resolv.conf`.

  ⚠️ **It does need tenant-side configuration, and an earlier version of this
  comment claimed otherwise.** The claim was that glibc falls back to
  `127.0.0.1` with no `resolv.conf`, so a sandbox with no `/etc` would find the
  listener unaided. Measured inside `unshare -n` on the isolation image, with a
  stub nameserver bound on `127.0.0.1:53`: with no `resolv.conf` the stub
  received nothing and the lookup returned `:nxdomain`; with a `resolv.conf`
  naming `127.0.0.1` the same lookup reached the stub and resolved. The bind in
  `Hardening.Linux` exists because of that measurement.

  ⚠️ A resolver on a port other than 53 gets no `resolv.conf`, because the file
  has no syntax for one — see `ExSandbox.Hardening.Linux`.
  """
  @spec resolver_address() :: address()
  def resolver_address do
    :ex_sandbox
    |> Application.get_env(:egress, [])
    |> Keyword.get(:resolver_address, @default_resolver)
  end

  @doc """
  Where the resolver socket lives.

  ⚠️ Deliberately not under a sandbox's storage or any path `Hardening.Linux`
  binds into a tenant's mount view — the same rule, and the same reason, as
  `ExSandbox.Egress.Verdict.default_path/0`.

  ⚠️ **Defaults to the verdict socket's own directory rather than to a second
  configured constant**, and that is the point rather than a shortcut. The two
  sockets have identical requirements — bindable by the platform, invisible to
  the tenant — so a deployment that had to state the directory twice would have
  two chances to state it differently. The failure mode of a divergence is not
  symmetric: `/var/run` is writable on a deployment host and not on a developer
  machine, and a resolver that cannot bind refuses to start the whole node.
  """
  @spec default_path() :: String.t()
  def default_path do
    egress = Application.get_env(:ex_sandbox, :egress, [])

    case Keyword.get(egress, :resolver_socket_path) do
      nil -> beside_verdict_socket(egress)
      configured -> configured
    end
  end

  defp beside_verdict_socket(egress) do
    case Keyword.get(egress, :verdict_socket_path) do
      nil -> @default_path
      verdict -> Path.join(Path.dirname(verdict), Path.basename(@default_path))
    end
  end

  @doc false
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc """
  Answers one query for one sandbox: the whole service, minus the transport.

  Takes the raw query bytes and the `/30` the asking sandbox was provisioned
  with; returns the raw response bytes, having filed every recordable answer
  against that sandbox.

  ⚠️ Public and pure-ish on purpose. This is the part a second mechanism reuses
  untouched, and it is the part worth testing without a socket, a namespace or
  a container.
  """
  @spec answer(binary(), Policy.source_key(), keyword()) :: {:ok, binary()} | {:error, term()}
  def answer(query, source_key, opts \\ []) when is_binary(query) do
    registry = Keyword.get(opts, :registry, EgressRegistry)
    aliases = Keyword.get(opts, :host_aliases, [])
    resolve = Keyword.get(opts, :resolve, &resolve_upstream/2)

    with {:ok, decoded} <- decode(query),
         {:ok, question} <- sole_question(decoded) do
      respond(decoded, question, source_key, registry, aliases, resolve)
    end
  end

  # -- Callbacks ------------------------------------------------------------

  @impl true
  def init(opts) do
    path = Keyword.get(opts, :path, default_path())
    registry = Keyword.get(opts, :registry, EgressRegistry)

    # ⚠️ Read once, at start, and that is a stated limitation rather than an
    # oversight. Re-reading per query would put a `getifaddrs` and a shell-out
    # on the path of every name a sandbox looks up, and the cost would be paid
    # continuously to catch a host whose addresses changed under a running node
    # -- which is rare, and which the static classes below still cover for all
    # the private and loopback spellings. `ExSandbox.Egress.HostAliases` says
    # the same thing about the parse-time list.
    aliases = Keyword.get_lazy(opts, :host_aliases, &HostAliases.detect/0)

    # A stale socket file from a previous run makes `bind` fail with
    # `:eaddrinuse`, which reads as "another node is running" rather than "the
    # last one died". Same rule as `Verdict`.
    _ = File.rm(path)
    _ = File.mkdir_p(Path.dirname(path))

    case :gen_tcp.listen(0, [
           {:ifaddr, {:local, path}},
           :binary,
           packet: 4,
           active: false,
           reuseaddr: true
         ]) do
      {:ok, listener} ->
        :ok = permit_acceptor(path)

        state = %{
          listener: listener,
          registry: registry,
          host_aliases: aliases,
          path: path,
          # ⚠️ Carried in state so the socket path can be exercised against a
          # KNOWN upstream. Without it a test at this level can only assert
          # "bytes came back or the host could not resolve", and those two are
          # indistinguishable from a framing bug -- a check that cannot fail.
          # `answer/3` has always taken this; the server simply never passed it.
          resolve: Keyword.get(opts, :resolve, &resolve_upstream/2)
        }

        {:ok, state, {:continue, :accept}}

      {:error, reason} ->
        # ⚠️ Refused loudly. A resolver that failed to bind but let the node
        # boot produces sandboxes whose every name lookup times out, which
        # reads as a slow network rather than as an absent platform service.
        {:stop, {:resolver_listen_failed, path, reason}}
    end
  end

  # ⚠️ Same widening, same reason, as `Verdict.permit_acceptor/1` -- and the
  # same failure mode when it is missing. The BEAM binds this socket as root
  # and a unix socket takes mode `0755` from the umask, which denies
  # `connect(2)` to every other uid. The in-namespace listener runs under the
  # holder's user namespace (`nsenter -n -U`), so it is not that uid.
  #
  # `ask_resolver/3` in `nsacceptor.py` treats any failure as silence, which is
  # the right rule and is what makes this so quiet: every query is dropped,
  # the client retries and times out, and the symptom is "hostnames do not
  # resolve" rather than "the platform is unreachable". Measured inside the
  # isolation image against a running sandbox (029 T015):
  #
  #     mode 0755  -> tenant /proc/net/snmp: Udp InDatagrams +3, OutDatagrams +3,
  #                   NoPorts unchanged  (queries delivered to the listener,
  #                   listener sent nothing back), `:inet_res` -> {:error, :timeout}
  #     mode 0666  -> `:inet_res` -> answers
  #
  # The isolation is the path, not the mode: this lives beside the verdict
  # socket, outside everything `bwrap` binds into the sandbox, so tenant code
  # cannot see it at all. And reaching it grants nothing an allowlist would not
  # already permit -- the answers it returns are filtered by FR-015 before they
  # leave, and the binding it records is what the verdict later consults.
  defp permit_acceptor(path) do
    case File.chmod(path, 0o666) do
      :ok ->
        :ok

      {:error, reason} ->
        # Refused rather than tolerated, for the same reason the bind failure
        # is: a resolver no acceptor can reach denies every name while the
        # platform reports itself healthy.
        raise "egress: could not make the resolver socket reachable by the " <>
                "in-namespace listener at #{path}: #{inspect(reason)}"
    end
  end

  @impl true
  def handle_continue(:accept, state) do
    parent = self()

    # One acceptor process per node, handing each connection to a task. A
    # blocked resolution must not stall the next sandbox's query.
    _ =
      spawn_link(fn -> accept_loop(parent, state) end)

    {:noreply, state}
  end

  @impl true
  def handle_call({:answer, query, source_key}, _from, state) do
    result =
      answer(query, source_key,
        registry: state.registry,
        host_aliases: state.host_aliases,
        resolve: state.resolve
      )

    {:reply, result, state}
  end

  @impl true
  def terminate(_reason, %{path: path}), do: File.rm(path)

  # -- Transport ------------------------------------------------------------

  defp accept_loop(parent, state) do
    case :gen_tcp.accept(state.listener) do
      {:ok, socket} ->
        {:ok, pid} = Task.start(fn -> serve(socket, parent) end)
        :ok = :gen_tcp.controlling_process(socket, pid)
        accept_loop(parent, state)

      {:error, :closed} ->
        :ok

      {:error, _reason} ->
        accept_loop(parent, state)
    end
  end

  # The frame is `"<source-key>\n" <> <query bytes>`, length-prefixed by
  # `packet: 4` on both sides. The source key is the platform's own account of
  # which sandbox this is -- supplied to the in-namespace listener at start,
  # never read off the datagram. See `ExSandbox.Egress.Acceptor`.
  defp serve(socket, parent) do
    with {:ok, frame} <- :gen_tcp.recv(socket, 0, 5_000),
         {:ok, source_key, query} <- split_frame(frame),
         {:ok, response} <- GenServer.call(parent, {:answer, query, source_key}, 10_000) do
      :gen_tcp.send(socket, response)
    else
      other ->
        # ⚠️ Nothing is sent back. A malformed frame or a failed resolution
        # yields silence, which the in-namespace listener drops -- and a dropped
        # datagram is what a resolver that cannot answer looks like on the wire.
        # Synthesising a response here would mean inventing an answer.
        Logger.debug("egress resolver: no answer (#{inspect(other)})")
        :ok
    end

    :gen_tcp.close(socket)
  end

  defp split_frame(frame) do
    case :binary.split(frame, "\n") do
      [key_text, query] ->
        case parse_source_key(key_text) do
          {:ok, key} -> {:ok, key, query}
          :error -> {:error, {:bad_source_key, key_text}}
        end

      _ ->
        {:error, :bad_frame}
    end
  end

  defp parse_source_key(text) do
    case :inet.parse_ipv4_address(String.to_charlist(text)) do
      {:ok, {_, _, _, _} = address} -> {:ok, Policy.source_key(address)}
      _ -> :error
    end
  end

  # -- The service ----------------------------------------------------------

  # ⚠️ **`:inet_dns.decode/1` RAISES on malformed input**, it does not only
  # return `{:error, _}` -- MEASURED: `<<0, 1, 2, 3>>` gives
  # `FunctionClauseError in :inet_dns.do_decode/2`, not a tagged tuple. These
  # bytes come straight from tenant code, which chooses them, so the tagged
  # branch alone would leave a tenant able to raise inside the platform's
  # resolver at will. It would be caught by the serving task and look like an
  # intermittently unavailable resolver -- a denial of service on the platform's
  # own name service, reported as noise.
  defp decode(query) do
    case :inet_dns.decode(query) do
      {:ok, decoded} -> {:ok, decoded}
      {:error, reason} -> {:error, {:undecodable_query, reason}}
    end
  rescue
    error -> {:error, {:undecodable_query, error}}
  end

  # ⚠️ Exactly one question, which is what every resolver in practice accepts
  # and what every client in practice sends. A multi-question query would have
  # to be recorded as several bindings from one answer section, and the mapping
  # from answer to question is not determinable from the wire format -- so the
  # honest handling is to decline rather than to guess which name an address
  # belongs to. Guessing wrong would file an address under the wrong name and
  # permit a destination the operator never named.
  defp sole_question(decoded) do
    case dns_rec(decoded, :qdlist) do
      [question] -> {:ok, question}
      other -> {:error, {:unsupported_question_count, length(other)}}
    end
  end

  defp respond(decoded, question, source_key, registry, aliases, resolve) do
    name = question |> dns_query(:domain) |> to_string()
    type = dns_query(question, :type)

    case resolve.(name, type) do
      {:ok, upstream} ->
        {kept, dropped} = partition_answers(dns_rec(upstream, :anlist), aliases)

        log_dropped(name, dropped)
        :ok = record(registry, source_key, name, kept)

        {:ok, encode_response(decoded, upstream, kept)}

      {:error, reason} ->
        {:error, {:upstream_failed, name, reason}}
    end
  end

  # ⚠️ `:inet_res.resolve/4`, i.e. the **host's** resolver configuration, and
  # this is the trust boundary `FR-012` asks to be named. Resolution happens on
  # the platform, using the platform's own resolver settings; the tenant is
  # trusted to perform none of it. What the tenant supplies is a name, and the
  # only thing it can do with that name is learn an address the platform is
  # willing to tell it.
  defp resolve_upstream(name, type) do
    :inet_res.resolve(String.to_charlist(name), :in, type, timeout: @upstream_timeout)
  end

  # ⚠️ Only `A` and `AAAA` data are recordable, because only they are addresses
  # a connection can later be made to. A `CNAME` in the chain is passed through
  # to the tenant untouched and files nothing: the binding that matters is from
  # the name the operator wrote to the address the tenant will connect to, and
  # `:inet_res` returns the address records alongside the alias chain.
  defp partition_answers(answers, aliases) do
    Enum.split_with(answers, fn rr ->
      case address_of(rr) do
        nil -> true
        address -> Allowlist.classify(address, aliases) == nil
      end
    end)
  end

  defp address_of(rr) do
    case {dns_rr(rr, :type), dns_rr(rr, :data)} do
      {:a, {_, _, _, _} = address} -> address
      {:aaaa, {_, _, _, _, _, _, _, _} = address} -> address
      _ -> nil
    end
  end

  defp record(registry, source_key, name, kept) do
    addresses = kept |> Enum.map(&address_of/1) |> Enum.reject(&is_nil/1)

    case addresses do
      [] ->
        :ok

      _ ->
        case EgressRegistry.record_resolution(
               source_key,
               Policy.normalise_name(name),
               addresses,
               registry
             ) do
          :ok ->
            :ok

          {:error, :unknown_source} ->
            # ⚠️ Not an error to the caller. The sandbox gets its answer; what
            # it does not get is a binding, so a connect to that address matches
            # no entry and is refused. Failing the query instead would turn a
            # lifecycle race into a name that does not resolve, which is harder
            # to read and no safer.
            Logger.warning(
              "egress resolver: answered #{name} for an unregistered source #{inspect(source_key)}"
            )

            :ok
        end
    end
  end

  defp log_dropped(_name, []), do: :ok

  defp log_dropped(name, dropped) do
    classes =
      dropped
      |> Enum.map(&address_of/1)
      |> Enum.reject(&is_nil/1)
      |> Enum.map(&{&1, Allowlist.classify(&1)})

    Logger.warning("""
    egress resolver: refused #{length(classes)} answer(s) for #{name}.

    #{inspect(classes)}

    029-FR-015 excludes these address classes from what a sandbox may be
    pointed at, and the exclusion applies to what a resolver answers as well as
    to what an operator writes. A name in an allowlist resolving here is the
    DNS-rebinding shape.
    """)
  end

  # The upstream response, re-headed with the client's own id and question so
  # the client can match it. Rebuilding the record rather than forwarding the
  # upstream bytes is what makes the filtered answer list the one the tenant
  # sees.
  defp encode_response(decoded, upstream, kept) do
    client_header = dns_rec(decoded, :header)
    upstream_header = dns_rec(upstream, :header)

    header =
      dns_header(upstream_header,
        id: dns_header(client_header, :id),
        qr: true,
        ra: true
      )

    dns_rec(upstream,
      header: header,
      qdlist: dns_rec(decoded, :qdlist),
      anlist: kept,
      # ⚠️ Authority and additional sections are dropped rather than forwarded.
      # An `additional` section carries glue **addresses**, which would be a
      # second path by which an excluded address reaches the tenant -- past the
      # filter that only inspects the answer section.
      nslist: [],
      arlist: []
    )
    |> :inet_dns.encode()
  end
end
