defmodule ExSandbox.Egress.Acceptor do
  @moduledoc """
  The listener that lives inside one sandbox's network namespace
  (005 T060a1/T060a3, `contracts/egress.md`).

  ## Why this exists, and what it replaced

  `ExSandbox.Egress.Pool` binds `127.0.0.1` in the **host** namespace and was
  designed as one pool for every sandbox — `013-FR-014c` argued for blast
  radius, not process count, and a process per sandbox is the heaviest way to
  get it.

  That design cannot work, and the reason is not a bug to fix. An `nft`
  `redirect` is DNAT **to the local machine as the namespace sees it**, so it
  can only ever reach a socket in that namespace. Measured: with the pool
  listening on the host and the redirect installed in the sandbox's namespace,
  the tenant's connect returned OK and the pool never saw the connection.

  The one alternative that preserved a single pool — `dnat` to the gateway —
  was measured and **does not work**: `pasta` is a userspace stack that
  terminates and re-originates connections, so the pool reads
  `ORIGINAL_DST=127.0.0.1:<pool port>`, its own address, and would judge every
  connection against that. See `egress-path-measurements.md` option (b).

  So the acceptor moves to where the redirect lands. The blast-radius argument
  survives in substance — no acceptor holds a platform credential, and no
  sandbox has a route to any other — but the shape it justified does not.

  ## Why a port helper rather than `:gen_tcp`

  The BEAM runs in the host namespace. A socket it opens is a host socket, and
  no option to `:gen_tcp.listen/2` changes which namespace a socket belongs to
  — that is fixed by the namespace of the process at the moment of the syscall.

  So the listener is a **separate OS process**, entered into the sandbox's
  namespace with `nsenter -t <holder-pid> -n`, which binds there and relays.

  ⚠️ `nsenter` targets the **namespace holder**, never `pasta`'s own pid. See
  `ExSandbox.Egress.Pasta`: the pidfile records pasta's host-side process, and
  entering that one puts the acceptor in the *host* namespace, where it would
  bind a host port and see none of the sandbox's traffic.

  ## What is enforced here, and what is not

  Nothing. The decision is `ExSandbox.Egress.Pool.decide/3`'s, unchanged and
  shared, so there is exactly one implementation of "may this sandbox reach
  this destination" and moving the listener did not fork it.

  ⚠️ The identity is different, though, and the difference is load-bearing.
  The host pool attributed a connection by `peername` masked to a `/30`,
  because every sandbox reached the same socket and they had to be told apart.
  This acceptor serves **one** namespace: nothing else can reach it, so the
  sandbox's identity is the acceptor's own existence rather than anything read
  off the connection. `source_key` is supplied at start and is not derived from
  the peer — a per-namespace listener that trusted `peername` would be reading
  a value the tenant partly controls in order to answer a question it has
  already answered by connecting at all.
  """

  use GenServer

  alias ExSandbox.Egress.Policy

  @typedoc "How to reach the namespace this acceptor serves."
  @type spec :: %{
          source_key: Policy.source_key(),
          holder_pid: pos_integer(),
          port: :inet.port_number()
        }

  @doc false
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name))
  end

  @impl true
  def init(opts) do
    source_key = Keyword.fetch!(opts, :source_key)
    holder_pid = Keyword.fetch!(opts, :holder_pid)
    port = Keyword.fetch!(opts, :port)

    {:ok,
     %{
       source_key: source_key,
       holder_pid: holder_pid,
       port: port,
       registry: Keyword.get(opts, :registry, ExSandbox.Egress.Registry)
     }}
  end

  @doc """
  The command that starts a listener inside `holder_pid`'s namespace.

  Built here rather than inlined at the call site so it is testable on a host
  where it cannot run — which is every developer machine that is not Linux, and
  therefore every host where this would otherwise go unverified.

  ⚠️ Binds `0.0.0.0`, not `127.0.0.1`. A `redirect` rewrites the destination
  address to a local one, but the packet arrives on the namespace's own
  interface rather than on loopback. Measured: the acceptor bound `0.0.0.0`
  received `peer=('172.19.0.4', 48160)` — the namespace's `eth0` address, not
  `127.0.0.1`. A loopback-only bind would have missed every connection while
  looking correct.

  This is safe **because of** where it binds: the namespace holds exactly one
  tenant and nothing else can route to it, so `0.0.0.0` there is narrower than
  `127.0.0.1` on the host.
  """
  @spec listener_command(
          pos_integer(),
          :inet.port_number(),
          String.t(),
          String.t(),
          Policy.source_key(),
          String.t(),
          {:inet.ip_address(), :inet.port_number()} | nil
        ) :: [String.t()]
  def listener_command(
        holder_pid,
        port,
        helper_path,
        verdict_path,
        source_key,
        resolver_path,
        nil
      ) do
    # ⚠️ Port `0` is the helper's "serve no DNS" signal, and it is reached only
    # when the plan carries no resolver -- which is `LaunchPlan`'s explicit
    # "this sandbox has no name resolution at all". It is not a fallback: a
    # resolver that was configured and could not be read raises at plan-build
    # time and never gets here.
    listener_command(
      holder_pid,
      port,
      helper_path,
      verdict_path,
      source_key,
      resolver_path,
      {{0, 0, 0, 0}, 0}
    )
  end

  def listener_command(
        holder_pid,
        port,
        helper_path,
        verdict_path,
        source_key,
        resolver_path,
        {resolver_address, resolver_port}
      ) do
    # ⚠️ `-U`, not a bare `-n`. The BEAM stands outside the platform user
    # namespace that owns this netns, and from there `-n` alone is refused --
    # see `ExSandbox.Egress.Netns` for the measurement of both forms from both
    # vantage points. Without it the acceptor never starts, the redirect points
    # at a port nothing is listening on, and from inside the sandbox that is
    # indistinguishable from a correctly denied destination: every denial check
    # passes and egress is simply broken.
    #
    # ⚠️ `--preserve-credentials` was removed here in lockstep with
    # `Netns.nsenter/2` and `Capability`'s probe. This was the **third** copy of
    # the same flags, and it was found by `ProbeComposabilityTest` rather than
    # by the grep that updated the other two -- had it been missed, the redirect
    # and the listener would have disagreed about which credentials to carry
    # into the namespace, and the resulting silence would have looked exactly
    # like a working allowlist.
    [
      "nsenter",
      "-t",
      "#{holder_pid}",
      "-n",
      "-U",
      helper_path,
      "#{port}",
      verdict_path,
      # ⚠️ The sandbox names itself by the /30 it was PROVISIONED with, supplied
      # here by the platform. It is never read off a connection: this acceptor
      # serves one namespace and nothing else can reach it, so its identity is
      # its own existence. Deriving identity from the peer would consult a value
      # the tenant partly controls to answer a question already answered by
      # connecting at all.
      source_key_text(source_key),
      # ⚠️ The DNS half (029 T015). The same process carries it for the same
      # reason it carries TCP -- a socket the sandbox can reach must be created
      # from inside the namespace -- and it holds no more policy for DNS than it
      # does for TCP: it relays query bytes to `ExSandbox.Egress.Resolver` and
      # writes back what the platform answers.
      #
      # ⚠️ The bind address is passed rather than defaulted in the helper. It
      # must be **the same address** the `nft` exemption permits, and a default
      # on either side is a second place for that value to live. If the two
      # drifted, the listener would be bound where nothing is permitted to send:
      # DNS silently dead, and every denial check still green.
      resolver_path,
      to_string(:inet.ntoa(resolver_address)),
      "#{resolver_port}"
    ]
  end

  @doc """
  Whether a connection from this acceptor's sandbox may reach `destination`.

  Delegates to `ExSandbox.Egress.Pool.decide/3` with the `source_key` this
  acceptor was started for — see the moduledoc on why the key is supplied
  rather than read from the peer.
  """
  @spec permits?(spec(), {String.t(), :inet.port_number()}, GenServer.server()) :: boolean()
  def permits?(%{source_key: source_key}, destination, registry) do
    ExSandbox.Egress.Pool.decide(sandbox_address(source_key), destination, registry) ==
      :permitted
  end

  @doc """
  The acceptor's own /30, expressed as an address `Policy.source_key/1` masks
  back to that /30 — so the shared decision function is reached with the
  identity this acceptor was started for.

  Public because `ExSandbox.Egress.Verdict` reconstructs the same address when
  an acceptor names its sandbox on the wire. ⚠️ Two copies of this arithmetic
  would be two things that must agree forever, and the symptom of them drifting
  is a sandbox judged against a *neighbouring* sandbox's allowlist — a
  cross-tenant policy error with no local sign of being wrong.
  """
  @spec sandbox_address(Policy.source_key()) :: :inet.ip4_address()
  def sandbox_address({a, b, c, d}), do: {a, b, c, d + 2}

  # The wire form of a /30, as `ExSandbox.Egress.Verdict` parses it back.
  defp source_key_text({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
end
