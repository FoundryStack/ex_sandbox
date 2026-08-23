defmodule ExSandbox.Egress.ByteProbe do
  @moduledoc """
  The `029-FR-016` instrument: **did any bytes cross?**

  Every probe in `029` Phase 1 onward is built on this. It exists because the
  obvious instrument — *"did `:gen_tcp.connect/4` return `:ok`?"* — reports a
  boundary that is not there.

  ## Why "did connect succeed?" is the wrong question

  ⚠️ `ExSandbox.Egress.Acceptor` is a **transparent** proxy. The redirect sends
  every outbound connection to it, so the TCP handshake completes — against the
  acceptor — for a permitted and a refused destination alike. On a refusal the
  acceptor closes without answering, which is what `FR-011a` *requires*: a
  denied destination must be indistinguishable from an unreachable one.
  MEASURED (`egress-research.md:365-368`):

      # a listener that accepts and immediately closes -- the refusal path
      :gen_tcp.connect(~c"127.0.0.1", port, [], 2000)  #=> {:ok, #Port<0.4>}

  A connect-shaped probe gets `:ok` both times and reports egress policed when
  nothing is policed. This is the third weak-negative instrument this corpus has
  been bitten by.

  ## Why the probe speaks first

  ⚠️ Most services — `1.1.1.1:443` among them — wait for the client before
  saying anything. A read-only probe cannot tell a reached-but-quiet destination
  from a refused one inside its timeout, so `leg/4` always sends before it
  reads.

  ## ⚠️ Silence is not a refusal — the reason this module is not one function

  A destination that drops packets and a destination with nobody listening are
  **indistinguishable**. Both are silence. So `:silent` on its own is not
  evidence of anything, and a probe that reports it as a refusal is a probe that
  passes when the network is unplugged, when the timeout is too short, when the
  responder never started, and when the runner has no route at all.

  The previous phase hit this exactly: a UDP check passed, and the pass was
  vacuous, because both legs it probed were under no obligation to answer.

  So silence is only readable as a refusal once something *else* has
  established, independently, that bytes could have crossed. That is the
  **reference leg**, and `attempt/2` will not return a refusal without one:

      reference leg  →  subject leg  →  reference leg

  ⚠️ **The reference leg runs on both sides of the subject, and both runs must
  cross.** Running it only beforehand leaves a window: the responder dies, the
  route drops, the container is torn down, and the subject's silence is then
  scored as a held boundary. Bracketing costs two loopback round-trips and
  closes that window.

  ⚠️ **The reference leg is not the subject destination.** Its job is to answer
  "if bytes could cross right now, would this instrument see them?" — it is
  aimed at a responder that is *obliged* to answer. A reference leg pointed at
  the same destination the subject is testing answers a different, useless
  question.

  ## ⚠️ This instrument deliberately disagrees with `Mechanism.Beam.probe_exprs/3`

  That probe scores a read timeout as **reached**, and its comment is right to:
  its question is *"was this refused?"*, asked with no reference leg, and with
  no reference leg the safe reading of silence is "reached" — because scoring
  silence as a refusal would be the false pass, reporting a held boundary while
  a real breach against a quiet service goes unnoticed.

  This module scores the same timeout as `:silent`, and then **refuses to
  interpret it** until the reference leg has crossed twice. The two are not in
  conflict; they are the same caution reached from opposite ends. `probe_exprs/3`
  declines to read silence at all. `attempt/2` earns the right to read it.

  ## Answers and verdicts are different types, on purpose

  `answer/0` is what one leg observed. `verdict/0` is what the *set* of legs
  means. Collapsing them is how a single silent leg becomes a claimed boundary.

      leg/4      :: ... -> answer()      # an observation, uninterpreted
      verdict/2  :: answer, answer -> verdict()   # pure, and the only interpreter
      attempt/2  :: fun, fun -> verdict()         # runs the legs, gated

  `verdict/2` is pure and takes no sockets, so the interpretation table is
  testable without a network.
  """

  @typedoc "The transports `029` has to cover. `FR-013`: an allowlist a tenant can bypass by choosing a transport is not an allowlist."
  @type transport :: :tcp | :udp

  @typedoc """
  What a **single leg** observed. Uninterpreted on purpose.

  * `{:crossed, bytes}` — bytes came back. The only positive evidence there is.
  * `:silent` — nothing came back inside the timeout, or the peer closed without
    answering. ⚠️ Means *nothing* on its own. See the moduledoc.
  * `{:no_socket, reason}` — the socket could not be opened or the connect
    failed outright (`:econnrefused`, `:enetunreach`, …). Also not, by itself,
    a refusal: an unplugged cable produces it too.
  """
  @type answer :: {:crossed, binary()} | :silent | {:no_socket, term()}

  @typedoc """
  What the **set** of legs means.

  * `{:reached, bytes}` — bytes crossed from the subject vantage point.
  * `{:refused, answer}` — the subject observed no bytes *while* the reference
    leg was crossing, carrying the subject's own answer as the evidence.
  * `{:inconclusive, reason}` — the reference leg did not cross, so nothing the
    subject observed can be attributed. ⚠️ This is a **result**, not an error.
    A run that reports it has not failed; it has declined to lie.
  """
  @type verdict ::
          {:reached, binary()}
          | {:refused, answer()}
          | {:inconclusive, {:reference_leg, :before | :after, answer()}}

  @typedoc "A responder standing by to answer the reference leg."
  @type responder :: %{
          transport: transport(),
          address: :inet.ip_address(),
          port: :inet.port_number(),
          banner: binary(),
          pid: pid()
        }

  # ⚠️ Generous on purpose. The timeout is the instrument's resolution: a
  # destination slower than this is reported `:silent`, and under a crossing
  # reference leg that reads as a refusal. Callers probing anything but loopback
  # should not shorten it.
  @default_timeout_ms 3_000

  # ⚠️ The probe speaks first (see moduledoc), and what it says is arbitrary --
  # it only has to arrive. Recognisable in a packet capture rather than random.
  @default_payload "ex-sandbox-byte-probe"

  @doc """
  Runs one leg and reports what it observed, without interpreting it.

  ⚠️ Returns an `t:answer/0`, never a verdict. A caller reading `:silent` as a
  refusal without a reference leg has rebuilt the bug this module exists to
  prevent — use `attempt/2`.

  Options: `:payload` (default `#{inspect(@default_payload)}`),
  `:timeout` (default `#{@default_timeout_ms}` ms).
  """
  @spec leg(
          transport(),
          :inet.ip_address() | charlist() | String.t(),
          :inet.port_number(),
          keyword()
        ) ::
          answer()
  def leg(transport, address, port, opts \\ [])

  def leg(:tcp, address, port, opts) do
    payload = Keyword.get(opts, :payload, @default_payload)
    timeout = Keyword.get(opts, :timeout, @default_timeout_ms)

    case :gen_tcp.connect(host(address), port, [:binary, active: false], timeout) do
      {:ok, socket} ->
        # ⚠️ Speak first. A read-only probe cannot tell reached-but-quiet from
        # refused. The send's own result is deliberately ignored: against the
        # acceptor's refusal path the peer may already be gone, and the question
        # is what comes *back*, not whether the write landed.
        _ = :gen_tcp.send(socket, payload)

        answer = read_tcp(socket, timeout)
        :gen_tcp.close(socket)
        answer

      {:error, reason} ->
        {:no_socket, reason}
    end
  end

  def leg(:udp, address, port, opts) do
    payload = Keyword.get(opts, :payload, @default_payload)
    timeout = Keyword.get(opts, :timeout, @default_timeout_ms)

    # ⚠️ UDP has no handshake, so there is no "did connect succeed?" to be
    # tempted by -- bytes are the only signal there has ever been. That makes
    # the reference leg *more* load-bearing here, not less: every UDP failure
    # mode, policed or broken, looks the same from this side.
    case :gen_udp.open(0, [:binary, active: false]) do
      {:ok, socket} ->
        answer =
          case :gen_udp.send(socket, host(address), port, payload) do
            :ok -> read_udp(socket, timeout)
            {:error, reason} -> {:no_socket, reason}
          end

        :gen_udp.close(socket)
        answer

      {:error, reason} ->
        {:no_socket, reason}
    end
  end

  defp read_tcp(socket, timeout) do
    case :gen_tcp.recv(socket, 0, timeout) do
      {:ok, data} ->
        {:crossed, IO.iodata_to_binary(data)}

      # ⚠️ Scored `:silent`, NOT "reached". This is the single line where this
      # instrument parts company with `Mechanism.Beam.probe_exprs/3`, and the
      # moduledoc explains why both are right.
      {:error, :timeout} ->
        :silent

      # The acceptor's refusal path: accept, then close without answering.
      {:error, :closed} ->
        :silent

      {:error, :econnreset} ->
        :silent

      {:error, reason} ->
        {:no_socket, reason}
    end
  end

  defp read_udp(socket, timeout) do
    case :gen_udp.recv(socket, 0, timeout) do
      {:ok, {_address, _port, data}} -> {:crossed, IO.iodata_to_binary(data)}
      {:error, :timeout} -> :silent
      {:error, reason} -> {:no_socket, reason}
    end
  end

  defp host(address) when is_tuple(address), do: address
  defp host(address) when is_list(address), do: address
  defp host(address) when is_binary(address), do: String.to_charlist(address)

  @doc """
  Interprets a subject leg **in light of** a reference leg. Pure.

  ⚠️ The `{:crossed, _}` reference clause comes first and there is no clause
  that reads a subject answer without one. That is the gate, expressed as
  pattern matching rather than as discipline: there is no code path from
  `:silent` to `{:refused, _}` that does not pass a crossing reference leg.
  """
  @spec verdict(answer(), answer()) :: verdict()
  def verdict(reference, subject)

  def verdict({:crossed, _reference_bytes}, {:crossed, bytes}), do: {:reached, bytes}
  def verdict({:crossed, _reference_bytes}, :silent), do: {:refused, :silent}

  def verdict({:crossed, _reference_bytes}, {:no_socket, reason}),
    do: {:refused, {:no_socket, reason}}

  # ⚠️ The reference leg did not cross, so the subject is not consulted at all.
  # Whatever it saw is unattributable, and an unattributable observation
  # reported as a refusal is the vacuous pass.
  def verdict(reference, _subject), do: {:inconclusive, {:reference_leg, :before, reference}}

  @doc """
  The instrument. Runs `reference` → `subject` → `reference` and interprets.

  Both functions are zero-arity and return an `t:answer/0` — typically
  `leg/4` partially applied. Keeping them opaque is what lets the subject leg
  run somewhere this process cannot reach directly (inside a sandbox, over
  `:peer.call/4`, through `nsenter`) while the reference leg runs here.

  ⚠️ **Both reference runs must cross.** If the one after the subject does not,
  the verdict is `{:inconclusive, {:reference_leg, :after, answer}}` even though
  the first one crossed — the machinery stopped working at some point during the
  subject leg and there is no way to know which side of it.
  """
  @spec attempt((-> answer()), (-> answer())) :: verdict()
  def attempt(reference, subject) when is_function(reference, 0) and is_function(subject, 0) do
    case reference.() do
      {:crossed, _bytes} = before ->
        observed = subject.()

        case reference.() do
          {:crossed, _bytes} ->
            verdict(before, observed)

          # ⚠️ Not a failure of the subject. The instrument stopped being able
          # to see bytes partway through, so the subject's observation -- of
          # either kind -- means nothing.
          after_answer ->
            {:inconclusive, {:reference_leg, :after, after_answer}}
        end

      before ->
        {:inconclusive, {:reference_leg, :before, before}}
    end
  end

  @doc """
  Starts a responder for the reference leg to aim at, on an ephemeral port.

  ⚠️ Ephemeral (`port 0`) and bound to loopback. `029`'s tasks marked `[P]` must
  not bind a fixed port — the contended resources in this project are the build
  and port 4002, not the files.

  The responder reads whatever the probe says, replies with `banner`, and closes.
  ⚠️ It reads **before** it replies so it behaves like a real service, and so a
  probe that speaks first does not race its reply against the close.

  Options: `:banner` (default a unique binary), `:address` (default
  `{127, 0, 0, 1}`).
  """
  @spec responder(transport(), keyword()) :: {:ok, responder()} | {:error, term()}
  def responder(transport, opts \\ [])

  def responder(:tcp, opts) do
    address = Keyword.get(opts, :address, {127, 0, 0, 1})
    banner = Keyword.get_lazy(opts, :banner, &unique_banner/0)

    with {:ok, listen} <-
           :gen_tcp.listen(0, [:binary, ip: address, active: false, reuseaddr: true, backlog: 16]),
         {:ok, port} <- :inet.port(listen) do
      pid = spawn(fn -> tcp_accept_loop(listen, banner) end)
      :ok = :gen_tcp.controlling_process(listen, pid)

      {:ok, %{transport: :tcp, address: address, port: port, banner: banner, pid: pid}}
    end
  end

  def responder(:udp, opts) do
    address = Keyword.get(opts, :address, {127, 0, 0, 1})
    banner = Keyword.get_lazy(opts, :banner, &unique_banner/0)

    with {:ok, socket} <- :gen_udp.open(0, [:binary, ip: address, active: false]),
         {:ok, port} <- :inet.port(socket) do
      pid = spawn(fn -> udp_reply_loop(socket, banner) end)
      :ok = :gen_udp.controlling_process(socket, pid)

      {:ok, %{transport: :udp, address: address, port: port, banner: banner, pid: pid}}
    end
  end

  @doc """
  Stops a responder.

  ⚠️ Kills **the pid this module started**, captured at `responder/2`. Never a
  pattern-matched sweep over processes.
  """
  @spec close_responder(responder()) :: :ok
  def close_responder(%{pid: pid}) do
    Process.exit(pid, :kill)
    :ok
  end

  @doc """
  A convenience leg aimed at a responder — the usual `reference` for `attempt/2`.
  """
  @spec reference_leg(responder(), keyword()) :: (-> answer())
  def reference_leg(%{transport: transport, address: address, port: port}, opts \\ []) do
    fn -> leg(transport, address, port, opts) end
  end

  defp tcp_accept_loop(listen, banner) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        # ⚠️ Read first. The probe speaks first, and a responder that replied
        # and closed immediately could have its close overtake the probe's
        # write, producing an `:epipe` that reads as a refusal.
        _ = :gen_tcp.recv(socket, 0, 1_000)
        _ = :gen_tcp.send(socket, banner)
        :gen_tcp.close(socket)
        tcp_accept_loop(listen, banner)

      {:error, _reason} ->
        :ok
    end
  end

  defp udp_reply_loop(socket, banner) do
    case :gen_udp.recv(socket, 0) do
      {:ok, {address, port, _data}} ->
        _ = :gen_udp.send(socket, address, port, banner)
        udp_reply_loop(socket, banner)

      {:error, _reason} ->
        :ok
    end
  end

  defp unique_banner, do: "byte-probe-#{System.unique_integer([:positive])}"
end
