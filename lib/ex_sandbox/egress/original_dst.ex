defmodule ExSandbox.Egress.OriginalDst do
  @moduledoc """
  Recovers the destination a sandbox's connection was *originally* aimed at,
  before the netns redirect sent it to the pool (005 T060a3,
  `contracts/egress.md`).

  ## Why this exists at all

  Enforcement is transparent (`Principle VI`): the tenant application connects
  straight to its destination and is never told it is sandboxed, so there is no
  protocol frame in which it states where it wants to go — and deliberately so.
  Anything the sandbox *tells* us is a claim it controls. The kernel records the
  pre-redirection destination against the socket, and that record is the only
  account of the destination the sandbox cannot influence.

  ## Reading it, and the measurement that shaped this module

  `SO_ORIGINAL_DST` (`SOL_IP`, option 80) is readable from plain `:gen_tcp` via
  a `:raw` getopt — no NIF and no port driver. Measured on Linux 6.10 aarch64:

      inet:getopts(S, [{raw,0,80,16}])
      %=> {ok,[{raw,0,80,<<2,0,148,227,127,0,0,1,0,0,0,0,0,0,0,0>>}]}

  ⚠️ **`{:ok, []}` does not mean "no destination" — it means the option was not
  readable, and it is returned for an option that cannot exist.** Measured on
  the same OTP, a deliberately nonsensical `{:raw, 999, 999, 16}` also returns
  `{:ok, []}`, and on macOS `SO_ORIGINAL_DST` *silently vanishes from the result
  list* while a control option in the same call returns its bytes:

      inet:getopts(S, [{raw,6,1,4}, {raw,0,80,16}])   # macOS
      %=> {:ok, [{:raw, 6, 1, <<0,0,0,0>>}]}          # ORIGINAL_DST just gone

  So absence, invalidity, and "read successfully but empty" are one value. That
  is why this module returns `{:error, reason}` for every non-decodable shape
  and **never** a partially-trusted result: there is no bit pattern here that
  earns the benefit of the doubt. Had this been written as
  `{:ok, [{:raw, _, _, dst}]} -> parse(dst)` with a catch-all, it would compile,
  read correctly, and — on any host where the option is unavailable — take the
  catch-all for every connection while looking like working enforcement.

  ## What is decoded, and what is refused

  A `sockaddr_in` is 16 bytes: family (2), port (2, network order), address (4),
  padding (8). This decodes **only** `AF_INET` (family 2). Anything else is an
  error rather than a best effort:

    * a truncated buffer cannot be a destination
    * `AF_INET6` (family 10) in a 16-byte `sockaddr_in` buffer is a
      contradiction, not an address to salvage
    * port 0 is not connectable, so a decode yielding it is a malformed read
      rather than a destination

  ⚠️ Each refusal matters because the caller's next move is an allowlist check.
  A decoder that guessed would hand `Policy.permits?/2` a destination the
  sandbox never asked for, and the verdict — permit or refuse — would be about
  the wrong address either way.
  """

  @typedoc "A decoded IPv4 destination."
  @type destination :: {:inet.ip4_address(), :inet.port_number()}

  @typedoc "Why a buffer could not be decoded into a destination."
  @type error ::
          :unavailable
          | {:truncated, non_neg_integer()}
          | {:unsupported_family, non_neg_integer()}
          | :unconnectable_port

  @sol_ip 0
  @so_original_dst 80
  @sockaddr_in_bytes 16
  @af_inet 2

  @doc """
  The `:inet.getopts/2` request that reads `SO_ORIGINAL_DST`.

  Exposed so tests can issue the same request the pool does, rather than
  restating the three magic numbers and drifting from it.
  """
  @spec getopt_request() :: [{:raw, non_neg_integer(), non_neg_integer(), non_neg_integer()}]
  def getopt_request, do: [{:raw, @sol_ip, @so_original_dst, @sockaddr_in_bytes}]

  @doc """
  Reads the pre-redirection destination from an accepted socket.

  Returns `{:error, :unavailable}` on any host or socket where the option does
  not come back — which, per the module note, is the same value the OS gives for
  an option that does not exist. The caller must treat that as "no destination
  established", never as "no restriction".
  """
  @spec read(:gen_tcp.socket()) :: {:ok, destination()} | {:error, error()}
  def read(socket) do
    case :inet.getopts(socket, getopt_request()) do
      {:ok, [{:raw, @sol_ip, @so_original_dst, buffer}]} ->
        decode(buffer)

      # ⚠️ Covers `{:ok, []}` (option absent or invalid -- indistinguishable),
      # `{:error, _}`, and any shape this OTP might return that we have not
      # measured. All three mean the same thing: no destination was established.
      _ ->
        {:error, :unavailable}
    end
  end

  @doc """
  Decodes a `sockaddr_in` buffer into `{address, port}`.

  Split from `read/1` so every rejected shape is testable without a socket, and
  without needing a host where the redirect exists.
  """
  @spec decode(binary()) :: {:ok, destination()} | {:error, error()}
  # ⚠️ **Length is checked before anything is read out of the buffer**, and the
  # ordering is the guarantee rather than a tidiness preference. The first
  # version of this clause matched `<<@af_inet, _pad, port::16, a, b, c, d,
  # _rest::binary>>` with the length guard on a *later* clause -- and
  # `_rest::binary` matches zero bytes, so a 15-byte truncated buffer decoded
  # successfully into `127.0.0.1:38115` and never reached the guard.
  #
  # A short read is the likeliest malformed input there is, and it produced the
  # most dangerous possible output: a confident, entirely plausible destination
  # that `Policy.permits?/2` would then rule on. Caught by the adversarial test
  # on its first run, not by reading the clause.
  def decode(buffer) when is_binary(buffer) and byte_size(buffer) < @sockaddr_in_bytes do
    {:error, {:truncated, byte_size(buffer)}}
  end

  def decode(<<@af_inet, _pad, port::16, a, b, c, d, _rest::binary>>) when port > 0 do
    {:ok, {{a, b, c, d}, port}}
  end

  def decode(<<@af_inet, _pad, 0::16, _rest::binary>>), do: {:error, :unconnectable_port}

  def decode(<<family, _pad, _rest::binary>>), do: {:error, {:unsupported_family, family}}
end
