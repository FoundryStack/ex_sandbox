defmodule ExSandbox.Mechanism.Beam.ConnectProbeVerdictTest do
  @moduledoc """
  A completed TCP handshake is not evidence the destination was reached
  (005 T060a4e, `FR-011a`, `FR-011f`).

  ## Why this file exists

  `Egress.Acceptor` is a **transparent** proxy. The `nft` redirect sends every
  outbound connection to it, so the handshake always completes — against the
  acceptor — whether the destination is permitted or denied. On a refusal the
  acceptor closes the socket **without answering**, which is exactly what
  `FR-011a` requires (a denied destination must be indistinguishable from an
  unreachable one) and what `FR-011f` protects (no ranking REJECT above DROP).

  The connect probe scored `{:ok, socket}` as `:connected`, so with the boundary
  finally *working*, two denial checks reported breaches that never happened:

      The hostile act SUCCEEDED. It should have been refused.
      Evidence: "the sandbox opened a connection to the platform (127.0.0.1:43651)"

  ⚠️ **The enforcement was correct throughout.** Measured separately
  (`docker/loopback-redirect-probe.py`): the redirect *does* catch loopback, and
  `127.0.0.1` inside the netns *is* the host's. Nothing was relayed. The probe
  simply could not see the difference.

  ⚠️ **And the probe was correct for every configuration it had been measured
  against.** Under `--unshare-net` there was no acceptor and no listener, so
  `connect` genuinely failed and `:connected` genuinely meant reached. It became
  wrong the moment the boundary started *enforcing* rather than *isolating*.

  These tests use real sockets rather than a sandbox, because the property is
  about what TCP reports — which is the thing that was assumed.
  """
  use ExUnit.Case, async: true

  defp listener do
    {:ok, l} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(l)
    {l, port}
  end

  describe "what a handshake against the enforcement point proves" do
    test "connect SUCCEEDS against a listener that accepts and immediately closes" do
      # ⚠️ The measurement the old probe's verdict rested on, pinned so the
      # assumption cannot be made again. This is the acceptor's refusal path
      # byte for byte, and `connect` returns `{:ok, _}`.
      {l, port} = listener()

      spawn(fn ->
        {:ok, s} = :gen_tcp.accept(l)
        :gen_tcp.close(s)
      end)

      assert {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [], 2_000)
      :gen_tcp.close(socket)
    end

    test "a refusal is visible in the READ, which is where the probe must look" do
      {l, port} = listener()

      spawn(fn ->
        {:ok, s} = :gen_tcp.accept(l)
        :gen_tcp.close(s)
      end)

      {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 2_000)

      assert :gen_tcp.recv(socket, 0, 1_000) == {:error, :closed},
             "an acceptor refusal closes without answering; that is the signal"
    end

    test "a relayed connection is distinguishable: data crosses" do
      {l, port} = listener()

      spawn(fn ->
        {:ok, s} = :gen_tcp.accept(l)
        :gen_tcp.send(s, "ORIGIN-REPLY")
        Process.sleep(200)
        :gen_tcp.close(s)
      end)

      {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 2_000)

      assert {:ok, "ORIGIN-REPLY"} = :gen_tcp.recv(socket, 0, 1_000)
      :gen_tcp.close(socket)
    end

    test "a silent-but-open destination reads as TIMEOUT, not as closed" do
      # ⚠️ Why `:timeout` must count as REACHED. Most services wait for the
      # client to speak first, so silence on an open connection is the normal
      # case for a genuinely reached destination. Scoring it as a refusal would
      # be the false pass: a real breach against a quiet service would read as
      # a held boundary.
      {l, port} = listener()

      holder =
        spawn(fn ->
          {:ok, s} = :gen_tcp.accept(l)
          Process.sleep(3_000)
          :gen_tcp.close(s)
        end)

      {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 2_000)

      assert :gen_tcp.recv(socket, 0, 300) == {:error, :timeout},
             "an open-but-silent peer must not look like a refusal"

      :gen_tcp.close(socket)
      Process.exit(holder, :kill)
    end
  end
end
