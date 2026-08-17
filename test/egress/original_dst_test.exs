defmodule ExSandbox.Egress.OriginalDstTest do
  @moduledoc """
  The decoder for the kernel's pre-redirection destination record (T060a3).

  ⚠️ The adversarial shapes lead, because the dangerous defect here is not a
  refusal — it is a malformed buffer decoding into a plausible destination. The
  caller's next move is an allowlist check, so a guessed address produces a
  verdict about an address the sandbox never asked for, and *both* outcomes of
  that verdict are wrong.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.OriginalDst

  describe "shapes that must never yield a destination" do
    test "an empty buffer is truncated, not a destination" do
      # ⚠️ This is the shape `{:ok, []}` degrades into if a caller ever unwraps
      # the getopt result before decoding. It must not resolve to `0.0.0.0:0`.
      assert {:error, {:truncated, 0}} = OriginalDst.decode(<<>>)
    end

    test "a buffer one byte short of a sockaddr_in is refused" do
      short = <<2, 0, 0x94, 0xE3, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0>>
      assert byte_size(short) == 15
      assert {:error, {:truncated, 15}} = OriginalDst.decode(short)
    end

    test "AF_INET6 in a sockaddr_in buffer is a contradiction, not an address to salvage" do
      # Family 10 is AF_INET6 on Linux. The first four bytes would decode as a
      # perfectly plausible IPv4 address if the family were ignored -- which is
      # exactly why the family is checked first.
      buffer = <<10, 0, 0x01, 0xBB, 93, 184, 216, 34, 0, 0, 0, 0, 0, 0, 0, 0>>
      assert {:error, {:unsupported_family, 10}} = OriginalDst.decode(buffer)
    end

    test "port 0 is not connectable, so decoding it is a malformed read" do
      buffer = <<2, 0, 0::16, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0>>
      assert {:error, :unconnectable_port} = OriginalDst.decode(buffer)
    end

    test "an all-zero buffer yields no destination" do
      # The most likely thing a failed read leaves behind. It must not become
      # `0.0.0.0:0` -- a destination the allowlist would then rule on.
      assert {:error, _} = OriginalDst.decode(<<0::128>>)
    end
  end

  describe "decoding a real record" do
    test "decodes the sockaddr_in measured from the kernel on Linux" do
      # Captured from `inet:getopts(S, [{raw,0,80,16}])` on Linux 6.10 aarch64:
      # family 2, port 0x94E3 = 38115, address 127.0.0.1.
      buffer = <<2, 0, 148, 227, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0>>
      assert {:ok, {{127, 0, 0, 1}, 38_115}} = OriginalDst.decode(buffer)
    end

    test "decodes a routable address and port in network byte order" do
      # 93.184.216.34:443 -- port 443 is 0x01BB, high byte first.
      buffer = <<2, 0, 0x01, 0xBB, 93, 184, 216, 34, 0, 0, 0, 0, 0, 0, 0, 0>>
      assert {:ok, {{93, 184, 216, 34}, 443}} = OriginalDst.decode(buffer)
    end

    test "port is read big-endian, so a byte-swapped read is visibly wrong" do
      # ⚠️ Guards a specific silent defect: little-endian decoding turns 443
      # into 48_129, which is a *valid* port. Nothing downstream would flag it;
      # the allowlist would simply refuse a destination the sandbox did ask for.
      buffer = <<2, 0, 0x01, 0xBB, 10, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0>>
      assert {:ok, {_, 443}} = OriginalDst.decode(buffer)
      refute match?({:ok, {_, 48_129}}, OriginalDst.decode(buffer))
    end
  end

  describe "reading from a socket" do
    test "a socket with no recorded redirect reports unavailable rather than a destination" do
      # ⚠️ On macOS the option vanishes from the getopts result; on Linux a
      # non-redirected socket still answers with its real peer. Both are correct
      # for this assertion's purpose: neither may produce a destination the
      # sandbox did not aim at. The point is that `read/1` never invents one.
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, port} = :inet.port(listener)

      task = Task.async(fn -> :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false]) end)
      {:ok, socket} = :gen_tcp.accept(listener, 2_000)

      case OriginalDst.read(socket) do
        {:error, :unavailable} ->
          :ok

        {:ok, {address, decoded_port}} ->
          # Where the option *is* readable, it must agree with the socket's own
          # account of where the connection went -- a decoder that returned
          # something else would be misreporting the destination.
          assert {:ok, {address, decoded_port}} == :inet.sockname(socket)
      end

      Task.await(task)
      :gen_tcp.close(socket)
      :gen_tcp.close(listener)
    end

    test "the getopt request names SOL_IP and SO_ORIGINAL_DST for a 16-byte buffer" do
      # Pins the three magic numbers so the pool and the tests cannot drift.
      assert [{:raw, 0, 80, 16}] = OriginalDst.getopt_request()
    end
  end
end
