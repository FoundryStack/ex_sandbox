defmodule ExSandbox.Egress.AcceptorCommandTest do
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Acceptor

  # The acceptor's listener is an OS process entered into the sandbox's network
  # namespace. It cannot be exercised off Linux, so its *shape* is what gets
  # verified here -- the arrangement that keeps a Linux-only command from being
  # checked only where the whole launch works.
  describe "listener_command/3" do
    setup do
      %{command: Acceptor.listener_command(4242, 18_080, "/opt/axonn/nsacceptor")}
    end

    test "enters the target namespace by holder pid", %{command: command} do
      assert Enum.take(command, 4) == ["nsenter", "-t", "4242", "-n"]
    end

    test "joins the userns that owns the netns, without which it never binds", %{
      command: command
    } do
      # ⚠️ Measured on `docker-isolation:latest` under unprivileged
      # `docker run --device /dev/net/tun`. From outside the platform user
      # namespace -- which is where the BEAM stands, `/proc/self/ns/user`
      # differing from the holder's -- a bare `-n` is REFUSED and
      # `-n -U --preserve-credentials` succeeds.
      #
      # The failure this guards is silent rather than loud: no acceptor means
      # the redirect points at a port nothing listens on, which from inside the
      # sandbox is indistinguishable from a correctly denied destination. Every
      # denial check would pass while egress was simply broken.
      assert "-U" in command
      assert "--preserve-credentials" in command
    end

    test "the helper and its port follow the nsenter flags", %{command: command} do
      assert List.last(command) == "18080"
      assert "/opt/axonn/nsacceptor" in command

      helper_index = Enum.find_index(command, &(&1 == "/opt/axonn/nsacceptor"))
      flag_index = Enum.find_index(command, &(&1 == "--preserve-credentials"))

      assert helper_index > flag_index,
             "the helper must be the command nsenter runs, not an argument to nsenter"
    end

    test "is an argv list, never an interpolated shell string", %{command: command} do
      assert Enum.all?(command, &is_binary/1)
      refute Enum.any?(command, &String.contains?(&1, " "))
    end
  end
end
