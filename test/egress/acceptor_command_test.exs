defmodule ExSandbox.Egress.AcceptorCommandTest do
  use ExUnit.Case, async: true

  alias ExSandbox.Egress.Acceptor

  # The acceptor's listener is an OS process entered into the sandbox's network
  # namespace. It cannot be exercised off Linux, so its *shape* is what gets
  # verified here -- the arrangement that keeps a Linux-only command from being
  # checked only where the whole launch works.
  describe "listener_command/7" do
    setup do
      %{
        command:
          Acceptor.listener_command(
            4242,
            18_080,
            "/opt/axonn/nsacceptor",
            "/var/run/axonn-egress-verdict.sock",
            {10, 0, 4, 0},
            # ⚠️ The DNS half arrived in 029 T015: the same process carries the
            # resolver relay, for the same reason it carries TCP -- a socket a
            # sandbox can reach has to be created from inside its namespace.
            # See `resolver_wiring_test.exs` for why the bind address is passed
            # rather than defaulted on either side.
            "/var/run/axonn-egress-resolver.sock",
            {{127, 0, 0, 1}, 53}
          )
      }
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
      # `-n -U` succeeds.
      #
      # The failure this guards is silent rather than loud: no acceptor means
      # the redirect points at a port nothing listens on, which from inside the
      # sandbox is indistinguishable from a correctly denied destination. Every
      # denial check would pass while egress was simply broken.
      assert "-U" in command
      # ⚠️ Absent, deliberately: the holder's userns is owned by the sandbox uid
      # under the split ordering, so credentials must be remapped rather than
      # preserved or the listener never binds.
      refute "--preserve-credentials" in command
    end

    test "the helper and its arguments follow the nsenter flags", %{command: command} do
      assert "/opt/axonn/nsacceptor" in command

      helper_index = Enum.find_index(command, &(&1 == "/opt/axonn/nsacceptor"))
      flag_index = Enum.find_index(command, &(&1 == "-U"))

      assert helper_index > flag_index,
             "the helper must be the command nsenter runs, not an argument to nsenter"

      # ⚠️ The full argv, in order, rather than a membership check. The helper
      # reads these positionally, so a value inserted in the wrong place is a
      # helper that binds its resolver where the sandbox's own address should
      # be -- and the symptom is a launch that fails at bind time, or worse, one
      # that binds somewhere the `nft` rule never permitted.
      assert Enum.drop(command, helper_index + 1) == [
               "18080",
               "/var/run/axonn-egress-verdict.sock",
               "10.0.4.0",
               "/var/run/axonn-egress-resolver.sock",
               "127.0.0.1",
               "53"
             ]
    end

    test "names the sandbox by the /30 it was provisioned with", %{command: command} do
      # ⚠️ The identity is supplied by the platform, never derived from the
      # connection. `ExSandbox.Egress.Verdict` parses this back to decide which
      # allowlist applies, so a wrong or forgeable value here judges a sandbox
      # against a NEIGHBOURING sandbox's policy -- a cross-tenant error with no
      # local sign of being wrong.
      assert "10.0.4.0" in command
    end

    test "carries the verdict socket, without which the acceptor denies everything", %{
      command: command
    } do
      # The acceptor holds no policy: it asks. A missing or wrong path here is
      # not a loud failure -- an unobtainable verdict is DENY, so the sandbox
      # loses egress entirely while every denial check still passes.
      assert "/var/run/axonn-egress-verdict.sock" in command
    end

    test "is an argv list, never an interpolated shell string", %{command: command} do
      assert Enum.all?(command, &is_binary/1)
      refute Enum.any?(command, &String.contains?(&1, " "))
    end
  end
end
