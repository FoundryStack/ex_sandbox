defmodule ExSandbox.Egress.VerdictReachabilityTest do
  @moduledoc """
  The verdict socket is reachable by the uid the acceptor actually runs as
  (005 T060a4e).

  ## Why this file exists

  `nsacceptor.py` runs inside the sandbox's namespace, entered *after* `setpriv`
  under the split launch ordering — so it runs as the **sandbox uid**. The BEAM
  binds the verdict socket as root, and a unix socket inherits mode `0755` from
  the umask, which denies `connect(2)` to every other uid.

  `ask_platform/4` treats any failure to obtain a verdict as a refusal. That is
  correct — fail-open would make an unreachable supervisor indistinguishable
  from a permissive allowlist — and it is exactly what made this silent: every
  destination was denied, **every denial check passed**, and the only symptom
  was the permitted destination being unreachable.

  Measured (`docker/verdict-socket-probe.py`):

      mode 0755, uid 0  -> sandbox uid: PermissionError [Errno 13]
      mode 0666         -> sandbox uid: GOT:PERMIT

  ⚠️ This test asserts the **mode**, not a successful cross-uid connect, because
  a test cannot drop privilege on the host it runs on. The mode is the thing
  that was wrong and the thing a future change would get wrong again.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Egress.Verdict

  setup do
    path =
      Path.join(
        System.tmp_dir!(),
        "verdict-reach-#{System.unique_integer([:positive])}.sock"
      )

    {:ok, pid} = Verdict.start_link(path: path, name: nil)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    %{path: path}
  end

  describe "the socket the acceptor must connect to" do
    test "is world-connectable, because the acceptor is not root", %{path: path} do
      %File.Stat{mode: mode} = File.stat!(path)
      permissions = Bitwise.band(mode, 0o777)

      # ⚠️ The WRITE bit for "other" (0o002), not merely any access. `connect(2)`
      # on a unix socket requires write permission, and the default mode here is
      # `0755` -- which grants other *read and execute*. A first version of this
      # test checked `0o006` and passed against the unfixed code, because
      # `0o755 &&& 0o006` is 4. It measured the host's umask rather than this
      # module's behaviour, and a sabotage that removed the chmod entirely left
      # it green.
      assert Bitwise.band(permissions, 0o002) != 0,
             """
             The verdict socket is mode #{Integer.to_string(permissions, 8)}.

             `nsacceptor.py` runs as the SANDBOX uid, not root, so it cannot
             connect(2) here. Every verdict then fails, and because an
             unobtainable verdict is correctly a REFUSAL, every destination is
             denied -- which passes every denial check and shows up only as the
             permitted destination being unreachable.
             """
    end

    test "still exists and is a socket, not a regular file", %{path: path} do
      # A chmod that silently created or replaced a plain file would satisfy the
      # mode assertion above while nothing could connect to it.
      assert File.exists?(path)
      assert %File.Stat{type: :other} = File.stat!(path)
    end

    test "answers a query rather than accepting an instruction", %{path: path} do
      # ⚠️ Why widening the mode does not widen the boundary. Reaching this
      # socket lets a caller ASK whether a source may reach a destination; it
      # does not let one change the answer. `FR-011b` is enforced by `Registry`
      # holding the only copy of the allowlist, not by the socket's mode.
      {:ok, socket} =
        :gen_tcp.connect({:local, path}, 0, [:binary, active: false, packet: :line], 2_000)

      # An unregistered source: default-deny must apply.
      :ok = :gen_tcp.send(socket, "10.99.99.0 1.1.1.1 443\n")

      assert {:ok, answer} = :gen_tcp.recv(socket, 0, 2_000)
      assert String.trim(answer) == "DENY"

      :gen_tcp.close(socket)
    end
  end
end
