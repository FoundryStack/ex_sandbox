defmodule ExSandbox.Hardening.SandboxUidTest do
  @moduledoc """
  The uid the launch drops to must be one the host can actually resolve
  (005 T036e, FR-007).

  ## The bug this exists to prevent

  `setpriv_args/1` built `--reuid=sandbox-<id>` from the sandbox id, and
  `contracts/hardening.md` §`build_command/2` shows exactly that shape. But
  nothing creates an OS user by that name, so `setpriv` fails to resolve it:

      setpriv: failed to parse reuid: 'sandbox-env-36'

  and the node exits 1 before Erlang starts. `--reuid` accepts a name *only* if
  it exists in the passwd database; otherwise it wants a numeric uid.

  This was not visible in any earlier test. `probe_setpriv/0` attempts the drop
  with the hardcoded `65534` (`nobody`), which resolves everywhere — so the
  capability probed true while every real launch failed. The probe and the launch
  disagreed about which uid they were testing.

  ## Why a numeric uid rather than creating users

  Creating a passwd entry per sandbox means the library mutating host user state:
  it needs root, it persists past the sandbox, and it makes reclamation a
  user-database cleanup problem. `005`'s threat model needs the uid to be
  *unprivileged and distinct per sandbox*, which a numeric uid from a configured
  range satisfies without any of that.

  `verify_applied/1` already returns `uid: integer()` — the contract expected a
  number at the far end while the command sent a name.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Hardening.Linux

  defp args_for(id) do
    {:ok, {_prog, args}} =
      Linux.compose_for_inspection(
        %ExSandbox.Sandbox{
          id: id,
          owner_ref: "owner-1",
          template_ref: "tpl",
          memory_limit_mb: 256,
          cpu_limit: 500,
          disk_quota_mb: 1024
        },
        []
      )

    args
  end

  defp flag_value(args, prefix) do
    Enum.find_value(args, fn arg ->
      arg = to_string(arg)
      if String.starts_with?(arg, prefix), do: String.replace_prefix(arg, prefix, "")
    end)
  end

  describe "--reuid" do
    test "is numeric, because setpriv cannot resolve a name that has no passwd entry" do
      uid = flag_value(args_for("env-36"), "--reuid=")

      assert uid =~ ~r/^\d+$/,
             """
             --reuid=#{uid} names an OS user nothing creates. setpriv exits:

                 setpriv: failed to parse reuid: '#{uid}'

             and the sandbox dies before Erlang starts.
             """
    end

    test "matches --regid, so the process has no group privilege its uid lacks" do
      args = args_for("env-37")
      assert flag_value(args, "--reuid=") == flag_value(args, "--regid=")
    end

    test "is never 0, which would make the whole drop decorative" do
      refute flag_value(args_for("env-38"), "--reuid=") == "0"
    end
  end

  describe "uid assignment" do
    test "differs between sandboxes, so one cannot signal or trace another" do
      a = flag_value(args_for("tenant-a"), "--reuid=")
      b = flag_value(args_for("tenant-b"), "--reuid=")

      refute a == b,
             """
             Both sandboxes run as uid #{a}. FR-007 requires an identity that
             cannot administer the host; two sandboxes sharing one can read each
             other's files and signal each other's processes.
             """
    end

    test "is stable for a given sandbox id, so verification and cleanup agree" do
      assert flag_value(args_for("stable-1"), "--reuid=") ==
               flag_value(args_for("stable-1"), "--reuid=")
    end
  end
end
