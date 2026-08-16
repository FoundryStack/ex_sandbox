defmodule ExSandbox.Mechanism.Beam.IsolationFilesystemTest do
  @moduledoc """
  A sandbox cannot read the platform's files, another tenant's storage, or
  escalate to another OS user (005 T032, `FR-007`, `FR-010`).

  Nothing inside the BEAM provides any of this. `File.read/1` in tenant code
  reaches whatever the OS process can reach, so these three guarantees come
  entirely from the mount namespace and uid drop in the hardening wrapper — and
  are absent the moment that wrapper is not applied.
  """
  use ExUnit.Case, async: false

  @moduletag :isolation

  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  defp sandbox(tag) do
    %Sandbox{
      id: "fs-#{tag}-#{System.unique_integer([:positive])}",
      owner_ref: "owner-#{tag}",
      template_ref: "conformance-template",
      cpu_limit: 500,
      memory_limit_mb: 128,
      disk_quota_mb: 256
    }
  end

  defp launch(tag) do
    {:ok, provisioned} = Beam.provision(sandbox(tag))
    on_exit(fn -> Beam.destroy(provisioned) end)
    provisioned
  end

  # ⚠️ `Beam.call/5`, never `:erpc.call/5` -- a sandbox under `--unshare-net` has
  # no network interfaces, so distribution-based RPC raises
  # `{:erpc, :noconnection}` against a perfectly healthy sandbox. The stdio
  # control channel is what survives the confinement being real.
  #
  # ⚠️ Erlang's `:file`, never Elixir's `File`. The sandbox boots a bare `erl`
  # with only OTP on its code path -- `:code.which(File)` there answers
  # `:non_existing` -- so every `File` call returns `:undef`. That is the
  # dangerous kind of wrong: `{:error, :undef}` and `{:error, :eacces}` both
  # satisfy "the sandbox could not read it", so these tests would have passed
  # against a sandbox with no filesystem confinement at all.
  defp eval(sb, module, function, args) do
    assert {:ok, result} = Beam.call(sb, module, function, args)
    result
  end

  test "platform configuration files are unreachable" do
    sb = launch("a")

    # A real file with real content, created outside the sandbox's storage.
    # Probing a path that does not exist would report `:enoent` and pass whether
    # or not confinement works.
    path = Path.join(System.tmp_dir!(), "platform_secret_#{System.unique_integer([:positive])}")
    File.write!(path, "SECRET_KEY_BASE=must-not-be-readable")
    on_exit(fn -> File.rm_rf(path) end)

    assert File.read!(path) =~ "must-not-be-readable",
           "precondition failed: the platform cannot read its own file"

    assert {:error, reason} = eval(sb, :file, :read_file, [path]),
           "sandbox read a platform file at #{path} -- the mount namespace is not confining it"

    assert reason in [:enoent, :eacces, :eperm]
  end

  test "another sandbox's storage is unreachable" do
    sb_a = launch("a")
    sb_b = launch("b")

    # Written by tenant B into **B's own** storage, so the path really exists for
    # somebody -- the strongest form of this test. An earlier version wrote to
    # `sb_a.id`'s path and discarded the result, so a silently failed write left
    # nothing to read and the assertion passed for the wrong reason.
    # The real bind path from the hardening module. `/sandbox/<id>` -- what an
    # earlier version guessed -- exists nowhere, so the write failed `:enoent`
    # and tenant A's read failed for the same reason rather than for lack of
    # access. Both assertions passed against a path neither tenant could use.
    target = Path.join(ExSandbox.Hardening.Linux.storage_path(sb_b), "private.txt")

    assert :ok = eval(sb_b, :file, :write_file, [target, "tenant b data"]),
           "precondition failed: tenant B could not write its own storage"

    assert {:ok, "tenant b data"} = eval(sb_b, :file, :read_file, [target]),
           "precondition failed: tenant B cannot read back what it just wrote"

    assert {:error, _} = eval(sb_a, :file, :read_file, [target]),
           "tenant A read tenant B's storage"
  end

  test "privilege escalation to another OS user is refused" do
    sb = launch("a")

    uid = sb |> eval(:os, :cmd, [~c"id -u"]) |> to_string() |> String.trim()

    refute uid == "0",
           "sandbox is running as root -- `setpriv` did not drop privileges (FR-010)"

    # Attempting to become root is refused rather than merely unattempted.
    output = sb |> eval(:os, :cmd, [~c"setpriv --reuid 0 id -u 2>&1"]) |> to_string()

    refute String.trim(output) == "0",
           "sandbox escalated to uid 0: #{output}"
  end
end
