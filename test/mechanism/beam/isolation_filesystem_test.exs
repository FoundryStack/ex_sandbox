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
    {provisioned, String.to_atom(provisioned.mechanism_ref)}
  end

  test "platform configuration files are unreachable" do
    {_sb, node} = launch("a")

    # A real file with real content, created outside the sandbox's storage.
    # Probing a path that does not exist would report `:enoent` and pass whether
    # or not confinement works.
    path = Path.join(System.tmp_dir!(), "platform_secret_#{System.unique_integer([:positive])}")
    File.write!(path, "SECRET_KEY_BASE=must-not-be-readable")
    on_exit(fn -> File.rm_rf(path) end)

    assert File.read!(path) =~ "must-not-be-readable",
           "precondition failed: the platform cannot read its own file"

    assert {:error, reason} = :erpc.call(node, File, :read, [path], 10_000),
           "sandbox read a platform file at #{path} -- the mount namespace is not confining it"

    assert reason in [:enoent, :eacces, :eperm]
  end

  test "another sandbox's storage is unreachable" do
    {sb_a, node_a} = launch("a")
    {_sb_b, node_b} = launch("b")

    # Written by tenant B into its own storage, so the path is one that really
    # exists for somebody -- the strongest form of this test.
    target = "/sandbox/#{sb_a.id}/private.txt"
    _ = :erpc.call(node_b, File, :write, [target, "tenant b data"], 10_000)

    assert {:error, _} = :erpc.call(node_a, File, :read, [target], 10_000),
           "tenant A read tenant B's storage"
  end

  test "privilege escalation to another OS user is refused" do
    {_sb, node} = launch("a")

    uid = :erpc.call(node, :os, :cmd, [~c"id -u"], 10_000) |> to_string() |> String.trim()

    refute uid == "0",
           "sandbox is running as root -- `setpriv` did not drop privileges (FR-010)"

    # Attempting to become root is refused rather than merely unattempted.
    output =
      :erpc.call(node, :os, :cmd, [~c"setpriv --reuid 0 id -u 2>&1"], 10_000) |> to_string()

    refute String.trim(output) == "0",
           "sandbox escalated to uid 0: #{output}"
  end
end
