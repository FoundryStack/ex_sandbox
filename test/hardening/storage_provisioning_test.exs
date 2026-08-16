defmodule ExSandbox.Hardening.StorageProvisioningTest do
  @moduledoc """
  The sandbox's writable storage must exist, and be owned by the uid the
  sandbox drops to, before the launch binds it (005 T036f, FR-009, FR-010).

  ## The bug this exists to prevent

  `confinement_args/2` bound `storage_path(sandbox)` read-write, and nothing
  anywhere created that directory. `bwrap` refuses a bind whose source is
  missing:

      bwrap: Can't find source path /var/lib/axonn/sandboxes/env-3

  so every launch exited 1. Creating it is not incidental setup — an unwritable
  storage root means the sandbox has nowhere to put anything, which is the
  private-storage half of `FR-010`.

  ## Ownership is part of the requirement, not a detail

  The directory must be owned by the sandbox's **numeric uid**. Created as root
  with default permissions, the sandbox drops privilege and then cannot write to
  its own storage — the launch succeeds and every write fails, which is worse
  than failing at launch because it looks like a working sandbox.

  Mode is `0o700`: the owning uid only. `0o755` would let every other sandbox on
  the gateway read this one's storage, defeating the isolation the per-sandbox
  uid exists to create.
  """
  # ⚠️ `async: false`. This test mutates `:ex_sandbox, :beam`'s `:storage_root`,
  # which is global application config -- and `capability_build_parity_test.exs`
  # reads it concurrently to check that the storage bind is present. Run async,
  # the two race: the parity test occasionally composed a command against this
  # test's temporary root and reported `disk_quota` unconstructed, failing about
  # one run in three.
  use ExUnit.Case, async: false

  alias ExSandbox.Hardening.Linux

  setup do
    root =
      Path.join(
        System.tmp_dir!(),
        "ex_sandbox_storage_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(root)

    previous = Application.get_env(:ex_sandbox, :beam, [])
    Application.put_env(:ex_sandbox, :beam, Keyword.put(previous, :storage_root, root))

    on_exit(fn ->
      Application.put_env(:ex_sandbox, :beam, previous)
      File.rm_rf(root)
    end)

    %{root: root}
  end

  defp sandbox do
    %ExSandbox.Sandbox{
      id: "store-#{System.unique_integer([:positive])}",
      owner_ref: "owner-1",
      template_ref: "tpl",
      memory_limit_mb: 256,
      cpu_limit: 500,
      disk_quota_mb: 1024
    }
  end

  describe "prepare_storage/1" do
    test "creates the directory the launch binds", %{root: root} do
      sb = sandbox()

      assert :ok = Linux.prepare_storage(sb)
      assert File.dir?(Path.join(root, sb.id))
    end

    test "is idempotent, so a retried provision does not fail on existing storage" do
      sb = sandbox()

      assert :ok = Linux.prepare_storage(sb)
      assert :ok = Linux.prepare_storage(sb)
    end

    test "restricts the directory to its owner", %{root: root} do
      sb = sandbox()
      :ok = Linux.prepare_storage(sb)

      %File.Stat{mode: mode} = File.stat!(Path.join(root, sb.id))

      assert Bitwise.band(mode, 0o077) == 0,
             """
             Storage is group/world accessible (mode #{Integer.to_string(Bitwise.band(mode, 0o777), 8)}).

             Every sandbox on this gateway runs as a different uid but shares this
             root, so anything other than owner-only lets one tenant read
             another's storage.
             """
    end

    test "gives each sandbox its own directory" do
      a = sandbox()
      b = sandbox()

      :ok = Linux.prepare_storage(a)
      :ok = Linux.prepare_storage(b)

      refute a.id == b.id
    end
  end
end
