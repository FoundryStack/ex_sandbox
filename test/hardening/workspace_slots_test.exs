defmodule ExSandbox.Hardening.WorkspaceSlotsTest do
  @moduledoc """
  A workspace's slots stay the platform's, the way its root does.

  ## The bug this exists to prevent

  OBSERVED 2026-09-22 on production: the hand-off chowned every top-level
  entry but `.git` to the sandbox, `.slots` included, so each slot worktree
  and its `.git` file became the tenant's. The platform's next
  `git checkout` in a slot refused with "detected dubious ownership", and
  every publish to that environment rolled back.

  ⚠️ The ownership assertions mean something only as root, which is how the
  platform runs inside its user namespace. Unprivileged, every `chown` to
  another uid is refused and tolerated, and these tests check modes and
  symlink handling alone. Run them as root in a Linux container:

      docker run --rm -v "$PWD":/src -w /src elixir:1.19 \\
        sh -c 'mix local.hex --force && mix deps.get && mix test test/hardening/workspace_slots_test.exs'
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Hardening.Linux

  @moduletag :tmp_dir

  setup do
    previous = Application.get_env(:ex_sandbox, :beam, [])
    Application.put_env(:ex_sandbox, :beam, Keyword.put(previous, :workspace_slots, ".slots"))
    on_exit(fn -> Application.put_env(:ex_sandbox, :beam, previous) end)
  end

  defp sandbox(workspace_path) do
    %ExSandbox.Sandbox{
      id: "slots-#{System.unique_integer([:positive])}",
      owner_ref: "owner-1",
      template_ref: "tpl",
      memory_limit_mb: 256,
      cpu_limit: 500,
      disk_quota_mb: 1024,
      workspace_path: workspace_path
    }
  end

  defp root?, do: File.stat!("/").uid == 0 and System.cmd("id", ["-u"]) == {"0\n", 0}

  defp mode(path), do: Bitwise.band(File.lstat!(path).mode, 0o7777)

  defp workspace(dir) do
    File.write!(Path.join(dir, "mix.exs"), "")
    File.mkdir_p!(Path.join(dir, ".git"))

    for slot <- ["a", "b"] do
      File.mkdir_p!(Path.join([dir, ".slots", slot, "lib"]))

      File.write!(
        Path.join([dir, ".slots", slot, ".git"]),
        "gitdir: #{dir}/.git/worktrees/#{slot}\n"
      )

      File.write!(Path.join([dir, ".slots", slot, "mix.exs"]), "")
    end

    File.write!(Path.join([dir, ".slots", "serving"]), "a\n")
    dir
  end

  test "keeps each slot and its .git the platform's, and hands over what is inside", %{
    tmp_dir: dir
  } do
    %{uid: platform} = File.stat!(workspace(dir))
    sandbox = sandbox(dir)

    assert :ok = Linux.prepare_workspace(sandbox)

    assert mode(dir) == 0o770
    assert mode(Path.join(dir, ".slots")) == 0o750
    assert mode(Path.join([dir, ".slots", "a"])) == 0o770

    if root?() do
      tenant = File.stat!(Path.join(dir, "mix.exs")).uid
      refute tenant == platform, "the root's own files were not handed over"

      for path <- [".slots", ".slots/a", ".slots/b", ".slots/a/.git", ".slots/serving", ".git"] do
        assert File.lstat!(Path.join(dir, path)).uid == platform,
               "#{path} was given to the sandbox"
      end

      for path <- [".slots/a/lib", ".slots/a/mix.exs", ".slots/b/lib"] do
        assert File.lstat!(Path.join(dir, path)).uid == tenant,
               "#{path} was kept from the sandbox"
      end

      assert File.stat!(Path.join(dir, ".slots/a")).gid == tenant
    end
  end

  test "repairs a slot a previous hand-off gave away, but not its .git", %{tmp_dir: dir} do
    %{uid: platform} = File.stat!(workspace(dir))

    if root?() do
      {_, 0} = System.cmd("chown", ["-R", "4242:4242", Path.join(dir, ".slots")])
    end

    assert :ok = Linux.prepare_workspace(sandbox(dir))

    if root?() do
      assert File.lstat!(Path.join(dir, ".slots/a")).uid == platform

      # ⚠️ Re-owning it would make the tenant's gitdir pointer the platform's.
      assert File.lstat!(Path.join(dir, ".slots/a/.git")).uid == 4242
    end
  end

  test "does not follow a slot that is a symlink", %{tmp_dir: dir} do
    workspace(dir)

    outside =
      Path.join(dir, "..")
      |> Path.expand()
      |> Path.join("outside-#{System.unique_integer([:positive])}")

    File.mkdir_p!(Path.join(outside, "lib"))
    File.chmod!(outside, 0o700)
    on_exit(fn -> File.rm_rf(outside) end)

    File.rm_rf!(Path.join([dir, ".slots", "b"]))
    File.ln_s!(outside, Path.join([dir, ".slots", "b"]))
    %{uid: owner} = File.stat!(Path.join(outside, "lib"))

    assert :ok = Linux.prepare_workspace(sandbox(dir))

    assert mode(outside) == 0o700
    assert File.stat!(Path.join(outside, "lib")).uid == owner
  end

  test "hands over nothing below a slots directory that is a symlink", %{tmp_dir: dir} do
    File.write!(Path.join(dir, "mix.exs"), "")
    outside = Path.expand(Path.join(dir, "../slots-#{System.unique_integer([:positive])}"))
    File.mkdir_p!(Path.join(outside, "a"))
    File.chmod!(Path.join(outside, "a"), 0o700)
    on_exit(fn -> File.rm_rf(outside) end)
    File.ln_s!(outside, Path.join(dir, ".slots"))

    assert :ok = Linux.prepare_workspace(sandbox(dir))

    assert mode(Path.join(outside, "a")) == 0o700
  end
end
