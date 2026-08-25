defmodule ExSandbox.Hardening.ConfinementExtraSubpathsTest do
  @moduledoc """
  `:permit_extra_subpaths` grants exactly the directories it names, and nothing
  beside them (028 T033a).

  ## Why this exists at all

  `028` Phase 7: the owner ran the product in a browser and the run died with
  `EPERM: operation not permitted, open '/tmp/claude-501'`. The delegated CLI
  writes to a scratch directory under `/tmp` whose path is a **string literal**
  in the shipped binary — `TMPDIR` does not move it — and `confine/2`'s profile
  granted no `/tmp` at all. `FR-023`'s rule is *relocate, never widen*, and
  there is nothing here to relocate, so the owner took the widening with its
  cost stated (decision Q20).

  This file is the reproduction, widened into a test. It failed before the
  option existed, on `confine/2` ignoring an option it did not know.

  ## ⚠️ It asserts on `sandbox-exec`'s behaviour, never on the profile string

  A profile is a string until the kernel reads it, and the two disagree in both
  directions. A grant written against an unresolved symlink spelling appears in
  the string and matches nothing; R30 measured the opposite failure, a profile
  naming too *little* killing the child with **134** before any path was
  reached, so that every breach assertion passed while the boundary did not
  exist. So every case below runs a real process against a real path and reads
  what the operating system did.

  The string is asserted on in exactly one place — the negative direction, where
  absence from the profile is conclusive on its own — and that assertion lives
  next to a behavioural one, never alone.
  """
  use ExUnit.Case, async: false

  # Not tagged `:isolation`, for the reason `ConfinementTest` records: R30
  # measured `sandbox-exec` enforcing this boundary on darwin, so this runs on
  # both platforms and fails loudly on a host that cannot build the profile.

  alias ExSandbox.Hardening.Confinement

  setup do
    root = Path.join(System.tmp_dir!(), "confinement-extra-#{System.unique_integer([:positive])}")
    p = Path.join(root, "p")
    extra = Path.join(root, "extra")
    denied = Path.join(root, "denied")

    Enum.each([p, extra, denied], &File.mkdir_p!/1)
    File.write!(Path.join(p, "own.txt"), "reachable")
    File.write!(Path.join(extra, "scratch.txt"), "granted-by-the-caller")
    File.write!(Path.join(denied, "secret.txt"), "must-not-be-readable")

    on_exit(fn -> File.rm_rf(root) end)

    {:ok, root: root, p: p, extra: extra, denied: denied}
  end

  # Runs `command` confined to `p`, with whatever extra grants the case is
  # about, and reports what happened rather than what was configured.
  defp run(p, command, args, opts \\ []) do
    case Confinement.confine({command, args}, [permit_path: p] ++ opts) do
      {:ok, %{cmd: cmd, args: wrapped, env: env, cd: cd}} ->
        System.cmd(
          cmd,
          wrapped,
          stderr_to_stdout: true,
          env: env,
          cd: cd
        )

      {:error, reason} ->
        flunk("""
        The confinement profile could not be built: #{inspect(reason)}

        This is not a pass. A profile that refuses to build denies every path,
        including P, so it satisfies every breach assertion for the wrong
        reason.
        """)
    end
  end

  describe "the control, which must run first" do
    test "the permitted path is readable with an extra grant present", %{p: p, extra: extra} do
      {out, status} =
        run(p, "cat", [Path.join(p, "own.txt")], permit_extra_subpaths: [extra])

      assert {0, "reachable"} == {status, out},
             """
             P itself became unreadable once an extra grant was added. Every
             denial below would then pass for a reason that has nothing to do
             with the boundary — R30's 134, or a profile that no longer parses.
             """
    end
  end

  describe "the grant" do
    test "a path outside P is denied without it", %{p: p, extra: extra} do
      {out, status} = run(p, "cat", [Path.join(extra, "scratch.txt")])

      assert status != 0, "the extra path was readable with no grant asked for"
      assert out =~ "Operation not permitted" or out =~ "No such file"
    end

    test "the same path is readable with it", %{p: p, extra: extra} do
      {out, status} =
        run(p, "cat", [Path.join(extra, "scratch.txt")], permit_extra_subpaths: [extra])

      assert {0, "granted-by-the-caller"} == {status, out}
    end

    test "the same path is writable with it", %{p: p, extra: extra} do
      target = Path.join(extra, "written-by-the-child.txt")

      {out, status} =
        run(p, "sh", ["-c", "echo wrote > #{target}"], permit_extra_subpaths: [extra])

      assert {0, ""} == {status, out}
      assert File.read!(target) == "wrote\n"
    end
  end

  describe "and it does not leak sideways" do
    test "a sibling of the granted path stays denied", %{p: p, extra: extra, denied: denied} do
      {out, status} =
        run(p, "cat", [Path.join(denied, "secret.txt")], permit_extra_subpaths: [extra])

      assert status != 0, """
      Granting one directory re-permitted its sibling. That is the shape this
      module exists to deny — deny-by-default did not survive the grant.
      """

      assert out =~ "Operation not permitted"
    end

    test "the parent of the granted path is not itself writable", %{
      p: p,
      root: root,
      extra: extra
    } do
      target = Path.join(root, "escaped.txt")

      {_out, status} =
        run(p, "sh", ["-c", "echo escaped > #{target}"], permit_extra_subpaths: [extra])

      assert status != 0
      refute File.exists?(target)
    end

    test "`(subpath …)` reaches nested directories, which is what the caller asked for", %{
      p: p,
      extra: extra
    } do
      nested = Path.join([extra, "a", "b"])
      File.mkdir_p!(nested)
      File.write!(Path.join(nested, "deep.txt"), "nested")

      {out, status} =
        run(p, "cat", [Path.join(nested, "deep.txt")], permit_extra_subpaths: [extra])

      assert {0, "nested"} == {status, out}
    end
  end

  describe "the default" do
    test "no grant appears in the profile when the option is absent", %{p: p, extra: extra} do
      {:ok, %{args: args}} = Confinement.confine({"cat", []}, permit_path: p)

      refute Enum.any?(args, &String.contains?(&1, extra)),
             "a grant appeared for a path no caller named"
    end

    test "an empty list is the same as no option at all", %{p: p} do
      {:ok, %{args: with_empty}} =
        Confinement.confine({"cat", []}, permit_path: p, permit_extra_subpaths: [])

      {:ok, %{args: without}} = Confinement.confine({"cat", []}, permit_path: p)

      assert with_empty == without
    end
  end
end
