defmodule ExSandbox.Hardening.ConfinementTest do
  @moduledoc """
  A confined process reaches the one path it was given and nothing beside it
  (015 T106, from research R16).

  ## What this is for, and why it is not the tenant profile

  `ExSandbox` confines tenant code. The gap R16 found is the mirror image: the
  delegated Claude Code CLI is a **control-plane** process that reads and writes
  tenant storage with ordinary filesystem calls, and nothing scopes which
  storage it may reach.

  The sandbox guarantee does not cover it, and the reason is directional.
  `confinement_args/2` binds a storage path into the **sandboxed process's**
  mount namespace (`hardening/linux.ex:316-345`), whose own comment says
  everything else "is simply not in its mount view". That constrains what the
  sandbox sees. A control-plane process is not in that namespace, so the same
  directory is an ordinary host path to it — and `storage_path/1` puts every
  sandbox's storage as a **sibling** under one root (`linux.ex:1101`), so
  reaching the next one along is a `..` away.

  The tenant profile cannot be reused for this, on both counts:

    * `@forbidden_env_fragments` strips `API_KEY`/`TOKEN`/`CREDENTIAL` by
      substring (`linux.ex:62-72`), so the CLI could not reach the model.
    * `--unshare-net` would deny the model endpoint outright.

  The posture needed is the **inverse** of a sandbox's: keep the credential,
  keep egress, restrict paths. Hence a second, thinner profile — T107.

  ## Phrased in paths, not tenants — deliberately

  P and Q are two arbitrary directories. There is no tenant here and there must
  not be: `012-FR-007` has this library treat ownership as an opaque reference
  it never interprets, and `012-FR-008` forbids it tenant lifecycle logic. Path
  confinement needs no host-application knowledge — it takes a path, not a
  tenant — which is what makes it a hardening-interface concern `012-FR-005a`
  keeps here. Deciding *which* path a run may reach is tenancy, and that stays
  in Axonn (`015` T106a).

  ## It failed before the mechanism existed. That was the finding.

  ⚠️ **UPDATE (T107): it passes now, and the sequence is the point.** It was
  written before the mechanism existed, per `012-FR-012a`, and MEASURED failing
  on `confine/2` being undefined (run `2026-08-19T15:28:53Z-85`). T107 is the
  diff that turned it green. A profile written first and a test written to match
  it would have been built from prediction — the shape `FR-012a` exists to
  prevent.

  ## ⚠️ It asserts on a DENIAL, never on a flag having been passed

  `012-FR-012a` requires a cap be established by breaching it. The reason is
  measured, not theoretical: `005` R9b found `taskpolicy -m` **silently lost
  across an intervening exec** — `taskpolicy -m 100 sandbox-exec … ./hog 300`
  allocates 300 MB under a nominal 100 MB cap and exits 0. That passes any
  check asking whether the limiting mechanism was invoked. So every assertion
  below runs a real read against a real path and requires it to fail.

  ⚠️ And each breach has a **control**: the same read against P must succeed. A
  confinement that denies everything — a broken profile, a missing binary, a
  typo'd path — satisfies "Q was refused" perfectly. Without the control, the
  most complete failure is indistinguishable from the strongest pass.
  """
  use ExUnit.Case, async: false

  # ⚠️ NOT tagged `:isolation`, and the reason is a measurement (R30).
  #
  # It was, when written: `:isolation` is excluded off Linux by
  # `test_helper.exs`, and the assumption was that this needed a mount namespace
  # like the tenant profile does. R30 then measured `sandbox-exec` enforcing the
  # same boundary on darwin — surviving three nested execs, not widenable by
  # re-invoking itself, not defeated by a symlink out of the subtree.
  #
  # So this runs on **both** platforms, and that is the point: the boundary this
  # asserts is the one thing in the containment suite a developer's own machine
  # can actually check. `confine/2` returns `{:cannot_enforce, …}` on a host that
  # cannot build the profile, and the tests below fail loudly on it rather than
  # skipping — a host where the CLI is unconfined must not read as green.

  alias ExSandbox.Hardening.Confinement

  setup do
    root = Path.join(System.tmp_dir!(), "confinement-#{System.unique_integer([:positive])}")
    p = Path.join(root, "p")
    q = Path.join(root, "q")
    File.mkdir_p!(p)
    File.mkdir_p!(q)

    # Sibling directories under a common root: the layout `storage_path/1`
    # produces, reconstructed without borrowing its tenant vocabulary.
    File.write!(Path.join(p, "own.txt"), "reachable")
    File.write!(Path.join(q, "secret.txt"), "must-not-be-readable")
    File.write!(Path.join(root, "above.txt"), "must-not-be-readable")

    on_exit(fn -> File.rm_rf(root) end)

    {:ok, root: root, p: p, q: q}
  end

  # Runs `cat <path>` under the confinement profile that binds `p`, and reports
  # what actually happened rather than what was configured.
  defp read_under_confinement(p, path) do
    case Confinement.confine({"cat", [path]}, permit_path: p) do
      {:ok, %{cmd: cmd, args: args, env: env, cd: cd}} ->
        opts = [stderr_to_stdout: true, env: env, cd: cd]
        {out, status} = System.cmd(cmd, args, opts)
        {status, out}

      {:error, reason} ->
        flunk("""
        The confinement profile could not be built: #{inspect(reason)}

        This is not a pass. A profile that refuses to build denies every path,
        including P, so it satisfies the breach assertions for the wrong reason.
        """)
    end
  end

  # The general form of `read_under_confinement/2`: runs any command under the
  # profile that binds `p` and reports what happened.
  defp run_under_confinement(p, command, args) do
    case Confinement.confine({command, args}, permit_path: p) do
      {:ok, %{cmd: cmd, args: wrapped, env: env, cd: cd}} ->
        opts = [stderr_to_stdout: true, env: env, cd: cd]
        {out, status} = System.cmd(cmd, wrapped, opts)
        {status, out}

      {:error, reason} ->
        flunk("""
        The confinement profile could not be built: #{inspect(reason)}

        This is not a pass, for the reason given on `read_under_confinement/2`.
        """)
    end
  end

  # A freshly built Mach-O/ELF, which is what makes it a valid stand-in for a
  # user-installed CLI: it carries its own signature rather than a system
  # binary's, so it runs unsandboxed and any refusal under the profile is the
  # profile's doing. Exit codes are the whole result -- 7 ran, 8 read, 9 denied
  # -- so nothing about this probe depends on parsing its output.
  @probe_source """
  #include <stdio.h>
  int main(int argc, char **argv) {
    if (argc > 1) { FILE *f = fopen(argv[1], "r"); if (!f) return 9; fclose(f); return 8; }
    return 7;
  }
  """

  defp compile_probe(dir) do
    case Enum.find(["cc", "clang", "gcc"], &System.find_executable/1) do
      nil ->
        {:error, "no C compiler on PATH (looked for cc, clang, gcc)"}

      compiler ->
        source = Path.join(dir, "probe.c")
        probe = Path.join(dir, "probe")
        File.write!(source, @probe_source)

        case System.cmd(compiler, ["-o", probe, source], stderr_to_stdout: true) do
          {_out, 0} -> {:ok, probe}
          {out, status} -> {:error, "#{compiler} exited #{status}: #{out}"}
        end
    end
  end

  describe "the working directory the spec hands back" do
    # ⚠️ These pin a CONTRACT, and the contract exists because leaving it
    # implicit produced a failure that read as a flake. A child started outside
    # its own boundary resolves relative paths outside it, and on darwin cannot
    # read its own working directory -- but only when the VM reached that
    # directory by `chdir` rather than by starting there, which is the
    # difference between an umbrella `mix test` and the same suite run from the
    # app's own directory. See the moduledoc note on `confine/2`.

    test "defaults to the permitted path, resolved", %{p: p} do
      {:ok, spec} = Confinement.confine({"pwd", []}, permit_path: p)

      assert spec.cd == physical(p),
             """
             The spec left the caller to choose a working directory, and the
             only directory the profile fully grants is P.
             """
    end

    test "is left alone when the caller names one", %{p: p, q: q} do
      {:ok, spec} = Confinement.confine({"pwd", []}, permit_path: p, cd: q)

      assert spec.cd == q
    end

    test "starts the child inside the boundary, able to read where it is", %{p: p} do
      {status, out} = run_under_confinement(p, "pwd", ["-P"])

      # Equality rather than a `=~`, so a `getcwd` diagnostic on stderr fails
      # this: `run_under_confinement/3` merges stderr into `out`.
      assert {0, physical(p)} == {status, String.trim(out)}
    end
  end

  # The path after symlinks, which on darwin is what `System.tmp_dir!()` is not:
  # `/var` is a symlink to `/private/var`, and the kernel evaluates both the
  # profile and `getcwd` against the resolved spelling.
  defp physical(dir) do
    {out, 0} = System.cmd("/bin/pwd", ["-P"], cd: dir)
    String.trim(out)
  end

  describe "a confined process and the path it was given" do
    # ⚠️ THE CONTROL, and it runs first on purpose. If this fails, every
    # assertion below is meaningless -- they would be measuring a broken
    # profile rather than a boundary.
    test "reads the path bound to it", %{p: p} do
      assert {0, out} = read_under_confinement(p, Path.join(p, "own.txt"))
      assert out =~ "reachable"
    end

    test "is refused a sibling path it was not given", %{p: p, q: q} do
      {status, out} = read_under_confinement(p, Path.join(q, "secret.txt"))

      refute status == 0,
             "read of a sibling path succeeded: #{out}"

      refute out =~ "must-not-be-readable",
             "the sibling's CONTENTS came back even though the exit status was non-zero"
    end

    test "is refused a `..` traversal above the path it was given", %{root: root, p: p} do
      # Spelled as a traversal rather than as an absolute path, because these
      # are two different failures: an absolute path is denied by the bind
      # simply not covering it, while `..` from *inside* the bind asks whether
      # the boundary holds at its own edge.
      traversal = Path.join(p, "../above.txt")
      {status, out} = read_under_confinement(p, traversal)

      refute status == 0, "`..` traversal above the bound path succeeded: #{out}"
      refute out =~ "must-not-be-readable", "the parent's CONTENTS came back"

      # And the same file by its absolute name, which must also be refused.
      {abs_status, abs_out} = read_under_confinement(p, Path.join(root, "above.txt"))
      refute abs_status == 0, "absolute read above the bound path succeeded: #{abs_out}"
    end

    # ⚠️ THE CASE THAT HAD NO TEST, and the whole reason D14a was opened.
    #
    # The four tests above read and refuse paths; none of them EXECUTES
    # anything, and `delegated_launch_test.exs` asserts argv shape rather than
    # execution. So the property the delegated CLI actually depends on -- that
    # a binary living under a path this profile DENIES can still be run -- was
    # asserted nowhere. The 24/24 passing launches offered as evidence for it
    # ran against a hardlink placed INSIDE the permit path, so the denied-path
    # case appears never to have been exercised on its own.
    #
    # `q` is that denied path: a sibling of the permitted `p`, and the same
    # directory whose `secret.txt` the test above proves is unreadable.
    #
    # ⚠️ The probe is COMPILED, never a `cp` of a system binary. MEASURED
    # (D14a): a copy of `/bin/echo` is SIGKILLed with 137 *unsandboxed too*,
    # because its platform-binary signature is invalid off the signed system
    # volume. That is a confound, not a result, and it already burned one
    # investigation -- a test built on it would "prove" confinement blocks exec
    # when nothing of the sort happened.
    test "executes a binary from a path it was DENIED, and reads no further", ctx do
      %{p: p, q: q} = ctx

      case compile_probe(q) do
        {:error, reason} ->
          flunk("""
          The exec probe could not be built: #{reason}

          This is not a pass. This host cannot answer whether a confined child
          can execute a binary under a denied path, and a suite that reads green
          without having asked is the failure mode this file exists to refuse.
          Install a C compiler, or exclude this test deliberately and say so.
          """)

        {:ok, probe} ->
          # 7 is the probe's own no-argument exit code, so a 7 can only be
          # produced by the probe having actually run. A confinement failure
          # yields the confiner's error status instead -- MEASURED on linux,
          # `bwrap: execvp …: No such file or directory`, exit 1.
          # ⚠️ READ THE ERRNO BEFORE READING THE CODE. Both failures exit 1 and
          # the message below used to name only one of them, which cost an
          # investigation: `execvp: Permission denied` (EACCES) is the HOST
          # refusing, not the profile. `System.tmp_dir!()` above is `/tmp`, and
          # Docker mounts a bare `--tmpfs` `noexec` -- so inside a container
          # this test failed while pointing at `command_bind/2`, where nothing
          # was wrong. `docker/compose.isolation.yml` mounts `/tmp:exec` for
          # exactly this reason.
          assert {7, _} = run_under_confinement(p, probe, []),
                 """
                 A confined child could not execute a binary under a denied path.

                 `execvp ...: Permission denied` (EACCES) means the FILESYSTEM
                 refused, not the profile -- almost always a `noexec` mount
                 under #{System.tmp_dir!()}. Check it before changing any
                 confinement code:

                     grep " #{System.tmp_dir!()} " /proc/mounts

                 `execvp ...: No such file or directory` (ENOENT) is the profile:
                 on linux `--ro-bind <resolved> <resolved>` missing or naming the
                 symlink rather than its target; on darwin it means something now
                 governs `process-exec*` that did not before.
                 """

          # ⚠️ The runtime self-read, which is the ONLY thing the grant buys on
          # darwin -- MEASURED, exec already succeeded without it. A 183 MB
          # single-file executable may read its own file for an embedded payload
          # or an update check, and `028/spec.md:248-252` records this CLI's
          # failure signature for a denied path as exit 0, zero bytes, no
          # complaint. This is what keeps that from being the outcome.
          assert {8, _} = run_under_confinement(p, probe, [probe]),
                 "the executed binary could not read its own file"

          # And the grant is a grant of ONE FILE. If this returns 8, the profile
          # widened to the directory and every sibling of the CLI -- every
          # retained old version, every other tool the operator installed --
          # came back with it.
          assert {9, _} = run_under_confinement(p, probe, [Path.join(q, "secret.txt")]),
                 """
                 The executable grant widened to its directory: a sibling under
                 the DENIED path became readable to the confined child.

                 This is the `(subpath …)`-instead-of-`(literal …)` mistake, and
                 on the real layout it re-permits every retained CLI version.
                 """
      end
    end

    # ⚠️ MEASURED before this was fixed: `echo x > /dev/null` inside the profile
    # failed with `Operation not permitted`. `/dev` was granted `file-read*` and
    # nothing else, while the comment on `runtime_read_paths/0` claimed it was
    # there so a process "denied `/dev/null` and `/dev/urandom`" would not die.
    # Half of that was implemented.
    #
    # Asserted as behaviour rather than by reading the profile text, because the
    # profile said the right thing throughout.
    test "can write the two device sinks a process dies without", %{p: p} do
      {status, out} =
        run_under_confinement(p, "sh", [
          "-c",
          "echo x > /dev/null && head -c 4 /dev/urandom > /dev/null && echo BOTH_OK"
        ])

      assert status == 0,
             "a confined child could not write /dev/null or read /dev/urandom: #{out}"

      assert out =~ "BOTH_OK"
    end

    # The inverted posture is the whole reason this is a second profile rather
    # than a reuse of the tenant one. A profile that confined paths *and*
    # stripped the credential would pass every assertion above and still be
    # useless: the CLI could not reach the model.
    test "keeps the environment it was handed, credential included", %{p: p} do
      sentinel = "sk-ant-sentinel-#{System.unique_integer([:positive])}"

      {:ok, %{cmd: cmd, args: args, env: env, cd: cd}} =
        Confinement.confine({"sh", ["-c", "printf %s \"$ANTHROPIC_API_KEY\""]},
          permit_path: p,
          env: [{"ANTHROPIC_API_KEY", sentinel}]
        )

      opts = [stderr_to_stdout: true, env: env, cd: cd]
      {out, status} = System.cmd(cmd, args, opts)

      assert status == 0

      assert out =~ sentinel,
             """
             The credential did not survive the profile.

             This profile is for a CONTROL-PLANE process and must NOT strip it
             (R16). ⚠️ The fix is NOT to weaken `@forbidden_env_fragments` --
             R14 requires "a deliberate separate channel, never a weakening of
             that list", and that list is what keeps credentials out of every
             tenant sandbox (`015-FR-005`).
             """
    end
  end
end
