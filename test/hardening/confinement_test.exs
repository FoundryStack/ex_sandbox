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

  ## ⚠️ This test FAILS TODAY. That is the finding.

  It is written before the mechanism exists, per `012-FR-012a`, so that T107 is
  visible in a diff as the thing that turns it green. A profile written first
  and a test written to match it would be built from prediction — the exact
  shape `FR-012a` exists to prevent.

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

  # `:isolation` is excluded off Linux by `test_helper.exs`, and this needs a
  # real mount namespace, so it carries the tag with the rest of the containment
  # suite. Off Linux it does not pass — it does not run, which is the honest
  # answer ExUnit has no third outcome for.
  #
  #     docker compose -f docker/compose.isolation.yml run --rm --build isolation
  @moduletag :isolation

  alias ExSandbox.Hardening.Linux

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
    case Linux.confine_control_plane_process({"cat", [path]}, permit_path: p) do
      {:ok, %{cmd: cmd, args: args, env: env, cd: cd}} ->
        opts = [stderr_to_stdout: true, env: env] ++ if(cd, do: [cd: cd], else: [])
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

    # The inverted posture is the whole reason this is a second profile rather
    # than a reuse of the tenant one. A profile that confined paths *and*
    # stripped the credential would pass every assertion above and still be
    # useless: the CLI could not reach the model.
    test "keeps the environment it was handed, credential included", %{p: p} do
      sentinel = "sk-ant-sentinel-#{System.unique_integer([:positive])}"

      {:ok, %{cmd: cmd, args: args, env: env, cd: cd}} =
        Linux.confine_control_plane_process({"sh", ["-c", "printf %s \"$ANTHROPIC_API_KEY\""]},
          permit_path: p,
          env: [{"ANTHROPIC_API_KEY", sentinel}]
        )

      opts = [stderr_to_stdout: true, env: env] ++ if(cd, do: [cd: cd], else: [])
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
