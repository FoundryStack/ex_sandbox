defmodule ExSandbox.Hardening.GrantedEnvSecretTest do
  @moduledoc """
  A secret handed to a sandbox as granted environment is refused by name, and
  what the refusal does **not** cover is measured rather than assumed
  (015 T054, `015-FR-005`, `013-FR-011d`).

  ## Why this lives in `ex_sandbox` and not beside the rest of T054

  T054's other searches are in
  `apps/axonn/test/axonn/model_access/credential_leak_test.exs`, and these
  three started there. They moved because `library_boundary_test.exs` caught
  the reference: `ExSandbox.Hardening.Linux` is **private** to this library --
  only the `ExSandbox.Hardening` behaviour and `ExSandbox.Hardening.Confinement`
  are public per `contracts/boundary.md`, and the public behaviour exposes no
  composition function.

  ⚠️ The fix was to move the tests, not to widen the list. The Axonn-side file
  cites that very boundary in a comment and then crossed it, which is the kind
  of drift the boundary test exists to catch. Adding `Linux` to the public list
  to keep a test compiling would convert a private implementation detail into a
  compatibility promise for the sake of test convenience -- `012-FR-007`'s
  concern exactly.

  Phrased here in **paths and environment pairs**, with no tenant concept, per
  `012`'s split: the mechanism is `ex_sandbox`'s, the tenant-shaped assertion
  stays in Axonn.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Hardening.Linux

  # ⚠️ Random per run, never a literal. A hardcoded sentinel eventually lands in
  # a fixture or a snapshot, and from then on every search finds it in the
  # repository rather than in the surface under test.
  defp sentinel do
    "sk-ant-sentinel-" <> Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
  end

  defp sandbox do
    %ExSandbox.Sandbox{
      id: "sb-#{System.unique_integer([:positive])}",
      owner_ref: "owner-#{System.unique_integer([:positive])}",
      template_ref: "tpl",
      memory_limit_mb: 256,
      cpu_limit: 500,
      disk_quota_mb: 1024
    }
  end

  defp render(term), do: inspect(term, limit: :infinity, printable_limit: :infinity)

  setup do
    %{secret: sentinel()}
  end

  test "a composed launch command carries no secret when none was granted", %{secret: secret} do
    # ⚠️ `compose_for_inspection/2` rather than a launch: it runs on any host,
    # with no availability gate, and returns the full argv a sandbox would start
    # with. That argv IS sandbox-reachable state -- the confined process can
    # read its own `/proc/self/cmdline`.
    {:ok, {prog, args}} = Linux.compose_for_inspection(sandbox(), [])

    refute render([prog | args]) =~ secret
  end

  test "🔒 granting a credential-named variable is REFUSED, not carried", %{secret: secret} do
    # ⚠️ Asserted through the refusal rather than by searching the composed
    # argv, because there is no argv to search -- composition never happens. A
    # test that only searched output would report a pass for the wrong reason.
    assert {:error, {:forbidden_env, keys}} =
             Linux.compose_for_inspection(sandbox(), [{"ANTHROPIC_API_KEY", secret}])

    assert "ANTHROPIC_API_KEY" in keys, """
    `@forbidden_env_fragments` did not reject `ANTHROPIC_API_KEY`.

    ⚠️ Per `015` R14 this list MUST NOT be weakened to admit a credential. A
    delegated CLI that needs one takes a separate control-plane channel
    (`Axonn.ModelAccess.Backend.DelegatedCli.invocation_env/1`) -- never a hole
    in this list, because a hole here eventually reaches a sandbox.
    """
  end

  test "⚠️ the refusal matches the NAME, so a misnamed grant IS carried -- measured", %{
    secret: secret
  } do
    # A measured limit of the mechanism, asserted so it stays true rather than
    # becoming a surprise. `reject_forbidden_env/1` (`linux.ex:502-513`) matches
    # the variable NAME against `@forbidden_env_fragments`; it never examines
    # the value. A credential granted under a name resembling nothing on that
    # list is composed into the argv unopposed.
    #
    # ⚠️ This is NOT an argument for value-scanning. Guessing whether a string
    # is a secret is a heuristic that fails open, and this list's value is that
    # it is exact and cannot drift. The real control is that nothing grants
    # sandbox env from a credential at all -- `015-FR-005` holds because the two
    # channels are separate, and this list is a backstop against a mistake, not
    # the boundary itself.
    #
    # Recorded because a reader who believes the list IS the boundary would
    # conclude that renaming a variable is a safe workaround.
    assert {:ok, {_prog, args}} =
             Linux.compose_for_inspection(sandbox(), [{"HARMLESS", secret}])

    assert render(args) =~ secret, """
    a credential granted under a non-matching NAME was not carried into the
    argv -- which would mean the refusal now inspects values.

    If that is a deliberate change, rewrite this test rather than deleting it:
    the property it records (name-matching, not value-matching) is what makes
    the separate control-plane channel necessary.
    """
  end
end
