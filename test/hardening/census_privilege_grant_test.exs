defmodule ExSandbox.Hardening.CensusPrivilegeGrantTest do
  @moduledoc """
  The isolation harness runs on a NARROWED privilege grant, not `privileged:
  true` (005 T060a10, 013-FR-006b, 013-FR-006f).

  ## The requirement this defends

  `013-FR-006b` says a deployment enabling only the runtime-level mechanism
  must run the execution plane **without** the elevated privileges nested
  containerisation needs. The census container ran `privileged: true` for most
  of this feature's life, so every green result it produced was evidence about
  a host granting far more than the requirement permits.

  T060a10 narrowed it to three specific grants, each measured against the thing
  that broke without it:

    * `systempaths=unconfined` — lets `bwrap` BUILD the mount confinement.
      Docker's masked `/proc` over-mounts, not a missing capability, are what
      the kernel refuses to let a new namespace mount over.
    * `CAP_SYS_PTRACE` — lets `verify_applied/1` READ `/proc/<pid>/ns/mnt` for
      a sandbox running as another uid after `setpriv`.
    * `CAP_SYS_ADMIN` — lets the acceptor JOIN the sandbox netns, i.e.
      `setns(2)` into another process's namespace. Still needed after the
      in-namespace helper process was deleted: the syscall is the same one,
      made from a thread of this BEAM rather than from `nsenter`.

  ## Why this is a test and not just a comment

  Two failure directions, and this file exists for the first:

  A future edit that restores `privileged: true` would make the census pass
  again while silently abandoning `013-FR-006b` — nothing else in the suite
  would notice, because a privileged host is a *superset* of what the
  narrowed one grants. Every check would stay green. That is precisely the
  regression shape this feature keeps finding, so it is asserted rather than
  documented.

  An edit that removes one of the three grants fails loudly instead: the
  census goes red, as it did twice while the three were being found. That
  direction needs no test.

  ⚠️ Asserts on the compose file rather than on a running container,
  deliberately. The property is "what this repo asks Docker for", which is a
  fact about the file and is checkable on any host — including macOS, where
  the container cannot run at all.
  """
  use ExUnit.Case, async: true

  @compose Path.join([__DIR__, "..", "..", "docker", "compose.isolation.yml"])

  # The services that boot systemd and launch sandboxes. `postgres` is a plain
  # unprivileged image and is deliberately not listed.
  @sandbox_services ["isolation", "pasta-reclaim"]

  setup_all do
    assert File.exists?(@compose), "expected the isolation compose file at #{@compose}"
    {:ok, source: File.read!(@compose)}
  end

  test "no service asks for blanket privilege", %{source: source} do
    # Matches the YAML key, not the word: every explanatory comment in that file
    # mentions `privileged: true` while describing its removal, and a bare
    # substring search would flag those forever.
    granting =
      source
      |> String.split("\n")
      |> Enum.reject(&String.starts_with?(String.trim(&1), "#"))
      |> Enum.filter(&(String.trim(&1) == "privileged: true"))

    assert granting == [], """
    docker/compose.isolation.yml asks for `privileged: true`.

    `013-FR-006b` requires the execution plane to run WITHOUT the privileges
    nested containerisation needs, and T060a10 established a narrower grant
    that passes the full census (473/7/0 isolation, 37/1/0 credentials):

        security_opt: [systempaths=unconfined]
        cap_add:      [SYS_PTRACE, SYS_ADMIN]

    If a change genuinely needs blanket privilege, the honest move is to record
    WHICH operation needs it -- as T060a10 did for all three grants above --
    rather than to restore the flag and let the census go green on a host that
    proves less than it appears to.
    """
  end

  test "each sandbox service keeps all three measured grants", %{source: source} do
    for service <- @sandbox_services do
      block = service_block(source, service)

      for {grant, buys} <- [
            {"systempaths=unconfined", "bwrap cannot BUILD the mount confinement"},
            {"SYS_PTRACE", "verify_applied/1 cannot READ the sandbox's ns/mnt"},
            {"SYS_ADMIN", "the acceptor cannot JOIN the sandbox netns via nsenter"}
          ] do
        assert String.contains?(block, grant), """
        service `#{service}` no longer grants `#{grant}`.

        Without it, #{buys}, and the census fails rather than passing silently.
        See the comments in docker/compose.isolation.yml for the measurement
        behind each of the three.
        """
      end
    end
  end

  # The lines belonging to one service: from its key to the next key at the same
  # indentation. Split textually because the point is to read what the file
  # asks for, including which service asks for it.
  defp service_block(source, service) do
    [_, rest] = String.split(source, "\n  #{service}:\n", parts: 2)

    rest
    |> String.split("\n")
    |> Enum.take_while(fn line ->
      line == "" or String.starts_with?(line, "   ") or String.starts_with?(line, "  #")
    end)
    |> Enum.join("\n")
  end
end
