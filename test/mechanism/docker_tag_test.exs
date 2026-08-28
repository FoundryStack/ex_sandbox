defmodule ExSandbox.Mechanism.DockerTagTest do
  @moduledoc """
  The `:docker` tag makes the container-backed tests **absent** on a host with
  no daemon rather than green.

  ## Why an exclusion needs its own test

  `ExSandbox.Hardening.DarwinTagTest` makes this argument in full and it is the
  same argument here, so only the part that differs is restated: those tests are
  excluded on a host that lacks a *kernel facility*, which is stable for the
  life of the machine. This group is excluded on a host where a *daemon was not
  answering*, which is a state an operator can create by accident -- a stopped
  Docker Desktop, a `DOCKER_HOST` left pointing at a socket from an earlier
  experiment -- and then read the resulting "0 failures" as a pass.

  The two failure modes are the ones the Darwin canary names: the exclusion is
  dropped and these tests run where they cannot pass, or the exclusion works and
  no module carries the tag so nothing is excluded. Both are covered the only
  way an exclusion can be: by a test that must **fail** if it ever runs on the
  wrong host.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Test.DockerDaemon

  describe "the :docker exclusion" do
    test "is configured exactly when no daemon answered" do
      excluded? = :docker in ExUnit.configuration()[:exclude]

      assert excluded? == not DockerDaemon.reachable?(),
             """
             `:docker` is #{if excluded?, do: "excluded", else: "included"} on a host \
             where the daemon probe says #{inspect(DockerDaemon.probe())}.

             With no daemon it must be excluded: every test in the group shells out to \
             `docker`, and running them there reports the failure of a confinement that \
             was never this host's to give.

             With a daemon it must NOT be excluded, which is the half that goes wrong \
             silently -- an over-broad exclusion turns the whole Docker mechanism into a \
             green run on the one host that could have verified it.
             """
    end

    @tag :docker
    test "canary: a tagged test never executes without a daemon" do
      # ⚠️ This test exists to FAIL. On a host with no daemon the exclusion must
      # keep it from running at all; if it runs there, the assertion reports
      # that in the only way ExUnit can hear.
      #
      # Written as `assert true` it would pass everywhere and establish nothing,
      # which is the shape of check this tag exists to remove.
      assert DockerDaemon.reachable?(),
             """
             A `:docker` test executed on a host with no container runtime: \
             #{DockerDaemon.unreachable_reason()}.

             The exclusion in `test/test_helper.exs` is not reaching this module. Every \
             other `:docker` test is now running here too, and each will fail against a \
             daemon that is not there -- read those failures as this defect, not as a \
             broken mechanism.
             """
    end
  end
end
