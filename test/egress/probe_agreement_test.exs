defmodule ExSandbox.Egress.ProbeAgreementTest do
  @moduledoc """
  That the two probes for `:network_restriction` answer the same question
  (005 T060a5c).

  ## Two implementations, one capability name

  `:network_restriction` is answered independently by
  `ExSandbox.Hardening.Linux.probe_network_policy/0` and by
  `ExSandbox.Capability.check/1`. They were written at different times for
  different callers and drifted: hardening requires `bwrap` **and**
  `--unshare-net` **and** `pasta` **and** `/dev/net/tun` -- the policed path --
  while the capability vocabulary required only `bwrap` and `--unshare-net`.

  ⚠️ **Why the drift is reachable rather than cosmetic.**
  `Conformance.Helpers.host_capability/1` calls `Capability.check/1`, and
  `helpers.ex:165` uses the result to explain a third outcome. On a Linux host
  with bubblewrap but no pasta, the permissive probe reports available, so the
  census prints "the breach could not be demonstrated either way" with **no
  cause attached** -- while `require_hardening/0`, gating on the strict probe,
  has already refused to launch the sandbox. The operator gets an unexplained
  third outcome for a cause the same library knows.

  ⚠️ **The fix direction matters.** Relaxing hardening to match the vocabulary
  would be the smaller diff and would be wrong: pasta is what makes the route
  *policed* rather than merely absent, and dropping it restores the
  `--unshare-net` state -- deny everything, pass every denial check. The
  vocabulary probe is the one that was wrong.
  """
  use ExUnit.Case, async: true

  alias ExSandbox.Capability

  describe "the capability vocabulary describes the policed path" do
    @tag :isolation
    test "on Linux, the two probes agree" do
      if match?({:unix, :linux}, :os.type()) do
        vocabulary = Capability.check(:network_restriction).available?
        hardening = ExSandbox.Hardening.Linux.capabilities()[:network_restriction]

        assert vocabulary == hardening,
               """
               The two probes for `:network_restriction` disagree on this host.

               `ExSandbox.Capability`: #{vocabulary}
               `Hardening.Linux`:      #{hardening}

               A host where these differ launches nothing (hardening gates
               `require_hardening/0`) while the census explains the resulting
               third outcome using the other probe -- which believes the
               capability is present, so it supplies no cause.
               """
      end
    end

    test "the detail names what the policed path needs" do
      report = Capability.check(:network_restriction)

      # On every host: available or not, an unavailable report must say what is
      # missing in terms an operator can act on. ⚠️ Asserted on both platforms
      # deliberately -- macOS has its own detail (no namespaces at all), and a
      # regression that emptied the Linux branch's detail would otherwise be
      # invisible until someone read a container log.
      unless report.available? do
        assert is_binary(report.detail) and report.detail != "",
               "an unavailable capability must name its cause"
      end
    end
  end
end
