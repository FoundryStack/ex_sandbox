defmodule ExSandbox.Application do
  # Private (FR-014). An OTP application callback is started by the runtime, not
  # called by a consumer, so it is not part of ExSandbox's interface -- see that
  # module's moduledoc for the public list.
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Holds each running sandbox's egress allowlist, keyed by its source /30
      # (005 T060a1). Started here rather than per-sandbox: `013-FR-014c` asks
      # for blast radius, not process count, and a process per sandbox is the
      # heaviest way to get it -- at 500 sandboxes that is 500 supervised
      # processes doing almost nothing.
      ExSandbox.Egress.Registry,

      # Hands out the /30 each sandbox's namespace is built on (005 T060a3).
      # Started beside the registry rather than under it: the two hold halves of
      # one invariant -- an address is not free until its policy is gone -- and
      # `ExSandbox.Egress.Binding` is what keeps them in step. Restarting either
      # alone would leave the other holding state about sandboxes it can no
      # longer describe, which `:one_for_one` permits and nothing here detects.
      #
      # ⚠️ That is a known gap, not a settled design: both are in-memory, so a
      # host restart forgets every live sandbox's policy while the sandboxes
      # keep running. Reconstructing them is T060a6's reclamation work.
      ExSandbox.Egress.Allocator,

      # The acceptor pool every sandbox's traffic is redirected to (005 T060a1).
      #
      # ⚠️ Started **after** the registry, and the order is not cosmetic: the
      # pool consults the registry on its first connection, and `:one_for_one`
      # starts children in the order listed. A pool that outlived its registry
      # would default-deny -- correct, but for the wrong reason and silently.
      #
      # ⚠️ This was missing until T060a3b, and its absence was undetectable.
      # `LaunchPlan` installs a redirect to this pool's port; with nothing
      # listening there, the redirect points at a dead port, and from inside the
      # sandbox that is indistinguishable from a destination denied by policy.
      # Every denial check in the conformance suite would pass while no
      # allowlist was enforced by anything at all. The only outward symptom
      # would be permitted destinations failing too, which reads as a boundary
      # that is slightly too strict rather than as an enforcement point that
      # does not exist -- the `--unshare-net` shape, one layer further out.
      ExSandbox.Egress.Pool,

      # Answers "may this sandbox reach this destination?" for the per-namespace
      # acceptors (005 T060a1).
      #
      # ⚠️ Started **after** the registry for the same reason the pool is: it
      # answers from `Pool.decide/3`, which reads the registry. A verdict server
      # that outlived its registry would deny everything -- correct, but for the
      # wrong reason and silently, because blanket denial passes every denial
      # check in the conformance suite.
      #
      # ⚠️ The acceptors treat any unobtainable verdict as DENY. So this being
      # absent does not fail loudly: it converts every sandbox's egress into
      # blanket denial while the suite stays green. That is the `--unshare-net`
      # state wearing the appearance of an enforced allowlist, which is the
      # precise thing T060 exists to end.
      ExSandbox.Egress.Verdict,

      # Answers DNS for sandboxes, and files what each one resolved (029 T015).
      #
      # ⚠️ Started **after** the registry, and this one writes to it rather than
      # only reading: `029-FR-012` matches a hostname allowlist entry against
      # what this sandbox resolved that name to, and this is what records it.
      # A resolver that outlived its registry would answer queries and file
      # nothing, so every hostname entry would silently deny -- the exact
      # failure `FR-012` exists to end, arriving through a restart instead of
      # through a type mismatch.
      #
      # ⚠️ Its absence is **not** silent in the same way the verdict server's
      # is, and that is deliberate: with nothing bound to the resolver socket,
      # the in-namespace listener's relay fails and the datagram is dropped, so
      # names do not resolve at all rather than resolving into an unenforced
      # allowlist. A sandbox that cannot resolve is visibly broken; a sandbox
      # that resolves into nothing recorded is invisibly denied.
      ExSandbox.Egress.Resolver
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: ExSandbox.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
