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

      # ⚠️ `ExSandbox.Egress.Pool` was a child here until 2026-08-29, and its
      # removal is the *reverse* of the defect this list once documented.
      #
      # The comment that stood here warned that the pool's absence was
      # undetectable: `LaunchPlan` installed a redirect to its port, and with
      # nothing listening there a sandbox could not tell a dead port from a
      # denied destination, so every conformance denial check would pass while
      # no allowlist was enforced by anything.
      #
      # That warning was correct when written and had stopped being true. An
      # `nft` `redirect` is DNAT to the local machine as the *sandbox's*
      # namespace sees it, so a host listener could never receive one -- and the
      # launcher stopped naming this port when the acceptor moved into the
      # namespace (see `node_launcher.ex`, `@acceptor_port`). What remained was a
      # supervised process holding a socket nothing could reach, which reads as
      # an enforcement point and is not one. `Pool` is now a plain module with a
      # single function, called by every acceptor.
      #
      # ⚠️ The enforcement point it is not replaced by is not supervised here on
      # purpose: there is one acceptor per sandbox, started and stopped by
      # `ExSandbox.Mechanism.Beam.NodeLauncher` with the sandbox it serves. Its
      # start is what refuses the launch when a namespace cannot be entered.

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
      # ⚠️ Its absence is loud rather than silent, and that is deliberate: the
      # acceptor's DNS leg calls this server, so with it down a query gets no
      # answer and names do not resolve at all. A sandbox that cannot resolve is
      # visibly broken; a sandbox that resolves into nothing recorded would be
      # invisibly denied.
      ExSandbox.Egress.Resolver
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: ExSandbox.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
