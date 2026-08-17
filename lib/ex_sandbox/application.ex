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
      ExSandbox.Egress.Allocator
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: ExSandbox.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
