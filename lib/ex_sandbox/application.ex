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
      ExSandbox.Egress.Registry
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: ExSandbox.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
