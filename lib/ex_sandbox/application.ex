defmodule ExSandbox.Application do
  # Private (FR-014). An OTP application callback is started by the runtime, not
  # called by a consumer, so it is not part of ExSandbox's interface -- see that
  # module's moduledoc for the public list.
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Starts a worker by calling: ExSandbox.Worker.start_link(arg)
      # {ExSandbox.Worker, arg}
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: ExSandbox.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
