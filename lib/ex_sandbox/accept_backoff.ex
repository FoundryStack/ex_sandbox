defmodule ExSandbox.AcceptBackoff do
  # Private (FR-014). Shared by the egress acceptor's loops and the gateway's.
  @moduledoc false

  require Logger

  @first_ms 100
  @cap_ms 30_000

  @doc """
  Logs a failed accept, waits, and returns the failure count for the next attempt.

  An accept that fails with `:emfile` leaves its connection in the queue, so an
  immediate retry fails the same way and floods the log. At the cap this logs
  twice a minute. A successful accept resets the caller's count to zero.
  """
  @spec wait(String.t(), term(), non_neg_integer()) :: pos_integer()
  def wait(what, reason, failures) do
    Logger.warning("#{what} accept failed: #{inspect(reason)}")
    Process.sleep(min(@first_ms * 2 ** min(failures, 9), @cap_ms))
    failures + 1
  end
end
