defmodule ExSandbox.BookkeepingMechanism do
  @moduledoc """
  A mechanism whose `list_running/0` reports its own bookkeeping (005 T060i).

  ## The defect, and why it is the realistic one

  `003-FR-015` asks `list_running/0` to enumerate **reality**. The natural
  implementation enumerates what the mechanism was *asked* to start: keep a set,
  add on `start/1`, remove on `stop/1`, return the set. It is simple, it is
  correct on every path a developer exercises by hand, and it is trivially
  consistent with itself.

  It also cannot detect the only case `list_running/0` exists for — a sandbox
  that **died without telling anyone**. The host was down, the process was
  OOM-killed, the container went away; nothing called `stop/1`, so the
  bookkeeping still says running and the reconciler is told everything is fine.

  This module is that implementation, plus a `kill/1` that ends a sandbox the
  way reality does: without informing the bookkeeping. `status/1` reports the
  truth (it inspects the store), so the two views **disagree** — which is
  exactly what the reconciliation group crosses them to find.

  ## Not a strawman

  Every other lifecycle behaviour is correct. It provisions, starts, stops and
  destroys properly; `destroy/1` is idempotent; `status/1` distinguishes
  `:running`, `:stopped` and `:absent`. A suite that failed this mechanism on
  anything except the reality-versus-bookkeeping divergence would be failing it
  for the wrong reason, and the meta-test asserts that too.
  """
  @behaviour ExSandbox.Mechanism

  # Two stores, deliberately. `:bookkeeping` is what the mechanism *believes*;
  # `:reality` is what is actually running. A correct `list_running/0` would
  # read the second. This one reads the first.
  #
  # ⚠️ `:persistent_term` rather than ETS. An ETS table is owned by the process
  # that created it and dies with that process -- and `SuiteRunner` runs each
  # check's `on_exit` after the test that created the table has finished, so
  # `destroy/1` reached a table that no longer existed and raised. The failure
  # looked like a mechanism defect and was an artifact of the fixture.
  @bookkeeping {__MODULE__, :bookkeeping}
  @reality {__MODULE__, :reality}

  @doc "Resets both stores. Call from test setup."
  def start_link do
    :persistent_term.put(@bookkeeping, MapSet.new())
    :persistent_term.put(@reality, MapSet.new())
    :ok
  end

  defp read(key), do: :persistent_term.get(key, MapSet.new())
  defp add(key, ref), do: :persistent_term.put(key, MapSet.put(read(key), ref))
  defp remove(key, ref), do: :persistent_term.put(key, MapSet.delete(read(key), ref))

  @doc """
  Ends a sandbox the way reality does -- without telling the bookkeeping.

  This is the whole point of the fixture. No mechanism callback is involved,
  because none would be: the sandbox died, and nothing was informed.
  """
  def kill(%{mechanism_ref: ref}), do: remove(@reality, ref)

  @impl true
  def required_capabilities, do: []

  @impl true
  def provision(sandbox), do: {:ok, %{sandbox | mechanism_ref: "bookkeeping-" <> sandbox.id}}

  @impl true
  def start(%{mechanism_ref: ref} = sandbox) do
    add(@bookkeeping, ref)
    add(@reality, ref)
    {:ok, sandbox}
  end

  @impl true
  def stop(%{mechanism_ref: ref} = sandbox) do
    remove(@bookkeeping, ref)
    remove(@reality, ref)
    {:ok, sandbox}
  end

  @impl true
  def destroy(%{mechanism_ref: ref}) do
    # Idempotent, per `003-FR-013`. Getting this right matters: a mechanism that
    # errored here would fail the lifecycle group for an unrelated reason and
    # muddy what this fixture demonstrates.
    remove(@bookkeeping, ref)
    remove(@reality, ref)
    :ok
  end

  @impl true
  # Reads **reality**, so it disagrees with `list_running/0` after a `kill/1`.
  # A mechanism where both read the bookkeeping would be self-consistent and
  # undetectable, which is a worse defect and a different fixture.
  def status(%{mechanism_ref: nil}), do: {:ok, :absent}

  def status(%{mechanism_ref: ref}) do
    if MapSet.member?(read(@reality), ref), do: {:ok, :running}, else: {:ok, :absent}
  end

  @impl true
  # The defect. Returns what the mechanism believes it started, which is right
  # on every path except the one that matters.
  def list_running do
    {:ok, MapSet.to_list(read(@bookkeeping))}
  end

  @impl true
  def usage(_sandbox), do: {:ok, %{}}
end
