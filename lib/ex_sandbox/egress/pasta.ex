defmodule ExSandbox.Egress.Pasta do
  @moduledoc """
  Finds the process that actually holds a sandbox's network namespace
  (005 T060a3, `contracts/egress.md`).

  ## Why this is a module and not two lines at the call site

  `pasta -P <pidfile>` records **pasta's own host-side pid**. The tenant runs
  in a child. Measured in the isolation container:

      pidfile pid = 10 -> ns net:[4026534462]   <- the HOST namespace
      tenant  pid = 11 -> ns net:[4026534599]   <- the sandbox namespace
      host  ns    =       net:[4026534462]

  Using the pidfile pid to install the redirect is not an error that surfaces.
  `nsenter -t 10 -n nft add rule …` **succeeds**: it installs the sandbox's NAT
  rule into the host's own namespace. The tenant is left entirely unpoliced,
  the host acquires a stray rule that redirects *its* outbound TCP, and nothing
  in the launch reports a problem. Every denial check still passes, because the
  tenant reaches nothing it is checked against for unrelated reasons.

  That is the single most dangerous mistake available on this path, and it is
  one identifier long. It gets a module, a name, and this comment.

  ## How the holder is identified

  By comparing namespace **inodes** — `/proc/<pid>/ns/net` — against our own.
  Not by process name, not by tree position, not by assuming the first child.

  The inode is the only check a merely-configured-*looking* namespace cannot
  fool: two processes are in the same network namespace exactly when the
  symlinks match. A name-based or position-based check answers a question about
  process bookkeeping when the question is about kernel identity.

  ⚠️ **A holder whose namespace equals ours is not a holder.** `find/2` refuses
  rather than returning it, because that value's only use is to be handed to
  `nsenter`, and handing it the host namespace is precisely the catastrophe
  above. There is no caller for whom "the host namespace" is a useful answer.

  ## Why finding it is a poll rather than a read

  `pasta` forks the tenant *after* it finishes configuring the namespace. A
  single check immediately after launch finds no child at all and reports what
  reads as an architectural refusal — "nothing entered a different namespace" —
  when the truth is only that nothing has yet. Measured: at t+2s the child did
  not exist; it appeared shortly after.
  """

  @typedoc "Why the namespace holder could not be identified."
  @type refusal :: :no_holder | :unreadable_self

  @default_timeout_ms 10_000
  @poll_interval_ms 250

  @doc """
  The pid of the process inside `pasta`'s namespace, or a refusal.

  `pasta_pid` is what the pidfile contained — the host-side process whose
  children are searched.
  """
  @spec find(pos_integer(), keyword()) :: {:ok, pos_integer()} | {:error, refusal()}
  def find(pasta_pid, opts \\ []) when is_integer(pasta_pid) and pasta_pid > 0 do
    timeout = Keyword.get(opts, :timeout_ms, @default_timeout_ms)
    proc = Keyword.get(opts, :proc_root, "/proc")

    case namespace_of(self_pid_path(proc)) do
      {:ok, host_ns} ->
        deadline = System.monotonic_time(:millisecond) + timeout
        poll(pasta_pid, host_ns, proc, deadline, opts)

      :error ->
        # ⚠️ Refused rather than defaulted. Without our own namespace there is
        # nothing to compare against, and the only available fallback -- "trust
        # the first child" -- is what this module exists to prevent.
        {:error, :unreadable_self}
    end
  end

  defp poll(pasta_pid, host_ns, proc, deadline, opts) do
    case holder(pasta_pid, host_ns, proc, opts) do
      {:ok, pid} ->
        {:ok, pid}

      :none ->
        if System.monotonic_time(:millisecond) < deadline do
          Process.sleep(Keyword.get(opts, :poll_interval_ms, @poll_interval_ms))
          poll(pasta_pid, host_ns, proc, deadline, opts)
        else
          {:error, :no_holder}
        end
    end
  end

  @doc """
  One pass over `pasta_pid`'s children, without waiting.

  Public so the identification rule is testable against a synthetic `/proc`
  on any host — this cannot run outside Linux, and left private the rule that
  matters most would be verifiable only where the whole launch works.
  """
  @spec holder(pos_integer(), String.t(), String.t(), keyword()) :: {:ok, pos_integer()} | :none
  def holder(pasta_pid, host_ns, proc \\ "/proc", opts \\ []) do
    children = Keyword.get(opts, :children, &children_of/3)

    pasta_pid
    |> then(&children.(&1, proc, opts))
    |> Enum.find_value(:none, fn pid ->
      case namespace_of(Path.join([proc, "#{pid}", "ns", "net"])) do
        # ⚠️ The inequality is the whole check. A child sharing our namespace is
        # not a sandbox -- it is a process in the host namespace, and returning
        # it would send the redirect there.
        {:ok, ns} when ns != host_ns -> {:ok, pid}
        _ -> nil
      end
    end)
  end

  defp children_of(pasta_pid, proc, _opts) do
    case File.ls(proc) do
      {:ok, entries} ->
        entries
        |> Enum.filter(&pid_dir?/1)
        |> Enum.map(&String.to_integer/1)
        |> Enum.filter(&(parent_of(&1, proc) == pasta_pid))
        |> Enum.sort()

      {:error, _} ->
        []
    end
  end

  defp pid_dir?(name), do: String.match?(name, ~r/^\d+$/)

  # `/proc/<pid>/stat` field 4 is the parent pid. Read from `stat` rather than
  # `status` because the executable name in field 2 may contain spaces and
  # parentheses -- so the parse takes everything after the closing paren.
  defp parent_of(pid, proc) do
    with {:ok, contents} <- File.read(Path.join([proc, "#{pid}", "stat"])),
         [_, rest] <- String.split(contents, ") ", parts: 2),
         [_state, ppid | _] <- String.split(rest, " ") do
      String.to_integer(ppid)
    else
      _ -> nil
    end
  end

  defp namespace_of(path) do
    case File.read_link(path) do
      {:ok, target} -> {:ok, target}
      {:error, _} -> :error
    end
  end

  defp self_pid_path(proc), do: Path.join([proc, "self", "ns", "net"])
end
