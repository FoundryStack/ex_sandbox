defmodule ExSandbox.Hardening do
  @moduledoc """
  The OS-level enforcement seam (012 T021, from `005`'s `contracts/hardening.md`).

  `AshSandbox.Resource` lets a host *declare* limits. This behaviour is what
  **enforces** them, and the distinction is the whole point: nothing inside the
  BEAM can cap a process's memory. `005` established that the boundary is the
  operating system — cgroup v2, namespaces, `bubblewrap`, `sandbox-exec`, Job
  Objects — and a mechanism that "enforces" limits in Elixir enforces nothing.

  ## Applied before the first instruction, or not at all

  `apply/2` returns the launch configuration to *start the process with*, rather
  than something to apply to a running process. This ordering is a requirement,
  not a convenience:

    * `005` R9b measured `taskpolicy -m` being **silently lost across an
      intervening exec** — `taskpolicy -m 100 sandbox-exec … ./hog 300`
      allocates 300 MB under a nominal 100 MB cap and exits 0.
    * `014` V3 found the Windows analogue: a Job Object cannot be attached
      before the process's first instruction.

  Both fail **open**, and both pass any check that asks whether the limiting
  mechanism was invoked. That is why `ExSandbox.Conformance` establishes limits
  by breaching them rather than by inspecting configuration (`FR-012a`), and why
  a hardening implementation that cannot apply a cap must say so rather than
  return a config that silently omits it.
  """

  @typedoc "The limits a sandbox is to run under."
  @type limits :: %{
          optional(:cpu_millicores) => non_neg_integer(),
          optional(:memory_mb) => non_neg_integer(),
          optional(:disk_mb) => non_neg_integer(),
          optional(:wall_clock_seconds) => non_neg_integer()
        }

  @typedoc """
  How to launch a process under these limits.

  `cmd`/`args` may wrap the requested command (a cgroup runner, `bwrap`,
  `sandbox-exec`), which is why the caller must launch **this** rather than the
  command it asked about.
  """
  @type launch_spec :: %{
          cmd: String.t(),
          args: [String.t()],
          env: [{String.t(), String.t()}],
          cd: String.t() | nil
        }

  @doc """
  Builds the launch specification enforcing `limits` for `command`.

  Returns `{:error, {:cannot_enforce, capability, detail}}` when a requested
  limit cannot be enforced on this host. It must **not** return a spec that
  omits the cap — that is the fail-open shape above, and it is indistinguishable
  from success at every layer that does not breach the cap to check.
  """
  @callback apply(command :: {String.t(), [String.t()]}, limits()) ::
              {:ok, launch_spec()}
              | {:error, {:cannot_enforce, ExSandbox.Capability.name(), String.t()}}
              | {:error, term()}

  @doc """
  Releases any OS resources this hardening created for a sandbox — a cgroup
  directory, a namespace, a temporary profile.

  Idempotent, for the same reason `destroy/1` is.
  """
  @callback release(handle :: term()) :: :ok | {:error, term()}

  @doc "Capabilities this hardening implementation requires of the host."
  @callback required_capabilities() :: [ExSandbox.Capability.name()]

  # The layers a tier statement is built from. Each is measured by reading a
  # file, never by shelling out: `tier/0` runs on the provisioning path and
  # `ExSandbox.Hardening.Linux.capabilities/0` is documented as a startup probe
  # precisely because it runs `unshare` and `bwrap`.
  @lsm_path "/sys/kernel/security/lsm"
  @status_path "/proc/self/status"
  @tun_path "/dev/net/tun"

  @doc """
  What this host can actually enforce, as one sentence fit to be **recorded**
  (`029-FR-040`).

  ## Why a string, and why it is stored rather than derived on read

  `FR-040` requires a host that cannot enforce these boundaries either to refuse
  to launch or to launch in a reduced tier **named in the sandbox's own recorded
  state**. The reason it must be recorded is the same reason
  `data_store_placement` is: a tier derived at read time describes *the host
  asking*, not the host the sandbox was launched on, and those diverge the
  moment a record outlives a redeploy. A reduced tier that is not recorded is
  indistinguishable from an enforced one.

  ⚠️ **This is measured, not declared.** `029` D18b states the darwin-in-Docker
  tier as *"no LSM, no seccomp; network layer enforced"*, and this function is
  deliberately not that sentence hardcoded -- a constant would go on reporting
  D18b's measurement on a host D18b never saw. What it reads:

    * `#{@lsm_path}` -- the LSMs the kernel has active. `capability` is
      discounted: every Linux kernel carries it and it is not an MAC layer, so
      counting it would report "LSM: capability" on a host with no MAC at all.
      An unreadable path (securityfs unmounted, or not Linux) reads as none,
      which is the conservative direction: it under-claims enforcement.
    * `#{@status_path}`'s `Seccomp:` field -- `0` is disabled, anything else is
      a filter loaded.
    * `pasta` on `PATH` and `#{@tun_path}` present -- the two facts
      `ExSandbox.Hardening.Linux`'s network probe needs a *device* and a binary
      for, and the two whose absence made `pasta --config-net` fail outright
      when it was measured (2026-08-17).

  ⚠️ **The network clause says "enforceable", not "enforced", and the gap is
  deliberate.** These two facts say the apparatus this host would police egress
  with is present; they do not say the sandbox being recorded was launched
  through it -- a sandbox with an empty allowlist takes the unpoliced branch.
  Writing "enforced" here would be the over-claim that
  ExSandbox.Hardening.Linux's private `probe_network_policy/0` warns about in its
  own comment,
  where "we cannot do this" becomes "we demonstrated this".
  """
  @spec tier() :: String.t()
  def tier do
    Enum.join([lsm_clause(), seccomp_clause()], ", ") <> "; " <> network_clause()
  end

  defp lsm_clause do
    case active_lsms() do
      [] -> "no LSM"
      names -> "LSM: " <> Enum.join(names, "+")
    end
  end

  defp active_lsms do
    case File.read(@lsm_path) do
      {:ok, contents} ->
        contents
        |> String.trim()
        |> String.split(",", trim: true)
        # `capability` is on every Linux kernel and confines nothing on its own.
        |> Enum.reject(&(&1 in ["", "capability"]))

      {:error, _} ->
        []
    end
  end

  defp seccomp_clause do
    case seccomp_mode() do
      0 -> "no seccomp"
      mode when is_integer(mode) -> "seccomp mode #{mode}"
      :unknown -> "no seccomp"
    end
  end

  defp seccomp_mode do
    with {:ok, contents} <- File.read(@status_path),
         line when is_binary(line) <-
           contents |> String.split("\n") |> Enum.find(&String.starts_with?(&1, "Seccomp:")),
         {mode, _rest} <-
           line |> String.replace_prefix("Seccomp:", "") |> String.trim() |> Integer.parse() do
      mode
    else
      _ -> :unknown
    end
  end

  defp network_clause do
    if not is_nil(System.find_executable("pasta")) and File.exists?(@tun_path) do
      "network layer enforceable"
    else
      "network layer not enforceable"
    end
  end
end
