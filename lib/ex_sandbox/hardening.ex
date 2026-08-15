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
end
