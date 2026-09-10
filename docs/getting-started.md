# Getting started

Run one piece of tenant code inside a real sandbox, and see the library refuse to run it inside a
fake one. About ten minutes.

You need Elixir 1.14+, and a container runtime (Docker Desktop, Colima, Podman with a Docker-
compatible socket) if you are not on Linux. Everything below was executed on macOS with Docker
Desktop 27.4.0; the output blocks are what it printed.

## 1. Install

```elixir
Mix.install([{:ex_sandbox, "~> 1.3"}])
```

Nothing else. This library depends on `:telemetry` and nothing beyond it — no Ash, no web
framework, no host application.

## 2. Ask the host what it can do

Before provisioning anything, ask:

```elixir
ExSandbox.capabilities()
|> Enum.each(fn c -> IO.puts("#{c.name}\t#{c.available?}") end)
```

On the macOS host this was written on:

```
resource_limits          false
filesystem_confinement   false
privilege_separation     false
network_restriction      false
disk_quota               false
process_separation       true
memory_cap               true
cpu_cap                  true
time_budget              false
```

Every report carries a `detail` saying *what is missing*, not merely that something is:

```elixir
ExSandbox.capabilities()
|> Enum.find(&(&1.name == :network_restriction))
|> Map.get(:detail)
#=> "macOS has no network namespace; a `sandbox-exec` profile is not inherited across..."
```

⚠️ `false` here is a fact about **this host**, not a fact about the library. Read
[Reading a refusal](how-to/read-a-refusal.md) once these start mattering to you.

## 3. Watch it refuse

`ExSandbox.Mechanism.Beam` confines with the *host's* kernel — cgroup v2, user and mount
namespaces, `bwrap`. macOS has none of them, so:

```elixir
alias ExSandbox.Sandbox
alias ExSandbox.Mechanism.Beam

sandbox = %Sandbox{id: "tour-1", owner_ref: "tenant-42", template_ref: "alpine:3"}

ExSandbox.provision(Beam, sandbox)
#=> {:error, {:capability_unavailable, [%ExSandbox.Capability{name: :resource_limits, ...}, ...]}}
```

This is the library working, not failing. It could have provisioned something that ran your
tenant's code with no confinement at all, and it declined. The list in the error names exactly
which capabilities are missing and why. See [Refusal is the design](explanation/refusal.md).

## 4. Bring a kernel that can

`ExSandbox.Mechanism.Docker` does not ask the host to confine anything — the Linux VM behind the
container runtime has cgroup v2, so the mechanism *constructs* the capabilities it needs and the
host probe is asked only about what is left over.

`template_ref` is the container image. `owner_ref` is yours: the library stores and compares it and
never parses it.

```elixir
alias ExSandbox.Mechanism.Docker

sandbox = %Sandbox{
  id: "tour-1",
  owner_ref: "tenant-42",
  template_ref: "alpine:3",
  memory_limit_mb: 256,
  cpu_limit: 500          # millicores
}

{:ok, provisioned} = ExSandbox.provision(Docker, sandbox)
provisioned.mechanism_ref
#=> "b50302f8c1e2..."      an opaque handle the mechanism assigned

ExSandbox.status(Docker, provisioned)
#=> {:ok, :provisioned}
```

`provision/2` creates the resources and starts nothing. The sandbox exists and is inert.

```elixir
{:ok, running} = ExSandbox.start(Docker, provisioned)

ExSandbox.status(Docker, running)
#=> {:ok, :running}
```

## 5. Run something in it

```elixir
ExSandbox.execute(Docker, running, {"sh", ["-c", "echo hello from $(hostname)"]})
#=> {:ok, %{exit_status: 0, stdout: "hello from b50302f8c1e2\n", stderr: "", truncated?: false}}
```

Its own hostname, its own process tree, and — because this sandbox named no `service_port` — no
network at all.

**The three returns are three different facts**, and the whole seam is built on keeping them
apart:

```elixir
# 1. It ran. What it decided is its own business.
ExSandbox.execute(Docker, running, {"sh", ["-c", "exit 3"]})
#=> {:ok, %{exit_status: 3, stdout: "", stderr: "", truncated?: false}}

# 2. It did not run.
ExSandbox.execute(Docker, running, {"no-such-binary", []})
#=> {:error, {:could_not_run, "OCI runtime exec failed: ... executable file not found in $PATH"}}

# 3. A limit stopped it. (`{:error, {:limit_exceeded, :memory | :cpu | :wall_clock}}`)
```

A non-zero exit status is a **result**. Collapsing it into `{:error, _}` throws away the difference
between "the tenant's build failed" and "we never got to run the tenant's build", and every
consumer that has to decide whether to retry needs that difference.

Want output as it is produced rather than at the end? Pass `:on_output`:

```elixir
ExSandbox.execute(Docker, running, {"sh", ["-c", "for i in 1 2 3; do echo $i; sleep 1; done"]},
  on_output: fn {stream, chunk} -> IO.write("[#{stream}] #{chunk}") end
)
```

⚠️ A chunk is a chunk, not a line. Nothing promises line framing — assemble lines yourself if you
need them, so that a long line arrives late rather than mangled.

## 6. Ask what it is using

```elixir
ExSandbox.usage(Docker, running)
#=> {:ok, %{cpu_millicores: 0, memory_mb: 1}}

ExSandbox.list_running(Docker)
#=> {:ok, ["b50302f8c1e2"]}
```

`list_running/1` is not on the happy path. It exists so a host can reconcile what it *recorded*
against what is *actually there* after a restart — and it filters on this library's own label, so
it will never claim a container something else started.

## 7. Stop and destroy

```elixir
{:ok, stopped} = ExSandbox.stop(Docker, running)
ExSandbox.status(Docker, stopped)
#=> {:ok, :stopped}          resources still there

:ok = ExSandbox.destroy(Docker, stopped)
ExSandbox.status(Docker, stopped)
#=> {:ok, :absent}
```

`destroy/2` is deliberately **not** capability-gated, and it is idempotent. Refusing to clean up
because the host cannot isolate would strand resources on exactly the hosts least able to afford
them, and a crash-recovery sweep destroys a list of which half is already gone.

## What you have, and what you do not

You ran tenant code under a memory cap and a CPU cap, in its own process tree, with no network.

You have **not** verified that any of it is enforced. That is a different question, and this
library answers it by breaching a boundary and watching it hold rather than by checking that a flag
was passed:

```elixir
defmodule MyMechanismTest do
  use ExSandbox.Conformance, mechanism: ExSandbox.Mechanism.Docker
end
```

It scores three outcomes — pass, guarantee failure, and **capability unavailable** — because "this
host cannot demonstrate the guarantee" and "this mechanism breached the guarantee" lead to opposite
actions.

⚠️ One thing the Docker mechanism does **not** claim: `:disk_quota`. `--storage-opt size` is
accepted and ignored on overlayfs, measured at 64 MB written into a nominal 16 MB quota. A sandbox
under this mechanism can fill the host filesystem, and that is stated rather than hidden.

## Next

* [Reading a refusal](how-to/read-a-refusal.md) — what each capability name means, and what to do
  about a missing one
* [Implementing a mechanism](how-to/implement-a-mechanism.md) — the behaviour, and the conformance
  suite that grades it
* [Refusal is the design](explanation/refusal.md) — why a partially confined tenant is worse than
  none
