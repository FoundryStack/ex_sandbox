import Config

# ⚠️ This file configures the library's OWN builds -- its tests, its docs, its
# isolation harness. It is NOT loaded into a consumer's application: Mix reads
# only the top-level project's `config/`, so an application depending on
# `:ex_sandbox` gets the defaults compiled into the code and whatever it sets
# itself, never these values.
#
# Which is why every key below also has a default at its point of use. A key that
# existed only here would work in this repository and be missing everywhere else,
# and the failure would surface inside a consumer's tree as a `nil` in a launch
# path rather than here as a missing config.

# Where the egress verdict socket is bound (005 T060a1).
#
# The per-namespace acceptors hold no policy: they read the destination a tenant
# actually asked for and request a verdict here, so `Pool.decide/3` stays the
# single implementation of the rule and the allowlist never enters a sandbox's
# blast radius.
#
# ⚠️ This path must never be one `Hardening.Linux` binds into a tenant's mount
# view. Measured: under the confinement it composes, a tenant's connect to this
# socket fails ENOENT -- the socket does not exist for the tenant rather than
# existing and being denied, which is what makes `FR-011b`'s "no control
# surface" structural rather than a permission check.
#
# Configurable because `/var/run` is writable on a deployment host and not on a
# developer machine, where the application would otherwise refuse to start.
config :ex_sandbox, :egress,
  verdict_socket_path: Path.join(System.tmp_dir!(), "ex-sandbox-egress-verdict.sock")

# Configuration rather than literals in the launcher, because these are
# deployment facts: a gateway on slower storage boots a node more slowly, and
# the only correct value is the operator's.
#
# `wait_boot_timeout_ms` is deliberately larger than `005-SC-005`'s 5-second
# readiness target. The target is what a healthy launch should achieve; this is
# when to give up and call the launch failed. Setting them equal would report
# failure for every sandbox that merely missed the target, turning a performance
# regression into an outage.
config :ex_sandbox, :beam,
  wait_boot_timeout_ms: 15_000,
  shutdown_timeout_ms: 5_000,
  probe_timeout_ms: 5_000,
  # Templates name the runtime a sandbox launches with (005 FR-022). `:any`
  # delegates existence checking to the host, which is right as a default
  # because a host keeps its own template registry and this library must not
  # read a host's schema (012-FR-009).
  #
  # ⚠️ A host that sets `:any` takes on the obligation to reject unknown
  # templates itself. Without that, a caller who typos a template name gets a
  # running sandbox built from something they did not choose, and
  # `:template_missing` (003-FR-027) can never be reported because nothing
  # noticed. `config/test.exs` configures a real list instead, so the check is
  # exercised here rather than delegated away.
  templates: :any

import_config "#{config_env()}.exs"
