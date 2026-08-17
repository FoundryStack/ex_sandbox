defmodule ExSandbox.Egress.Verification do
  @moduledoc """
  Whether a running sandbox is *policed* rather than merely *isolated*
  (005 T060a3/T060a5, `contracts/egress.md` §Capability probing).

  ## The coincidence this replaces

  `Hardening.Linux.sandbox_netns_separated?/1` compares namespace inodes. Under
  `--unshare-net` that was enough, because an empty namespace has no route and
  so isolation and policy coincided. `ExSandbox.Egress.LaunchPlan` installs a
  working default route, which ends the coincidence: separation is now true for
  a namespace that reaches the pool *and* for one that reaches nothing.

  ⚠️ Separation alone must therefore stop counting as success. A sandbox in its
  own namespace with **no registered policy** reaches nothing — which passes
  every denial check in the conformance suite, because a boundary permitting
  nothing is indistinguishable from a correct one under a suite that only tests
  denial (`contracts/egress.md`, "What is wrong today").

  ## Why this takes a map rather than reading `/proc` itself

  The two facts it joins come from different places — the kernel for the
  namespace, the `Registry` for the policy — and neither is reachable from a
  macOS host. Taking them as data makes the *join* testable everywhere, which
  matters because the join is the part that was missing, not either fact.
  """

  alias ExSandbox.Egress.Policy

  @typedoc "Why a sandbox is not confirmed policed."
  @type refusal :: :no_policy | :not_separated | :unverifiable

  @type observation :: %{
          netns_separated: boolean() | :unknown,
          source_key: Policy.source_key(),
          registered_allowlist: [Policy.destination()]
        }

  @doc """
  `:ok` only when the sandbox is in its own namespace **and** a policy is
  registered for its /30.

  Every other outcome is an error naming which half is missing. There is no
  outcome meaning "probably fine".
  """
  @spec policed?(observation()) :: :ok | {:error, refusal()}
  def policed?(%{netns_separated: :unknown}) do
    # T060a5's rule: a host that cannot answer reports unavailable, never `:ok`.
    # Reading "could not determine" as "separated" is how an unverifiable host
    # starts passing, and it would do so silently.
    {:error, :unverifiable}
  end

  def policed?(%{netns_separated: false}), do: {:error, :not_separated}

  def policed?(%{netns_separated: true, registered_allowlist: []}) do
    # ⚠️ The `--unshare-net` state, and the one the old check called success.
    # An empty allowlist is not a policy -- it is the absence of one, and the
    # sandbox it describes fails closed while every denial check passes.
    {:error, :no_policy}
  end

  def policed?(%{netns_separated: true, registered_allowlist: allowed}) when is_list(allowed) do
    :ok
  end
end
