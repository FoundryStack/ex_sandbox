defmodule ExSandbox.Mechanism.Beam.TemplateWildcardTest do
  @moduledoc """
  `templates: :any` resolves instead of raising (D33).

  ## Why this was missing, and why it matters more than its size suggests

  `resolve_template/1` had `template_ref in known` ahead of `known == :any`.
  With `known` the atom `:any`, `in` reaches `Enumerable.impl_for!/1` and
  raises `protocol Enumerable not implemented for Atom` — so the wildcard
  branch behind it was unreachable and **every provision on such a host
  crashed**, before any capability was consulted.

  `config/config.exs` sets exactly that value for `:dev` and `:prod`.
  `config/test.exs` sets a real list. So the whole suite exercised the one
  configuration that worked, and the two that ship did not. Found at the first
  real `ExSandbox.provision/2` in the studio container, on a host whose
  capability map reported all five available.

  ## Runs everywhere, deliberately

  Like `LaunchRefusalTest`, and for its reason: this is a *refusal-adjacent*
  path that the Linux-gated tests never reach, on the machine where most of
  this code is written. The assertion is only that resolution returns rather
  than raising — the launch that follows is expected to fail on a host without
  the capabilities, and that failure is a different, correct behaviour.
  """
  use ExUnit.Case, async: false

  alias ExSandbox.Mechanism.Beam
  alias ExSandbox.Sandbox

  setup do
    previous = Application.get_env(:ex_sandbox, :beam, [])
    on_exit(fn -> Application.put_env(:ex_sandbox, :beam, previous) end)
    %{previous: previous}
  end

  defp configure_templates(previous, value) do
    Application.put_env(:ex_sandbox, :beam, Keyword.put(previous, :templates, value))
  end

  defp sandbox(template_ref) do
    %Sandbox{
      id: "template-wildcard-#{System.unique_integer([:positive])}",
      owner_ref: "owner",
      template_ref: template_ref
    }
  end

  test "a wildcard registry accepts a name it was never given", %{previous: previous} do
    configure_templates(previous, :any)

    # ⚠️ The assertion is `not raising`, not `{:ok, _}`. On a host that cannot
    # confine, the launch behind this correctly refuses — that refusal is
    # `LaunchRefusalTest`'s subject and must not be asserted away here. What
    # this pins is that resolution got far enough to hand the launcher a
    # decision at all.
    assert {:error, _reason} = Beam.provision(sandbox("a-name-nobody-registered"))
  end

  test "a list registry still refuses a name it was not given", %{previous: previous} do
    configure_templates(previous, ["known-template"])

    assert {:error, {:template_missing, "unknown-template"}} =
             Beam.provision(sandbox("unknown-template"))
  end

  test "an empty registry accepts nothing", %{previous: previous} do
    # The safe direction, and stated in `resolve_template/1`'s own comment: a
    # mechanism that accepted every name when unconfigured would be the
    # fail-open shape the check exists to catch.
    configure_templates(previous, [])

    assert {:error, {:template_missing, "anything"}} = Beam.provision(sandbox("anything"))
  end
end
